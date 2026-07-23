"""Celery worker for isolated scan-shard execution."""
import subprocess
import socket
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from celery import Celery

from .config import settings
from .db import SessionLocal
from .models import DiscoveryObservation, RunStatus, ScanProfile, ScanRun, ScanShard, ShardStatus
from .results import masscan_observations, normalize_nmap_xml, store_artifact
from .services import audit, dispatch_available_shards, finalize_terminal_run

celery = Celery("scanpod_enterprise", broker=settings.amqp_url)
celery.conf.task_default_queue = "scan-shards"
celery.conf.task_acks_late = True
celery.conf.task_reject_on_worker_lost = True


@celery.task(bind=True, autoretry_for=(OSError,), retry_backoff=True, retry_kwargs={"max_retries": 2})
def execute_shard(self, shard_id: str) -> None:
    with SessionLocal() as session:
        shard = session.get(ScanShard, shard_id)
        if not shard or shard.status != ShardStatus.leased:
            return
        run = session.get(ScanRun, shard.run_id)
        if not run or run.status == RunStatus.cancelled:
            return
        profile = session.get(ScanProfile, run.profile_id)
        if not profile:
            shard.status, shard.error = ShardStatus.failed, "scan profile missing"
            session.commit()
            return

        shard.status = ShardStatus.running
        shard.lease_expires_at = None
        shard.worker_id = f"{socket.gethostname()}:{self.request.hostname}"
        shard.heartbeat_at = datetime.now(timezone.utc)
        shard.attempts += 1
        run.status = RunStatus.running
        run.started_at = run.started_at or datetime.now(timezone.utc)
        session.commit()
        dispatch_available_shards(session, run.id)

        discovery_xml = Path("/tmp") / f"scanpod-discovery-{shard.id}.xml"
        confirmation_xml = Path("/tmp") / f"scanpod-nmap-{shard.id}.xml"
        targets_file = Path("/tmp") / f"scanpod-targets-{shard.id}.txt"
        cancelled = False
        deadline = time.monotonic() + profile.timeout_seconds

        def run_command(command: list[str]) -> None:
            nonlocal cancelled
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            while process.poll() is None:
                time.sleep(settings.worker_heartbeat_seconds)
                session.refresh(run)
                session.refresh(shard)
                shard.heartbeat_at = datetime.now(timezone.utc)
                session.commit()
                if run.status == RunStatus.cancelled:
                    cancelled = True
                    process.terminate()
                    try:
                        process.wait(timeout=settings.scan_cancel_grace_seconds)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    break
                if time.monotonic() >= deadline:
                    process.kill()
                    raise subprocess.TimeoutExpired(command, profile.timeout_seconds)
            stdout, stderr = process.communicate()
            if cancelled:
                return
            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, command, output=stdout, stderr=stderr)

        try:
            if profile.scanner_mode == "masscan_then_nmap":
                discovery_ports = ",".join(item.removeprefix("T:") for item in profile.ports.split(","))
                run_command(["masscan", shard.cidr, "-p", discovery_ports, "--rate", str(profile.max_rate), "--wait", "5", "-oX", str(discovery_xml)])
                if not cancelled:
                    observations = masscan_observations(discovery_xml)
                    candidates = sorted({address for address, _, _ in observations})
                    session.query(DiscoveryObservation).filter_by(shard_id=shard.id).delete()
                    session.add_all(DiscoveryObservation(run_id=run.id, shard_id=shard.id, address=address, protocol=protocol, port=port) for address, protocol, port in observations)
                    shard.discovery_artifact_key = store_artifact(discovery_xml, run.id, shard.id, "masscan")
                    audit(session, "worker", "shard.discovery.completed", "scan_shard", shard.id, candidates=len(candidates), open_ports=len(observations), scanner="masscan")
                    if candidates:
                        targets_file.write_text("\n".join(candidates) + "\n")
                        run_command(["nmap", "-oX", str(confirmation_xml), "-iL", str(targets_file), "-p", profile.ports, *profile.arguments.split(), "--max-rate", str(profile.max_rate)])
                        if not cancelled:
                            normalize_nmap_xml(session, confirmation_xml, run.id, shard.id)
                            shard.artifact_key = store_artifact(confirmation_xml, run.id, shard.id, "nmap")
                    else:
                        audit(session, "worker", "shard.confirmation.skipped", "scan_shard", shard.id, reason="no_masscan_candidates")
            else:
                run_command(["nmap", "-oX", str(confirmation_xml), "-p", profile.ports, *profile.arguments.split(), "--max-rate", str(profile.max_rate), shard.cidr])
                if not cancelled:
                    normalize_nmap_xml(session, confirmation_xml, run.id, shard.id)
                    shard.artifact_key = store_artifact(confirmation_xml, run.id, shard.id, "nmap")

            if cancelled:
                shard.status = ShardStatus.cancelled
                shard.error = "cancelled by operator"
            else:
                shard.status = ShardStatus.completed
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            shard.error = (getattr(exc, "stderr", None) or str(exc)).strip()
            if shard.attempts >= settings.max_shard_attempts:
                shard.status = ShardStatus.dead_letter
            else:
                shard.status = ShardStatus.queued
                shard.retry_not_before = datetime.now(timezone.utc) + timedelta(seconds=2 ** shard.attempts * 30)
        finally:
            for path in (discovery_xml, confirmation_xml, targets_file):
                if path.exists():
                    path.unlink()

        shard.worker_id = None
        shard.heartbeat_at = None
        finalize_terminal_run(session, run, "worker")
        session.commit()
        dispatch_available_shards(session, run.id)
