"""Celery worker for isolated scan-shard execution."""
import subprocess
import socket
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from celery import Celery
from sqlalchemy import update

from .config import settings
from .db import SessionLocal
from .models import DiscoveryObservation, HostObservation, RunStatus, ScanProfile, ScanRun, ScanShard, ServiceObservation, ShardStatus
from .results import masscan_observations, normalize_nmap_xml, store_artifact
from .services import audit, dispatch_available_shards, finalize_terminal_run

celery = Celery("scanpod_enterprise", broker=settings.amqp_url)
celery.conf.task_default_queue = "scan-shards"
celery.conf.task_acks_late = True
celery.conf.task_reject_on_worker_lost = True


def nmap_confirmation_command(profile: ScanProfile, output: Path, targets: Path) -> list[str]:
    """Build Nmap's second-stage command for Masscan-proven candidates."""
    return [
        "nmap",
        "-Pn",
        "-oX",
        str(output),
        "-iL",
        str(targets),
        "-p",
        profile.ports,
        *profile.arguments.split(),
        "--max-rate",
        str(profile.max_rate),
    ]


class LeaseSuperseded(Exception):
    """Raised when a recovered shard has been claimed by another worker."""


def claim_lease(session, shard_id: str, lease_token: str, worker_id: str) -> ScanShard | None:
    """Atomically transition one dispatched lease to running."""
    claimed = session.execute(
        update(ScanShard)
        .where(
            ScanShard.id == shard_id,
            ScanShard.status == ShardStatus.leased,
            ScanShard.lease_token == lease_token,
        )
        .values(
            status=ShardStatus.running,
            lease_expires_at=None,
            worker_id=worker_id,
            heartbeat_at=datetime.now(timezone.utc),
            attempts=ScanShard.attempts + 1,
        )
    )
    if claimed.rowcount != 1:
        session.rollback()
        return None
    session.commit()
    return session.get(ScanShard, shard_id)


def current_lease(session, shard_id: str, lease_token: str) -> bool:
    """Check whether this worker still owns a running shard lease."""
    return session.query(ScanShard.id).filter(
        ScanShard.id == shard_id,
        ScanShard.status == ShardStatus.running,
        ScanShard.lease_token == lease_token,
    ).first() is not None


def clear_shard_observations(session, shard_id: str) -> None:
    """Remove prior-attempt observations after a new lease has been claimed."""
    host_ids = session.query(HostObservation.id).filter_by(shard_id=shard_id)
    session.query(ServiceObservation).filter(ServiceObservation.host_observation_id.in_(host_ids)).delete(
        synchronize_session=False
    )
    session.query(HostObservation).filter_by(shard_id=shard_id).delete(synchronize_session=False)
    session.query(DiscoveryObservation).filter_by(shard_id=shard_id).delete(synchronize_session=False)


def finish_lease(session, shard_id: str, lease_token: str, status: ShardStatus, **values) -> bool:
    """Persist a terminal/retry state only while this execution owns the lease."""
    result = session.execute(
        update(ScanShard)
        .where(
            ScanShard.id == shard_id,
            ScanShard.status == ShardStatus.running,
            ScanShard.lease_token == lease_token,
        )
        .values(status=status, worker_id=None, heartbeat_at=None, **values)
    )
    return result.rowcount == 1


@celery.task(bind=True, autoretry_for=(OSError,), retry_backoff=True, retry_kwargs={"max_retries": 2})
def execute_shard(self, shard_id: str, lease_token: str | None = None) -> None:
    # Tasks dispatched before execution fencing was introduced cannot prove
    # ownership. Lease recovery will safely reissue them with a fresh token.
    if not lease_token:
        return
    with SessionLocal() as session:
        shard = claim_lease(session, shard_id, lease_token, f"{socket.gethostname()}:{self.request.hostname}")
        if not shard:
            return
        run = session.get(ScanRun, shard.run_id)
        if not run or run.status == RunStatus.cancelled:
            finish_lease(session, shard_id, lease_token, ShardStatus.cancelled, error="cancelled by operator")
            session.commit()
            return
        profile = session.get(ScanProfile, run.profile_id)
        if not profile:
            finish_lease(session, shard_id, lease_token, ShardStatus.failed, error="scan profile missing")
            session.commit()
            return

        run.status = RunStatus.running
        run.started_at = run.started_at or datetime.now(timezone.utc)
        clear_shard_observations(session, shard.id)
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
                if not current_lease(session, shard_id, lease_token):
                    process.terminate()
                    raise LeaseSuperseded()
                session.execute(
                    update(ScanShard)
                    .where(
                        ScanShard.id == shard_id,
                        ScanShard.status == ShardStatus.running,
                        ScanShard.lease_token == lease_token,
                    )
                    .values(heartbeat_at=datetime.now(timezone.utc))
                )
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
                    if not current_lease(session, shard_id, lease_token):
                        raise LeaseSuperseded()
                    observations = masscan_observations(discovery_xml)
                    candidates = sorted({address for address, _, _ in observations})
                    session.add_all(DiscoveryObservation(run_id=run.id, shard_id=shard.id, lease_token=lease_token, address=address, protocol=protocol, port=port) for address, protocol, port in observations)
                    discovery_artifact_key = store_artifact(discovery_xml, run.id, shard.id, "masscan", lease_token)
                    audit(session, "worker", "shard.discovery.completed", "scan_shard", shard.id, candidates=len(candidates), open_ports=len(observations), scanner="masscan")
                    if candidates:
                        targets_file.write_text("\n".join(candidates) + "\n")
                        run_command(nmap_confirmation_command(profile, confirmation_xml, targets_file))
                        if not cancelled:
                            if not current_lease(session, shard_id, lease_token):
                                raise LeaseSuperseded()
                            normalize_nmap_xml(session, confirmation_xml, run.id, shard.id, lease_token)
                            artifact_key = store_artifact(confirmation_xml, run.id, shard.id, "nmap", lease_token)
                    else:
                        audit(session, "worker", "shard.confirmation.skipped", "scan_shard", shard.id, reason="no_masscan_candidates")
            else:
                run_command(["nmap", "-oX", str(confirmation_xml), "-p", profile.ports, *profile.arguments.split(), "--max-rate", str(profile.max_rate), shard.cidr])
                if not cancelled:
                    if not current_lease(session, shard_id, lease_token):
                        raise LeaseSuperseded()
                    normalize_nmap_xml(session, confirmation_xml, run.id, shard.id, lease_token)
                    artifact_key = store_artifact(confirmation_xml, run.id, shard.id, "nmap", lease_token)

            if cancelled:
                finished = finish_lease(session, shard_id, lease_token, ShardStatus.cancelled, error="cancelled by operator")
            else:
                if not current_lease(session, shard_id, lease_token):
                    raise LeaseSuperseded()
                finished = finish_lease(
                    session,
                    shard_id,
                    lease_token,
                    ShardStatus.completed,
                    artifact_key=locals().get("artifact_key"),
                    discovery_artifact_key=locals().get("discovery_artifact_key"),
                )
            if not finished:
                raise LeaseSuperseded()
        except LeaseSuperseded:
            session.rollback()
            return
        except Exception as exc:
            detail = (getattr(exc, "stderr", None) or str(exc)).strip()
            error = f"{type(exc).__name__}: {detail or 'no error detail'}"
            if shard.attempts >= settings.max_shard_attempts:
                finished = finish_lease(session, shard_id, lease_token, ShardStatus.dead_letter, error=error)
            else:
                finished = finish_lease(
                    session,
                    shard_id,
                    lease_token,
                    ShardStatus.queued,
                    error=error,
                    retry_not_before=datetime.now(timezone.utc) + timedelta(seconds=2 ** shard.attempts * 30),
                )
            if not finished:
                session.rollback()
                return
        finally:
            for path in (discovery_xml, confirmation_xml, targets_file):
                if path.exists():
                    path.unlink()

        finalize_terminal_run(session, run, "worker")
        session.commit()
        dispatch_available_shards(session, run.id)
