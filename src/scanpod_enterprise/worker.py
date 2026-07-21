"""Celery worker for isolated scan-shard execution.

The control plane is responsible for dispatch policy. This worker receives only
a shard identifier and reconstructs all execution settings from durable state.
"""
import subprocess
import socket
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from celery import Celery

from .config import settings
from .db import SessionLocal
from .models import RunStatus, ScanProfile, ScanRun, ScanShard, ShardStatus
from .results import normalize_nmap_xml, store_artifact
from .services import dispatch_available_shards

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
        artifact = Path("/tmp") / f"scanpod-{shard.id}.xml"
        command = ["nmap", "-oX", str(artifact), "-p", profile.ports, *profile.arguments.split(), "--max-rate", str(profile.max_rate), shard.cidr]
        cancelled = False
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            deadline = time.monotonic() + profile.timeout_seconds
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
                shard.status = ShardStatus.cancelled
                shard.error = "cancelled by operator"
            elif process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, command, output=stdout, stderr=stderr)
            else:
                normalize_nmap_xml(session, artifact, run.id, shard.id)
                shard.artifact_key = store_artifact(artifact, run.id, shard.id)
                shard.status = ShardStatus.completed
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            shard.error = str(exc)
            if shard.attempts >= settings.max_shard_attempts:
                shard.status = ShardStatus.dead_letter
            else:
                shard.status = ShardStatus.queued
                shard.retry_not_before = datetime.now(timezone.utc) + timedelta(seconds=2 ** shard.attempts * 30)
        finally:
            if artifact.exists():
                artifact.unlink()
        shard.worker_id = None
        shard.heartbeat_at = None
        terminal = session.query(ScanShard).filter(ScanShard.run_id == run.id, ScanShard.status.notin_([ShardStatus.completed, ShardStatus.failed, ShardStatus.cancelled, ShardStatus.dead_letter])).count() == 0
        if terminal:
            failed = session.query(ScanShard).filter(ScanShard.run_id == run.id, ScanShard.status.in_([ShardStatus.failed, ShardStatus.dead_letter])).count()
            run.status = RunStatus.failed if failed else RunStatus.completed
            run.completed_at = datetime.now(timezone.utc)
        session.commit()
        dispatch_available_shards(session, run.id)
