"""Celery worker for isolated scan-shard execution.

The control plane is responsible for dispatch policy. This worker receives only
a shard identifier and reconstructs all execution settings from durable state.
"""
import subprocess
from datetime import datetime, timezone
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
        shard.attempts += 1
        run.status = RunStatus.running
        run.started_at = run.started_at or datetime.now(timezone.utc)
        session.commit()
        dispatch_available_shards(session, run.id)
        artifact = Path("/tmp") / f"scanpod-{shard.id}.xml"
        command = ["nmap", "-oX", str(artifact), "-p", profile.ports, *profile.arguments.split(), "--max-rate", str(profile.max_rate), shard.cidr]
        try:
            subprocess.run(command, check=True, timeout=profile.timeout_seconds, capture_output=True, text=True)
            normalize_nmap_xml(session, artifact, run.id, shard.id)
            shard.artifact_key = store_artifact(artifact, run.id, shard.id)
            shard.status = ShardStatus.completed
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            shard.status, shard.error = ShardStatus.failed, str(exc)
        finally:
            if artifact.exists():
                artifact.unlink()
        terminal = session.query(ScanShard).filter(ScanShard.run_id == run.id, ScanShard.status.notin_([ShardStatus.completed, ShardStatus.failed, ShardStatus.cancelled])).count() == 0
        if terminal:
            failed = session.query(ScanShard).filter_by(run_id=run.id, status=ShardStatus.failed).count()
            run.status = RunStatus.failed if failed else RunStatus.completed
            run.completed_at = datetime.now(timezone.utc)
        session.commit()
        dispatch_available_shards(session, run.id)
