"""Prometheus metrics for control-plane and scanning operations."""
from datetime import datetime, timedelta, timezone

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from sqlalchemy import func
from sqlalchemy.orm import Session

from .config import settings
from .models import CurrentExposure, OutboxEvent, RunStatus, ScanRun, ScanSchedule, ScanShard, ShardStatus

API_REQUESTS = Counter("transport_lookout_api_requests_total", "API requests", ["method", "route", "status"])
API_DURATION = Histogram("transport_lookout_api_request_duration_seconds", "API request duration", ["method", "route"])
RUNS = Gauge("transport_lookout_runs", "Scan runs by status", ["status"])
SHARDS = Gauge("transport_lookout_shards", "Scan shards by status", ["status"])
OUTBOX_PENDING = Gauge("transport_lookout_outbox_pending", "Undelivered outbox events")
STALE_WORKERS = Gauge("transport_lookout_stale_worker_shards", "Running shards with stale heartbeats")
CURRENT_EXPOSURES = Gauge("transport_lookout_current_exposures", "Current open host-port exposures")
OVERDUE_SCHEDULES = Gauge("transport_lookout_overdue_schedules", "Enabled schedules past their next run time")
STALE_RUNS = Gauge("transport_lookout_stale_runs", "Running scans past the configured expected duration")


def collect_operational_metrics(session: Session) -> None:
    for metric_status in RunStatus:
        RUNS.labels(status=metric_status.value).set(session.query(ScanRun).filter_by(status=metric_status).count())
    for metric_status in ShardStatus:
        SHARDS.labels(status=metric_status.value).set(session.query(ScanShard).filter_by(status=metric_status).count())
    OUTBOX_PENDING.set(session.query(OutboxEvent).filter(OutboxEvent.delivered_at.is_(None)).count())
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.shard_lease_seconds)
    STALE_WORKERS.set(session.query(ScanShard).filter(ScanShard.status == ShardStatus.running, ScanShard.heartbeat_at < cutoff).count())
    CURRENT_EXPOSURES.set(session.query(func.count(CurrentExposure.id)).scalar() or 0)
    OVERDUE_SCHEDULES.set(session.query(ScanSchedule).filter(ScanSchedule.enabled.is_(True), ScanSchedule.next_run_at < datetime.now(timezone.utc)).count())
    run_cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.run_stale_seconds)
    STALE_RUNS.set(session.query(ScanRun).filter(ScanRun.status == RunStatus.running, ScanRun.started_at < run_cutoff).count())


def render_metrics(session: Session) -> tuple[bytes, str]:
    collect_operational_metrics(session)
    return generate_latest(), CONTENT_TYPE_LATEST
