import ipaddress
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from .config import settings
from .models import AuditEvent, InventoryScope, OutboxEvent, RunStatus, ScanProfile, ScanRun, ScanShard
from .models import ShardStatus


def audit(session: Session, actor: str, action: str, resource_type: str, resource_id: str, **detail):
    session.add(AuditEvent(actor=actor, action=action, resource_type=resource_type, resource_id=resource_id, detail=detail))


def parse_approved_cidr(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        network = ipaddress.ip_network(cidr, strict=True)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="cidr must be a canonical network") from exc
    if network.version != 4 or network.prefixlen < settings.max_cidr_prefix:
        raise HTTPException(status_code=422, detail=f"only IPv4 networks /{settings.max_cidr_prefix} or smaller are allowed")
    return network


def shard_cidr(cidr: str) -> list[str]:
    network = parse_approved_cidr(cidr)
    if network.prefixlen >= settings.shard_prefix:
        return [str(network)]
    shards = [str(item) for item in network.subnets(new_prefix=settings.shard_prefix)]
    if len(shards) > settings.max_shards_per_run:
        raise HTTPException(status_code=422, detail="run would create too many shards")
    return shards


def create_run(session: Session, scope: InventoryScope, profile: ScanProfile, actor: str) -> ScanRun:
    if not scope.approved:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="inventory scope is not approved")
    if scope.zone != profile.zone:
        raise HTTPException(status_code=422, detail="profile and inventory scope must use the same worker zone")
    run = ScanRun(inventory_scope_id=scope.id, profile_id=profile.id, requested_by=actor)
    session.add(run)
    session.flush()
    for cidr in shard_cidr(scope.cidr):
        session.add(ScanShard(run_id=run.id, cidr=cidr, zone=scope.zone))
    audit(session, actor, "run.created", "scan_run", run.id, scope_id=scope.id, profile_id=profile.id)
    session.commit()
    dispatch_available_shards(session, run.id)
    return run


def dispatch_available_shards(session: Session, run_id: str) -> int:
    """Lease up to a profile's concurrency budget and publish identifier-only tasks."""
    run = session.get(ScanRun, run_id)
    if not run or run.status in (RunStatus.cancelled, RunStatus.completed, RunStatus.failed):
        return 0
    profile = session.get(ScanProfile, run.profile_id)
    if not profile:
        return 0
    active = session.query(ScanShard).filter(ScanShard.run_id == run_id, ScanShard.status.in_([ShardStatus.leased, ShardStatus.running])).count()
    capacity = max(profile.max_concurrent_shards - active, 0)
    if not capacity:
        return 0
    shards = (session.query(ScanShard).filter_by(run_id=run_id, status=ShardStatus.queued).order_by(ScanShard.cidr).limit(capacity).with_for_update(skip_locked=True).all())
    now = datetime.now(timezone.utc)
    for shard in shards:
        shard.status = ShardStatus.leased
        shard.dispatched_at = now
        shard.lease_expires_at = now + timedelta(seconds=settings.shard_lease_seconds)
    session.commit()
    for shard in shards:
        session.add(OutboxEvent(topic="scan_shard", payload={"shard_id": shard.id}))
    session.commit()
    publish_pending_outbox(session)
    return len(shards)


def publish_pending_outbox(session: Session, limit: int = 100) -> int:
    """Publish durable work records; failed sends remain available for retry."""
    pending = (session.query(OutboxEvent).filter(OutboxEvent.delivered_at.is_(None)).order_by(OutboxEvent.created_at).limit(limit).all())
    from .worker import celery
    delivered = 0
    for event in pending:
        try:
            celery.send_task("scanpod_enterprise.worker.execute_shard", args=[event.payload["shard_id"]])
        except Exception as exc:  # broker outages must not lose the durable event
            event.attempts += 1
            event.last_error = str(exc)
            session.commit()
            continue
        event.attempts += 1
        event.delivered_at = datetime.now(timezone.utc)
        event.last_error = None
        session.commit()
        delivered += 1
    return delivered


def recover_expired_leases(session: Session, now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc)
    stale = session.query(ScanShard).filter(ScanShard.status == ShardStatus.leased, ScanShard.lease_expires_at < now).all()
    for shard in stale:
        shard.status = ShardStatus.queued
        shard.lease_expires_at = None
    session.commit()
    for run_id in {shard.run_id for shard in stale}:
        dispatch_available_shards(session, run_id)
    return len(stale)


def cancel_run(session: Session, run: ScanRun, actor: str) -> ScanRun:
    if run.status in (RunStatus.completed, RunStatus.failed, RunStatus.cancelled):
        raise HTTPException(status_code=409, detail="run is already terminal")
    run.status = RunStatus.cancelled
    run.completed_at = datetime.now(timezone.utc)
    for shard in session.query(ScanShard).filter(ScanShard.run_id == run.id, ScanShard.status.in_([ShardStatus.queued, ShardStatus.leased])):
        shard.status = ShardStatus.cancelled
    audit(session, actor, "run.cancelled", "scan_run", run.id)
    session.commit()
    return run
