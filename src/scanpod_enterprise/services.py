import ipaddress
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from .config import settings
from .models import AuditEvent, CurrentExposure, DiscoveryObservation, HostObservation, InventoryScope, OutboxEvent, RunStatus, ScanProfile, ScanRun, ScanShard, ServiceObservation
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
    now = datetime.now(timezone.utc)
    shards = (session.query(ScanShard).filter(ScanShard.run_id == run_id, ScanShard.status == ShardStatus.queued, or_(ScanShard.retry_not_before.is_(None), ScanShard.retry_not_before <= now)).order_by(ScanShard.cidr).limit(capacity).with_for_update(skip_locked=True).all())
    for shard in shards:
        shard.status = ShardStatus.leased
        shard.dispatched_at = now
        shard.lease_expires_at = now + timedelta(seconds=settings.shard_lease_seconds)
        shard.retry_not_before = None
        session.add(OutboxEvent(topic="scan_shard", payload={"shard_id": shard.id}))
    # The lease and durable publish intent must commit together. If the process
    # stops before broker delivery, the publisher can safely retry the outbox.
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
    stale = session.query(ScanShard).filter(or_(
        (ScanShard.status == ShardStatus.leased) & (ScanShard.lease_expires_at < now),
        (ScanShard.status == ShardStatus.running) & (ScanShard.heartbeat_at < now - timedelta(seconds=settings.shard_lease_seconds)),
    )).all()
    for shard in stale:
        shard.status = ShardStatus.queued
        shard.lease_expires_at = None
        shard.worker_id = None
        shard.heartbeat_at = None
    session.commit()
    for run_id in {shard.run_id for shard in stale}:
        dispatch_available_shards(session, run_id)
    return len(stale)


TERMINAL_SHARD_STATUSES = {
    ShardStatus.completed,
    ShardStatus.failed,
    ShardStatus.cancelled,
    ShardStatus.dead_letter,
}


def incomplete_discovery_shards(session: Session, run_id: str) -> int:
    """Return discovery shards with candidates but no completed Nmap artifact.

    A Masscan artifact by itself does not mean coverage is incomplete: a shard
    with no candidates correctly skips Nmap. Discovery observations are only
    recorded when Masscan found an address/port candidate.
    """
    return (
        session.query(ScanShard.id)
        .join(DiscoveryObservation, DiscoveryObservation.shard_id == ScanShard.id)
        .filter(
            ScanShard.run_id == run_id,
            ScanShard.artifact_key.is_(None),
        )
        .distinct()
        .count()
    )


def finalize_terminal_run(session: Session, run: ScanRun, actor: str) -> bool:
    """Finalize a run once every shard has reached a durable terminal state.

    This is deliberately shared by workers and scheduler recovery so the
    current-exposure safety gate is identical in normal and recovery paths.
    """
    if run.status not in {RunStatus.queued, RunStatus.running}:
        return False
    # SessionLocal disables autoflush. Persist a finishing worker's shard state
    # before the terminal-state query below so the query can see that shard.
    session.flush()
    pending = session.query(ScanShard).filter(
        ScanShard.run_id == run.id,
        ScanShard.status.notin_(TERMINAL_SHARD_STATUSES),
    ).count()
    if pending:
        return False

    failed = session.query(ScanShard).filter(
        ScanShard.run_id == run.id,
        ScanShard.status.in_([ShardStatus.failed, ShardStatus.dead_letter]),
    ).count()
    run.status = RunStatus.failed if failed else RunStatus.completed
    run.completed_at = datetime.now(timezone.utc)
    if run.status == RunStatus.completed:
        incomplete = incomplete_discovery_shards(session, run.id)
        if not incomplete:
            materialize_current_exposures(session, run)
        else:
            audit(session, actor, "run.inventory_update_skipped", "scan_run", run.id,
                  reason="incomplete_masscan_coverage", shards=incomplete)
    audit(session, actor, "run.finalized", "scan_run", run.id)
    return True


def reconcile_terminal_runs(session: Session) -> int:
    """Finalize parent runs from durable shard state, independent of worker exit timing."""
    reconciled = 0
    runs = session.query(ScanRun).filter(ScanRun.status.in_([RunStatus.queued, RunStatus.running])).all()
    for run in runs:
        if finalize_terminal_run(session, run, "scheduler"):
            reconciled += 1
    if reconciled:
        session.commit()
    return reconciled


def materialize_current_exposures(session: Session, run: ScanRun) -> int:
    """Replace the current read model for a successful scope/profile scan."""
    scope = session.get(InventoryScope, run.inventory_scope_id)
    if not scope:
        return 0
    existing = {(item.address, item.protocol, item.port): (item.first_seen_at, item.scan_count) for item in session.query(CurrentExposure).filter_by(inventory_scope_id=run.inventory_scope_id, profile_id=run.profile_id)}
    session.query(CurrentExposure).filter_by(inventory_scope_id=run.inventory_scope_id, profile_id=run.profile_id).delete()
    observed_at = run.completed_at or datetime.now(timezone.utc)
    rows = (session.query(HostObservation, ServiceObservation).join(ServiceObservation, ServiceObservation.host_observation_id == HostObservation.id).filter(HostObservation.run_id == run.id, HostObservation.state == "up", ServiceObservation.state == "open").all())
    for host, service in rows:
        key = (host.address, service.protocol, service.port)
        first_seen_at, scan_count = existing.get(key, (observed_at, 0))
        session.add(CurrentExposure(inventory_scope_id=run.inventory_scope_id, profile_id=run.profile_id, latest_run_id=run.id, zone=scope.zone, address=host.address, protocol=service.protocol, port=service.port, service=service.service, product=service.product, version=service.version, first_seen_at=first_seen_at, last_seen_at=observed_at, scan_count=scan_count + 1))
    return len(rows)


def exposure_diff(session: Session, scope_id: str, profile_id: str) -> tuple[ScanRun | None, ScanRun | None, list[dict], bool]:
    """Compare the two most recent completed observations for a scope/profile."""
    runs = (session.query(ScanRun).filter_by(
        inventory_scope_id=scope_id, profile_id=profile_id, status=RunStatus.completed,
    ).order_by(ScanRun.completed_at.desc()).limit(2).all())
    if not runs:
        return None, None, [], True
    current, previous = runs[0], runs[1] if len(runs) == 2 else None
    if incomplete_discovery_shards(session, current.id):
        return current, previous, [], False

    def observations(run: ScanRun) -> tuple[dict[tuple[str, str, int], ServiceObservation], set[str]]:
        items = {
            (host.address, service.protocol, service.port): service
            for host, service in session.query(HostObservation, ServiceObservation)
            .join(ServiceObservation, ServiceObservation.host_observation_id == HostObservation.id)
            .filter(HostObservation.run_id == run.id, HostObservation.state == "up", ServiceObservation.state == "open")
        }
        hosts = {address for (address,) in session.query(HostObservation.address).filter_by(run_id=run.id, state="up")}
        return items, hosts

    current_items, current_hosts = observations(current)
    if previous is None:
        return current, None, [
            {"change_type": "port_opened", "address": address, "protocol": protocol, "port": port,
             "service": item.service, "product": item.product, "version": item.version}
            for (address, protocol, port), item in sorted(current_items.items())
        ], True

    previous_items, previous_hosts = observations(previous)
    changes: list[dict] = []
    for address in sorted(previous_hosts - current_hosts):
        changes.append({"change_type": "host_disappeared", "address": address})
    for key in sorted(current_items.keys() - previous_items.keys()):
        address, protocol, port = key
        item = current_items[key]
        changes.append({"change_type": "port_opened", "address": address, "protocol": protocol, "port": port,
                        "service": item.service, "product": item.product, "version": item.version})
    for key in sorted(previous_items.keys() - current_items.keys()):
        address, protocol, port = key
        if address in current_hosts:
            item = previous_items[key]
            changes.append({"change_type": "port_closed", "address": address, "protocol": protocol, "port": port,
                            "previous_service": item.service, "previous_product": item.product, "previous_version": item.version})
    for key in sorted(current_items.keys() & previous_items.keys()):
        item, old = current_items[key], previous_items[key]
        if (item.service, item.product, item.version) != (old.service, old.product, old.version):
            address, protocol, port = key
            changes.append({"change_type": "service_changed", "address": address, "protocol": protocol, "port": port,
                            "service": item.service, "product": item.product, "version": item.version,
                            "previous_service": old.service, "previous_product": old.product, "previous_version": old.version})
    return current, previous, changes, True


def backfill_current_exposures(session: Session) -> int:
    """Populate the read model from the latest completed run per scope/profile."""
    seen: set[tuple[str, str]] = set()
    refreshed = 0
    for run in session.query(ScanRun).filter_by(status=RunStatus.completed).order_by(ScanRun.completed_at.desc()).all():
        key = (run.inventory_scope_id, run.profile_id)
        if key in seen:
            continue
        if incomplete_discovery_shards(session, run.id):
            continue
        materialize_current_exposures(session, run)
        seen.add(key)
        refreshed += 1
    if refreshed:
        session.commit()
    return refreshed


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
