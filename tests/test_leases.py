from datetime import datetime, timedelta, timezone

from scanpod_enterprise.db import SessionLocal
from scanpod_enterprise.models import InventoryScope, OutboxEvent, RunStatus, ScanProfile, ScanRun, ScanShard, ShardStatus
from scanpod_enterprise.services import dispatch_available_shards, recover_expired_leases
from scanpod_enterprise.worker import celery


def create_leased_run(session):
    scope = InventoryScope(name="lease-scope", cidr="10.70.0.0/24", zone="default", approved=True)
    profile = ScanProfile(name="lease-profile", version=1, ports="443", zone="default", max_concurrent_shards=1)
    session.add_all([scope, profile])
    session.flush()
    run = ScanRun(inventory_scope_id=scope.id, profile_id=profile.id, requested_by="operator", status=RunStatus.running)
    session.add(run)
    session.flush()
    return run


def test_broker_failure_keeps_the_shard_lease_and_outbox_together(monkeypatch):
    with SessionLocal() as session:
        run = create_leased_run(session)
        session.add(ScanShard(run_id=run.id, cidr="10.70.0.0/24", zone="default"))
        session.commit()
        monkeypatch.setattr(celery, "send_task", lambda *_, **__: (_ for _ in ()).throw(ConnectionError("broker down")))

        assert dispatch_available_shards(session, run.id) == 1

        shard = session.query(ScanShard).filter_by(run_id=run.id).one()
        event = session.query(OutboxEvent).one()
        assert shard.status == ShardStatus.leased
        assert event.payload == {"shard_id": shard.id}
        assert event.delivered_at is None


def test_expired_lease_is_requeued_and_dispatched(monkeypatch):
    with SessionLocal() as session:
        run = create_leased_run(session)
        shard = ScanShard(
            run_id=run.id,
            cidr="10.70.0.0/24",
            zone="default",
            status=ShardStatus.leased,
            lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        session.add(shard)
        session.commit()
        sent = []
        monkeypatch.setattr(celery, "send_task", lambda name, args: sent.append((name, args)))

        assert recover_expired_leases(session) == 1

        session.refresh(shard)
        assert shard.status == ShardStatus.leased
        assert shard.lease_expires_at is not None
        assert shard.lease_expires_at.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc)
        assert sent == [("scanpod_enterprise.worker.execute_shard", [shard.id])]
