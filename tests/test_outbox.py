from scanpod_enterprise.db import SessionLocal
from scanpod_enterprise.models import OutboxEvent
from scanpod_enterprise.services import publish_pending_outbox
from scanpod_enterprise.worker import celery


def test_failed_publish_is_retained_and_retried(monkeypatch):
    with SessionLocal() as session:
        event = OutboxEvent(topic="scan_shard", payload={"shard_id": "shard-1", "lease_token": "lease-1"})
        session.add(event)
        session.commit()
        monkeypatch.setattr(celery, "send_task", lambda *_, **__: (_ for _ in ()).throw(ConnectionError("broker down")))
        assert publish_pending_outbox(session) == 0
        retained = session.get(OutboxEvent, event.id)
        assert retained.delivered_at is None
        assert retained.attempts == 1

        sent = []
        monkeypatch.setattr(celery, "send_task", lambda name, args: sent.append((name, args)))
        assert publish_pending_outbox(session) == 1
        delivered = session.get(OutboxEvent, event.id)
        assert delivered.delivered_at is not None
        assert sent == [("scanpod_enterprise.worker.execute_shard", ["shard-1", "lease-1"])]


def test_legacy_outbox_event_is_fenced_before_publish(monkeypatch):
    from scanpod_enterprise.models import InventoryScope, RunStatus, ScanProfile, ScanRun, ScanShard, ShardStatus

    with SessionLocal() as session:
        scope = InventoryScope(name="legacy-scope", cidr="10.73.0.0/24", zone="default", approved=True)
        profile = ScanProfile(name="legacy-profile", version=1, ports="443", zone="default")
        session.add_all([scope, profile])
        session.flush()
        run = ScanRun(inventory_scope_id=scope.id, profile_id=profile.id, requested_by="operator", status=RunStatus.running)
        session.add(run)
        session.flush()
        shard = ScanShard(run_id=run.id, cidr="10.73.0.0/24", zone="default", status=ShardStatus.leased)
        session.add(shard)
        session.flush()
        session.add(OutboxEvent(topic="scan_shard", payload={"shard_id": shard.id}))
        session.commit()

        sent = []
        monkeypatch.setattr(celery, "send_task", lambda name, args: sent.append((name, args)))
        assert publish_pending_outbox(session) == 1

        event = session.query(OutboxEvent).one()
        assert event.payload["lease_token"] == session.get(ScanShard, shard.id).lease_token
        assert sent == [("scanpod_enterprise.worker.execute_shard", [shard.id, event.payload["lease_token"]])]
