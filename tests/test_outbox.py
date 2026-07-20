from scanpod_enterprise.db import SessionLocal
from scanpod_enterprise.models import OutboxEvent
from scanpod_enterprise.services import publish_pending_outbox
from scanpod_enterprise.worker import celery


def test_failed_publish_is_retained_and_retried(monkeypatch):
    with SessionLocal() as session:
        event = OutboxEvent(topic="scan_shard", payload={"shard_id": "shard-1"})
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
        assert sent == [("scanpod_enterprise.worker.execute_shard", ["shard-1"])]
