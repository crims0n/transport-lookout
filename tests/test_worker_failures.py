from datetime import datetime, timezone
import uuid

import pytest

from scanpod_enterprise import worker
from scanpod_enterprise.config import settings
from scanpod_enterprise.db import SessionLocal
from scanpod_enterprise.models import InventoryScope, RunStatus, ScanProfile, ScanRun, ScanShard, ShardStatus


class SuccessfulPopen:
    returncode = 0

    def __init__(self, *_args, **_kwargs):
        pass

    def poll(self):
        return 0

    def communicate(self):
        return "", ""


def leased_nmap_shard(session, name: str) -> ScanShard:
    scope = InventoryScope(name=f"{name}-scope", cidr="10.91.0.0/24", zone="default", approved=True)
    profile = ScanProfile(name=f"{name}-profile", version=1, ports="443", zone="default")
    session.add_all([scope, profile])
    session.flush()
    run = ScanRun(
        inventory_scope_id=scope.id,
        profile_id=profile.id,
        requested_by="operator",
        status=RunStatus.queued,
    )
    session.add(run)
    session.flush()
    shard = ScanShard(
        run_id=run.id,
        cidr="10.91.0.0/24",
        zone="default",
        status=ShardStatus.leased,
        lease_expires_at=datetime.now(timezone.utc),
        lease_token=str(uuid.uuid4()),
    )
    session.add(shard)
    session.commit()
    return shard


@pytest.mark.parametrize(
    ("failure", "expected_error"),
    [
        ("normalize", "malformed Nmap XML"),
        ("artifact", "artifact storage unavailable"),
    ],
)
def test_result_handling_errors_requeue_shards_without_waiting_for_lease_expiry(monkeypatch, failure, expected_error):
    monkeypatch.setattr(worker.subprocess, "Popen", SuccessfulPopen)
    if failure == "normalize":
        monkeypatch.setattr(worker, "normalize_nmap_xml", lambda *_args: (_ for _ in ()).throw(RuntimeError(expected_error)))
    else:
        monkeypatch.setattr(worker, "normalize_nmap_xml", lambda *_args: 0)
        monkeypatch.setattr(worker, "store_artifact", lambda *_args: (_ for _ in ()).throw(RuntimeError(expected_error)))

    with SessionLocal() as session:
        shard = leased_nmap_shard(session, failure)
        worker.execute_shard.run(shard.id, shard.lease_token)

        session.expire_all()
        updated = session.get(ScanShard, shard.id)
        assert updated.status == ShardStatus.queued
        assert updated.attempts == 1
        assert updated.retry_not_before is not None
        assert expected_error in updated.error


def test_result_handling_error_dead_letters_at_the_attempt_limit(monkeypatch):
    monkeypatch.setattr(worker.subprocess, "Popen", SuccessfulPopen)
    monkeypatch.setattr(worker, "normalize_nmap_xml", lambda *_args: (_ for _ in ()).throw(RuntimeError("malformed Nmap XML")))
    monkeypatch.setattr(settings, "max_shard_attempts", 1)

    with SessionLocal() as session:
        shard = leased_nmap_shard(session, "dead-letter")
        worker.execute_shard.run(shard.id, shard.lease_token)

        session.expire_all()
        updated = session.get(ScanShard, shard.id)
        assert updated.status == ShardStatus.dead_letter
        assert updated.retry_not_before is None
