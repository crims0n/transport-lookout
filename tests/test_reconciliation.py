from scanpod_enterprise.db import SessionLocal
from scanpod_enterprise.models import RunStatus, ScanRun, ScanShard, ShardStatus
from scanpod_enterprise.services import reconcile_terminal_runs


def test_reconciliation_completes_parent_when_every_shard_is_terminal():
    with SessionLocal() as session:
        run = ScanRun(inventory_scope_id="scope", profile_id="profile", requested_by="operator", status=RunStatus.running)
        session.add(run)
        session.flush()
        session.add_all([
            ScanShard(run_id=run.id, cidr="10.0.0.0/24", zone="default", status=ShardStatus.completed),
            ScanShard(run_id=run.id, cidr="10.0.1.0/24", zone="default", status=ShardStatus.cancelled),
        ])
        session.commit()
        assert reconcile_terminal_runs(session) == 1
        assert session.get(ScanRun, run.id).status == RunStatus.completed
