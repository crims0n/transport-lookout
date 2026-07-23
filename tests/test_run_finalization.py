from scanpod_enterprise.db import SessionLocal
from scanpod_enterprise.models import AuditEvent, DiscoveryObservation, InventoryScope, RunStatus, ScanProfile, ScanRun, ScanShard, ShardStatus
from scanpod_enterprise.services import finalize_terminal_run, reconcile_terminal_runs


def add_run(session, name: str):
    scope = InventoryScope(name=f"{name}-scope", cidr="10.90.0.0/24", zone="default", approved=True)
    profile = ScanProfile(name=f"{name}-profile", version=1, ports="443", zone="default", scanner_mode="masscan_then_nmap")
    session.add_all([scope, profile])
    session.flush()
    run = ScanRun(inventory_scope_id=scope.id, profile_id=profile.id, requested_by="operator", status=RunStatus.running)
    session.add(run)
    session.flush()
    return run


def test_finalizer_flushes_a_workers_uncommitted_completed_shard():
    with SessionLocal() as session:
        run = add_run(session, "flush")
        shard = ScanShard(run_id=run.id, cidr="10.90.0.0/24", zone="default", status=ShardStatus.running)
        session.add(shard)
        session.commit()

        # This mirrors the worker's final state change. SessionLocal disables
        # autoflush, so finalization must flush before it queries shard state.
        shard.status = ShardStatus.completed
        assert finalize_terminal_run(session, run, "worker") is True
        session.commit()

        assert session.get(ScanRun, run.id).status == RunStatus.completed


def test_reconciler_applies_the_same_incomplete_masscan_coverage_gate():
    with SessionLocal() as session:
        run = add_run(session, "incomplete")
        shard = ScanShard(
            run_id=run.id,
            cidr="10.90.0.0/24",
            zone="default",
            status=ShardStatus.completed,
            discovery_artifact_key="runs/incomplete/masscan.xml",
        )
        session.add(shard)
        session.flush()
        session.add(DiscoveryObservation(run_id=run.id, shard_id=shard.id, address="10.90.0.10", protocol="tcp", port=443))
        session.commit()

        assert reconcile_terminal_runs(session) == 1
        skipped = session.query(AuditEvent).filter_by(action="run.inventory_update_skipped", resource_id=run.id).one()
        assert skipped.detail["reason"] == "incomplete_masscan_coverage"


def test_empty_masscan_discovery_does_not_block_finalization():
    with SessionLocal() as session:
        run = add_run(session, "empty")
        session.add(ScanShard(
            run_id=run.id,
            cidr="10.90.0.0/24",
            zone="default",
            status=ShardStatus.completed,
            discovery_artifact_key="runs/empty/masscan.xml",
        ))
        session.commit()

        assert reconcile_terminal_runs(session) == 1
        assert session.get(ScanRun, run.id).status == RunStatus.completed
        assert session.query(AuditEvent).filter_by(action="run.inventory_update_skipped", resource_id=run.id).count() == 0
