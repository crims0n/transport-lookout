"""Durable schedule dispatcher; run as a single replicated deployment initially."""
import time
from datetime import datetime, timedelta, timezone
from .db import SessionLocal
from .models import InventoryScope, RunStatus, ScanProfile, ScanRun, ScanSchedule, ScanShard, ShardStatus
from .services import audit, backfill_current_exposures, create_run, dispatch_available_shards, publish_pending_outbox, reconcile_terminal_runs, recover_expired_leases


def dispatch_ready_runs(now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc)
    dispatched = 0
    with SessionLocal() as session:
        run_ids = (session.query(ScanRun.id).join(ScanShard).filter(ScanRun.status.in_([RunStatus.queued, RunStatus.running]), ScanShard.status == ShardStatus.queued, (ScanShard.retry_not_before.is_(None) | (ScanShard.retry_not_before <= now))).distinct().all())
        for (run_id,) in run_ids:
            dispatched += dispatch_available_shards(session, run_id)
    return dispatched


def dispatch_due_schedules(now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc)
    dispatched = 0
    with SessionLocal() as session:
        due = (session.query(ScanSchedule).filter(ScanSchedule.enabled.is_(True), ScanSchedule.next_run_at <= now).with_for_update(skip_locked=True).all())
        for schedule in due:
            scope = session.get(InventoryScope, schedule.inventory_scope_id)
            profile = session.get(ScanProfile, schedule.profile_id)
            if not scope or not profile or not scope.approved or scope.zone != profile.zone:
                schedule.enabled = False
                audit(session, "scheduler", "schedule.disabled", "scan_schedule", schedule.id, reason="scope/profile unavailable or incompatible")
                session.commit()
                continue
            create_run(session, scope, profile, schedule.created_by)
            # Advance from the scheduled instant and skip missed intervals. V1 does
            # not backfill old scans after downtime.
            scheduled_at = schedule.next_run_at
            if scheduled_at.tzinfo is None:  # SQLite test/dev compatibility
                scheduled_at = scheduled_at.replace(tzinfo=timezone.utc)
            next_run = scheduled_at + timedelta(minutes=schedule.interval_minutes)
            while next_run <= now:
                next_run += timedelta(minutes=schedule.interval_minutes)
            schedule.next_run_at = next_run
            audit(session, "scheduler", "schedule.dispatched", "scan_schedule", schedule.id)
            session.commit()
            dispatched += 1
    return dispatched


def main() -> None:
    with SessionLocal() as session:
        backfill_current_exposures(session)
    while True:
        with SessionLocal() as session:
            recover_expired_leases(session)
            publish_pending_outbox(session)
            reconcile_terminal_runs(session)
        dispatch_ready_runs()
        dispatch_due_schedules()
        time.sleep(30)


if __name__ == "__main__":
    main()
