"""initial control-plane schema

Revision ID: 20260720_01
Revises:
Create Date: 2026-07-20

This migration deliberately describes the original schema rather than importing
the application's current SQLAlchemy metadata.  A migration must be immutable:
new model fields belong in a later revision so a fresh database follows the
same upgrade path as an existing installation.
"""
from alembic import op
import sqlalchemy as sa


revision = "20260720_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    role = sa.Enum("platform_admin", "inventory_manager", "scan_operator", "auditor", name="role")
    run_status = sa.Enum("queued", "running", "completed", "failed", "cancelled", name="runstatus")
    shard_status = sa.Enum("queued", "leased", "running", "completed", "failed", "cancelled", "dead_letter", name="shardstatus")

    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("role", role, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("subject"),
    )
    op.create_index("ix_users_subject", "users", ["subject"])
    op.create_table(
        "inventory_scopes",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("cidr", sa.String(length=43), nullable=False),
        sa.Column("zone", sa.String(length=64), nullable=False),
        sa.Column("approved", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name"),
        sa.UniqueConstraint("cidr"),
    )
    op.create_index("ix_inventory_scopes_cidr", "inventory_scopes", ["cidr"])
    op.create_table(
        "scan_profiles",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("ports", sa.String(length=512), nullable=False),
        sa.Column("arguments", sa.String(length=512), nullable=False),
        sa.Column("max_rate", sa.Integer(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("zone", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name", "version", name="uq_profile_version"),
    )
    op.create_table(
        "scan_runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("inventory_scope_id", sa.String(length=36), sa.ForeignKey("inventory_scopes.id"), nullable=False),
        sa.Column("profile_id", sa.String(length=36), sa.ForeignKey("scan_profiles.id"), nullable=False),
        sa.Column("status", run_status, nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scan_runs_inventory_scope_id", "scan_runs", ["inventory_scope_id"])
    op.create_index("ix_scan_runs_status", "scan_runs", ["status"])
    op.create_table(
        "scan_schedules",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("inventory_scope_id", sa.String(length=36), sa.ForeignKey("inventory_scopes.id"), nullable=False),
        sa.Column("profile_id", sa.String(length=36), sa.ForeignKey("scan_profiles.id"), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("timezone", sa.String(length=64), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_scan_schedules_inventory_scope_id", "scan_schedules", ["inventory_scope_id"])
    op.create_index("ix_scan_schedules_next_run_at", "scan_schedules", ["next_run_at"])
    op.create_index("ix_scan_schedules_enabled", "scan_schedules", ["enabled"])
    op.create_table(
        "scan_shards",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("cidr", sa.String(length=43), nullable=False),
        sa.Column("zone", sa.String(length=64), nullable=False),
        sa.Column("status", shard_status, nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("artifact_key", sa.String(length=512), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_index("ix_scan_shards_run_id", "scan_shards", ["run_id"])
    op.create_table(
        "host_observations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("shard_id", sa.String(length=36), sa.ForeignKey("scan_shards.id"), nullable=False),
        sa.Column("address", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
    )
    op.create_index("ix_host_observations_run_id", "host_observations", ["run_id"])
    op.create_index("ix_host_observations_shard_id", "host_observations", ["shard_id"])
    op.create_index("ix_host_observations_address", "host_observations", ["address"])
    op.create_table(
        "service_observations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("host_observation_id", sa.String(length=36), sa.ForeignKey("host_observations.id"), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("service", sa.String(length=128), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("version", sa.String(length=128), nullable=True),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("resource_type", sa.String(length=100), nullable=False),
        sa.Column("resource_id", sa.String(length=255), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_events_actor", "audit_events", ["actor"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("service_observations")
    op.drop_table("host_observations")
    op.drop_table("scan_shards")
    op.drop_table("scan_schedules")
    op.drop_table("scan_runs")
    op.drop_table("scan_profiles")
    op.drop_table("inventory_scopes")
    op.drop_table("users")
