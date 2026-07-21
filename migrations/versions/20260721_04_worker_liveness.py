"""worker liveness and retry state

Revision ID: 20260721_04
Revises: 20260720_03
Create Date: 2026-07-21
"""
from alembic import op
import sqlalchemy as sa

revision = "20260721_04"
down_revision = "20260720_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("scan_shards")}
    if "worker_id" not in columns:
        op.add_column("scan_shards", sa.Column("worker_id", sa.String(length=255), nullable=True))
    if "heartbeat_at" not in columns:
        op.add_column("scan_shards", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
        op.create_index("ix_scan_shards_heartbeat_at", "scan_shards", ["heartbeat_at"])
    if "retry_not_before" not in columns:
        op.add_column("scan_shards", sa.Column("retry_not_before", sa.DateTime(timezone=True), nullable=True))
        op.create_index("ix_scan_shards_retry_not_before", "scan_shards", ["retry_not_before"])


def downgrade() -> None:
    op.drop_index("ix_scan_shards_retry_not_before", table_name="scan_shards")
    op.drop_index("ix_scan_shards_heartbeat_at", table_name="scan_shards")
    op.drop_column("scan_shards", "retry_not_before")
    op.drop_column("scan_shards", "heartbeat_at")
    op.drop_column("scan_shards", "worker_id")
