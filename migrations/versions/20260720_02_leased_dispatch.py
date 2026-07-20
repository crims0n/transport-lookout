"""bounded shard dispatch

Revision ID: 20260720_02
Revises: 20260720_01
Create Date: 2026-07-20
"""
from alembic import op
import sqlalchemy as sa

revision = "20260720_02"
down_revision = "20260720_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    profile_columns = {column["name"] for column in inspector.get_columns("scan_profiles")}
    shard_columns = {column["name"] for column in inspector.get_columns("scan_shards")}
    if "max_concurrent_shards" not in profile_columns:
        op.add_column("scan_profiles", sa.Column("max_concurrent_shards", sa.Integer(), nullable=False, server_default="4"))
    if "dispatched_at" not in shard_columns:
        op.add_column("scan_shards", sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True))
    if "lease_expires_at" not in shard_columns:
        op.add_column("scan_shards", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
        op.create_index("ix_scan_shards_lease_expires_at", "scan_shards", ["lease_expires_at"])


def downgrade() -> None:
    op.drop_index("ix_scan_shards_lease_expires_at", table_name="scan_shards")
    op.drop_column("scan_shards", "lease_expires_at")
    op.drop_column("scan_shards", "dispatched_at")
    op.drop_column("scan_profiles", "max_concurrent_shards")
