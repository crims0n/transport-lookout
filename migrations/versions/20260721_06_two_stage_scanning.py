"""two-stage Masscan discovery and Nmap confirmation

Revision ID: 20260721_06
Revises: 20260721_05
Create Date: 2026-07-21
"""
from alembic import op
import sqlalchemy as sa


revision = "20260721_06"
down_revision = "20260721_05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    profile_columns = {column["name"] for column in inspector.get_columns("scan_profiles")}
    shard_columns = {column["name"] for column in inspector.get_columns("scan_shards")}
    if "scanner_mode" not in profile_columns:
        op.add_column("scan_profiles", sa.Column("scanner_mode", sa.String(length=32), nullable=False, server_default="nmap"))
    if "discovery_artifact_key" not in shard_columns:
        op.add_column("scan_shards", sa.Column("discovery_artifact_key", sa.String(length=512), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_shards", "discovery_artifact_key")
    op.drop_column("scan_profiles", "scanner_mode")
