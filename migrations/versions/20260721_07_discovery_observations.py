"""persist Masscan discovery observations

Revision ID: 20260721_07
Revises: 20260721_06
Create Date: 2026-07-21
"""
from alembic import op
import sqlalchemy as sa


revision = "20260721_07"
down_revision = "20260721_06"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "discovery_observations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("shard_id", sa.String(length=36), sa.ForeignKey("scan_shards.id"), nullable=False),
        sa.Column("address", sa.String(length=64), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.UniqueConstraint("shard_id", "address", "protocol", "port", name="uq_discovery_observation"),
    )
    op.create_index("ix_discovery_observations_run_id", "discovery_observations", ["run_id"])
    op.create_index("ix_discovery_observations_shard_id", "discovery_observations", ["shard_id"])
    op.create_index("ix_discovery_observations_address", "discovery_observations", ["address"])


def downgrade() -> None:
    op.drop_table("discovery_observations")
