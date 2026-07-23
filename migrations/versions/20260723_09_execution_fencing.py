"""add execution fencing tokens

Revision ID: 20260723_09
Revises: 20260721_08
Create Date: 2026-07-23
"""
from alembic import op
import sqlalchemy as sa


revision = "20260723_09"
down_revision = "20260721_08"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_shards", sa.Column("lease_token", sa.String(length=36), nullable=True))
    op.create_index("ix_scan_shards_lease_token", "scan_shards", ["lease_token"])
    op.add_column("host_observations", sa.Column("lease_token", sa.String(length=36), nullable=True))
    op.create_index("ix_host_observations_lease_token", "host_observations", ["lease_token"])
    op.add_column("discovery_observations", sa.Column("lease_token", sa.String(length=36), nullable=True))
    op.create_index("ix_discovery_observations_lease_token", "discovery_observations", ["lease_token"])


def downgrade() -> None:
    op.drop_index("ix_discovery_observations_lease_token", table_name="discovery_observations")
    op.drop_column("discovery_observations", "lease_token")
    op.drop_index("ix_host_observations_lease_token", table_name="host_observations")
    op.drop_column("host_observations", "lease_token")
    op.drop_index("ix_scan_shards_lease_token", table_name="scan_shards")
    op.drop_column("scan_shards", "lease_token")
