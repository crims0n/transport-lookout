"""exposure observation counts

Revision ID: 20260721_08
Revises: 20260721_07
Create Date: 2026-07-21
"""
from alembic import op
import sqlalchemy as sa


revision = "20260721_08"
down_revision = "20260721_07"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("current_exposures")}
    if "scan_count" not in columns:
        op.add_column("current_exposures", sa.Column("scan_count", sa.Integer(), nullable=False, server_default="1"))


def downgrade() -> None:
    op.drop_column("current_exposures", "scan_count")
