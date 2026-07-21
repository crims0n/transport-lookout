"""current exposure inventory

Revision ID: 20260721_05
Revises: 20260721_04
Create Date: 2026-07-21
"""
from alembic import op
import sqlalchemy as sa

revision = "20260721_05"
down_revision = "20260721_04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "current_exposures" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "current_exposures",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("inventory_scope_id", sa.String(length=36), sa.ForeignKey("inventory_scopes.id"), nullable=False),
        sa.Column("profile_id", sa.String(length=36), sa.ForeignKey("scan_profiles.id"), nullable=False),
        sa.Column("latest_run_id", sa.String(length=36), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("zone", sa.String(length=64), nullable=False), sa.Column("address", sa.String(length=64), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False), sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("service", sa.String(length=128)), sa.Column("product", sa.String(length=255)), sa.Column("version", sa.String(length=128)),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False), sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("inventory_scope_id", "profile_id", "address", "protocol", "port", name="uq_current_exposure"),
    )
    for column in ("inventory_scope_id", "profile_id", "latest_run_id", "zone", "address", "port", "last_seen_at"):
        op.create_index(f"ix_current_exposures_{column}", "current_exposures", [column])


def downgrade() -> None:
    op.drop_table("current_exposures")
