"""initial control-plane schema

Revision ID: 20260720_01
Revises:
Create Date: 2026-07-20
"""
from alembic import op

from scanpod_enterprise.db import Base
import scanpod_enterprise.models  # noqa: F401

revision = "20260720_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
