"""Migration history is tested independently of ORM metadata creation."""
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def test_blank_database_upgrades_to_the_current_schema(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'migrations.db'}"
    root = Path(__file__).resolve().parents[1]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    engine = create_engine(database_url)
    config.attributes["connection"] = engine

    command.upgrade(config, "head")

    inspector = inspect(engine)
    assert {"inventory_scopes", "scan_profiles", "scan_runs", "scan_shards", "outbox_events", "current_exposures"} <= set(inspector.get_table_names())
    assert {"worker_id", "heartbeat_at", "retry_not_before"} <= {column["name"] for column in inspector.get_columns("scan_shards")}
    assert "max_concurrent_shards" in {column["name"] for column in inspector.get_columns("scan_profiles")}
