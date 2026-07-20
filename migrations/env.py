from alembic import context

from scanpod_enterprise.config import settings
from scanpod_enterprise.db import Base
import scanpod_enterprise.models  # noqa: F401

config = context.config
config.set_main_option("sqlalchemy.url", settings.database_url)


def run_migrations_online() -> None:
    connectable = context.config.attributes.get("connection")
    if connectable is None:
        from sqlalchemy import engine_from_config, pool
        connectable = engine_from_config(config.get_section(config.config_ini_section), prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
