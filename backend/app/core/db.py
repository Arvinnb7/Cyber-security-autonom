"""Database engine + session management.

SQLite for local dev/tests; PostgreSQL for production. Schema is owned by Alembic
migrations in production; dev/SQLite falls back to ``create_all`` for zero setup.
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

from app.core.config import settings

logger = logging.getLogger("sentinel.db")

_is_sqlite = settings.database_url.startswith("sqlite")
connect_args = {"check_same_thread": False} if _is_sqlite else {}
engine = create_engine(settings.database_url, echo=False, pool_pre_ping=not _is_sqlite,
                       connect_args=connect_args)


def run_migrations() -> None:
    """Bring the database schema to the latest Alembic revision."""
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(cfg, "head")


def init_db() -> None:
    from app import models  # noqa: F401 - register tables

    if _is_sqlite:
        # Zero-config for local dev and tests.
        SQLModel.metadata.create_all(engine)
    else:
        # Production (Postgres): migrations are the source of truth.
        run_migrations()
        logger.info("database migrated to head")


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
