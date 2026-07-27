"""add persisted user baselines + composite indexes for the real query patterns

Revision ID: 0004_scale_indexes_and_baseline
Revises: 0003_health_and_casework
Create Date: 2026-07-26 00:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlmodel import SQLModel

import app.models  # noqa: F401 - ensure all tables are registered
from app.models.tables import UserBaselineState

revision = "0004_scale_indexes_and_baseline"
down_revision = "0003_health_and_casework"
branch_labels = None
depends_on = None

_TABLES = [UserBaselineState.__table__]

# Single-column indexes only let the planner use one predicate per query. These
# match how the hot paths actually filter.
_INDEXES: list[tuple[str, str, list[str]]] = [
    # Baseline rebuild: origin + action + time window.
    ("ix_event_origin_action_ts", "event", ["origin", "action", "timestamp"]),
    # Detection correlation window.
    ("ix_event_origin_ts", "event", ["origin", "timestamp"]),
    # Activity-scoped detection (subjects touched this cycle).
    ("ix_event_origin_actor_ts", "event", ["origin", "actor_username", "timestamp"]),
    # Dashboard/analytics.
    ("ix_incident_origin_status", "incident", ["origin", "status"]),
    ("ix_incident_origin_created", "incident", ["origin", "created_at"]),
    # Signal dedup lookback.
    ("ix_signal_origin_created", "signal", ["origin", "created_at"]),
    # Baseline lookups.
    ("ix_userbaselinestate_origin_username", "userbaselinestate", ["origin", "username"]),
]


# Columns added to existing tables by this revision.
_COLUMNS = [
    ("systemhealth", sa.Column("issues", sa.JSON(), nullable=True)),
]


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table not in inspector.get_table_names():
        return set()
    return {c["name"] for c in inspector.get_columns(table)}


def _indexes(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table not in inspector.get_table_names():
        return set()
    return {i["name"] for i in inspector.get_indexes(table)}


def upgrade() -> None:
    SQLModel.metadata.create_all(op.get_bind(), tables=_TABLES)
    for table, column in _COLUMNS:
        if column.name not in _columns(table):
            op.add_column(table, column)
    present = _tables()
    for name, table, columns in _INDEXES:
        if table in present and name not in _indexes(table):
            op.create_index(name, table, columns)


def downgrade() -> None:
    for name, table, _cols in reversed(_INDEXES):
        if name in _indexes(table):
            op.drop_index(name, table_name=table)
    for table, column in reversed(_COLUMNS):
        if column.name in _columns(table):
            op.drop_column(table, column.name)
    SQLModel.metadata.drop_all(op.get_bind(), tables=_TABLES)
