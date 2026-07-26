"""add self-monitoring health + incident casework fields

Revision ID: 0003_health_and_casework
Revises: 0002_notification_channels
Create Date: 2026-07-26 00:00:00
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlmodel import SQLModel

import app.models  # noqa: F401 - ensure all tables are registered
from app.models.tables import IncidentNote, SystemHealth

revision = "0003_health_and_casework"
down_revision = "0002_notification_channels"
branch_labels = None
depends_on = None

_TABLES = [SystemHealth.__table__, IncidentNote.__table__]

# (table, column) added to existing tables by this revision.
_COLUMNS = [
    ("incident", sa.Column("assigned_to", sa.String(), nullable=True)),
    ("incident", sa.Column("acknowledged_at", sa.DateTime(), nullable=True)),
    ("incident", sa.Column("acknowledged_by", sa.String(), nullable=True)),
    ("incident", sa.Column("resolved_at", sa.DateTime(), nullable=True)),
    ("incident", sa.Column("closed_reason", sa.String(), nullable=False, server_default="")),
    ("notificationchannel", sa.Column("notify_on_health", sa.Boolean(), nullable=False,
                                      server_default=sa.true())),
]


_INDEX = "ix_incident_assigned_to"


def _existing(table: str) -> set[str]:
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
    # Both paths must work: a brand-new database (where 0001's create_all already
    # built these from current metadata) and a live one stamped at 0002 (where
    # they genuinely need adding). Every step is therefore checked first.
    SQLModel.metadata.create_all(op.get_bind(), tables=_TABLES)
    for table, column in _COLUMNS:
        if column.name not in _existing(table):
            op.add_column(table, column)
    if _INDEX not in _indexes("incident"):
        op.create_index(_INDEX, "incident", ["assigned_to"])


def downgrade() -> None:
    if _INDEX in _indexes("incident"):
        op.drop_index(_INDEX, table_name="incident")
    for table, column in reversed(_COLUMNS):
        if column.name in _existing(table):
            op.drop_column(table, column.name)
    SQLModel.metadata.drop_all(op.get_bind(), tables=list(reversed(_TABLES)))
