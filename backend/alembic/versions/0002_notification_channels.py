"""add notification channels + notification log (operational alerting)

Revision ID: 0002_notification_channels
Revises: 0001_baseline
Create Date: 2026-07-14 00:00:00
"""
from __future__ import annotations

from alembic import op
from sqlmodel import SQLModel

import app.models  # noqa: F401 - ensure all tables are registered
from app.models.tables import Notification, NotificationChannel

revision = "0002_notification_channels"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None

# Only the tables this revision introduces (create_all is checkfirst=True, so
# this is a no-op on databases where the baseline already created them and adds
# exactly these two on databases already stamped at 0001).
_TABLES = [NotificationChannel.__table__, Notification.__table__]


def upgrade() -> None:
    SQLModel.metadata.create_all(op.get_bind(), tables=_TABLES)


def downgrade() -> None:
    SQLModel.metadata.drop_all(op.get_bind(), tables=list(reversed(_TABLES)))
