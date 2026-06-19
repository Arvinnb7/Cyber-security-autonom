"""Single time source: naive UTC, to match SQLite storage and avoid tz bugs."""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
