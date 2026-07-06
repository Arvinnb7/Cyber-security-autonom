"""Runtime data mode — switchable live, inside a single running app.

The active mode ("demo" or "live") is held in memory for fast reads on hot paths
(detectors, analytics) and persisted in the ``AppState`` row so it survives
restarts. Every mode-scoped row is stamped with ``origin`` = the mode that
produced it, and reads filter by the current mode — so switching is instant,
reversible and never mixes or destroys the two datasets.
"""
from __future__ import annotations

import logging

from sqlmodel import Session

from app.core.config import settings
from app.core.time import utcnow
from app.models.tables import AppState

logger = logging.getLogger("sentinel.runtime")

VALID_MODES = ("demo", "live")
_mode: str | None = None


def init_mode(session: Session) -> str:
    """Load the persisted mode (or seed it from the DATA_MODE env default)."""
    global _mode
    state = session.get(AppState, 1)
    if state is None:
        state = AppState(id=1, data_mode="demo" if settings.is_demo else "live")
        session.add(state)
        session.commit()
    _mode = state.data_mode
    return _mode


def current_mode() -> str:
    # Falls back to the env default before init (e.g. in unit tests).
    if _mode is None:
        return "demo" if settings.is_demo else "live"
    return _mode


def is_demo() -> bool:
    return current_mode() == "demo"


def is_live() -> bool:
    return current_mode() == "live"


def set_mode(session: Session, mode: str) -> str:
    global _mode
    mode = mode.strip().lower()
    if mode not in VALID_MODES:
        raise ValueError(f"invalid mode '{mode}', expected one of {VALID_MODES}")
    state = session.get(AppState, 1) or AppState(id=1)
    state.data_mode = mode
    state.updated_at = utcnow()
    session.add(state)
    session.commit()
    _mode = mode
    logger.info("data mode switched to %s", mode)
    return mode
