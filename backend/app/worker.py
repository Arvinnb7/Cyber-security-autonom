"""Dedicated background worker: runs the scheduler (ingestion, reports, retention).

In production the API runs with multiple stateless workers and the scheduler
disabled; this single worker owns the periodic jobs so ingestion isn't duplicated.
Run with SENTINEL_RUN_SCHEDULER=true.
"""
from __future__ import annotations

import logging
import sys
import time
from datetime import timedelta

from sqlmodel import Session

from app.core import runtime
from app.core.config import settings
from app.core.db import engine, init_db
from app.core.logging import setup_logging
from app.core.scheduler import start_scheduler
from app.core.time import utcnow

setup_logging()
logger = logging.getLogger("sentinel.worker")


def healthcheck() -> int:
    """Exit 0 only if the scheduler is genuinely still running cycles.

    A process that is merely *alive* proves nothing: the whole point of this
    container is that jobs keep firing, so liveness is judged on the heartbeat
    the ingest job writes, not on the process existing.
    """
    from app.monitoring.health import get_state

    grace = timedelta(minutes=max(settings.health_cycle_stale_minutes * 2, 10))
    try:
        with Session(engine) as session:
            state = get_state(session)
    except Exception as exc:  # noqa: BLE001
        print(f"worker unhealthy: database unreachable ({exc})")
        return 1
    if state.last_cycle_at is None:
        return 0                      # still starting up; no cycle yet
    age = utcnow() - state.last_cycle_at
    if age > grace:
        print(f"worker unhealthy: last cycle {age} ago")
        return 1
    return 0


def main() -> None:
    # The API container runs migrations first (compose depends_on healthy); this
    # call is idempotent (no-op once the schema is at head).
    init_db()
    with Session(engine) as session:
        runtime.init_mode(session)
    start_scheduler()
    logger.info("worker started (scheduler running)")
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    if "--check" in sys.argv:
        raise SystemExit(healthcheck())
    main()
