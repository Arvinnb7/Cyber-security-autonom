"""Dedicated background worker: runs the scheduler (ingestion, reports, retention).

In production the API runs with multiple stateless workers and the scheduler
disabled; this single worker owns the periodic jobs so ingestion isn't duplicated.
Run with SENTINEL_RUN_SCHEDULER=true.
"""
from __future__ import annotations

import logging
import time

from sqlmodel import Session

from app.core import runtime
from app.core.db import engine, init_db
from app.core.logging import setup_logging
from app.core.scheduler import start_scheduler

setup_logging()
logger = logging.getLogger("sentinel.worker")


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
    main()
