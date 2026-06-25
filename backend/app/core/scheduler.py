"""Background scheduler: continuous ingestion + weekly report (APScheduler)."""
from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from sqlmodel import Session

from app.core.config import settings
from app.core.db import engine

logger = logging.getLogger("sentinel.scheduler")
_scheduler: BackgroundScheduler | None = None


def _ingest_job() -> None:
    from app.ingestion.pipeline import run_full_cycle

    try:
        with Session(engine) as session:
            run_full_cycle(session)
    except Exception:  # noqa: BLE001 - keep the scheduler alive
        logger.exception("ingest job failed")


def _weekly_report_job() -> None:
    from app.reporting.weekly import generate_weekly_report

    try:
        with Session(engine) as session:
            generate_weekly_report(session)
            logger.info("weekly report generated")
    except Exception:  # noqa: BLE001
        logger.exception("weekly report job failed")


def start_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        return
    # The scheduler runs in BOTH modes: in demo it drives the simulators, in live
    # it polls the real connectors. The cycle itself decides what data to pull.
    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(_ingest_job, "interval", seconds=settings.ingest_interval_seconds,
                       id="ingest", max_instances=1, coalesce=True)
    # Weekly in production; for the demo we also expose a manual trigger via the API.
    _scheduler.add_job(_weekly_report_job, "interval", days=7, id="weekly_report")
    _scheduler.start()
    logger.info("scheduler started (mode=%s, ingest every %ss)",
                settings.data_mode, settings.ingest_interval_seconds)


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
