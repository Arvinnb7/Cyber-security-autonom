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
    from app.monitoring.health import record_cycle

    try:
        with Session(engine) as session:
            result = run_full_cycle(session)
            # Heartbeat: proves to the watchdog that the engine is alive.
            record_cycle(session, result.get("events_ingested", 0))
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


def _escalation_job() -> None:
    """Re-alert response actions still waiting on manager approval (F: alerting)."""
    from app.notifications.service import escalate_pending_approvals

    try:
        with Session(engine) as session:
            n = escalate_pending_approvals(session)
            if n:
                logger.info("escalated %d pending approval(s)", n)
    except Exception:  # noqa: BLE001
        logger.exception("escalation job failed")


def _health_job() -> None:
    """Watch the watcher: alert if the platform itself has gone blind."""
    from app.monitoring.health import run_health_check

    try:
        with Session(engine) as session:
            run_health_check(session)
    except Exception:  # noqa: BLE001
        logger.exception("health job failed")


def _retention_job() -> None:
    """Purge raw events/signals past the retention window (incidents are kept)."""
    from datetime import timedelta

    from sqlmodel import delete

    from app.core.time import utcnow
    from app.models.tables import Event, Signal

    try:
        cutoff = utcnow() - timedelta(days=settings.retention_days)
        with Session(engine) as session:
            session.exec(delete(Signal).where(Signal.created_at < cutoff))
            session.exec(delete(Event).where(Event.timestamp < cutoff))
            session.commit()
    except Exception:  # noqa: BLE001
        logger.exception("retention job failed")


def start_scheduler() -> None:
    global _scheduler
    if _scheduler is not None or not settings.run_scheduler:
        return
    # Runs in both data modes (demo drives simulators, live polls real connectors).
    # In production, only ONE process should run this (a dedicated worker); API
    # workers set SENTINEL_RUN_SCHEDULER=false to avoid duplicate ingestion.
    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(_ingest_job, "interval", seconds=settings.ingest_interval_seconds,
                       id="ingest", max_instances=1, coalesce=True)
    _scheduler.add_job(_weekly_report_job, "interval", days=7, id="weekly_report")
    _scheduler.add_job(_escalation_job, "interval", minutes=10, id="approval_escalation",
                       max_instances=1, coalesce=True)
    _scheduler.add_job(_health_job, "interval", minutes=5, id="self_monitoring",
                       max_instances=1, coalesce=True)
    _scheduler.add_job(_retention_job, "interval", days=1, id="retention")
    _scheduler.start()
    logger.info("scheduler started (mode=%s, ingest every %ss, retention %sd)",
                settings.data_mode, settings.ingest_interval_seconds, settings.retention_days)


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
