"""Self-monitoring: watch the watcher.

The whole premise of replacing tier-1 monitoring staff is that the platform is
always looking. The dangerous failure mode is **silent blindness**: an expired
Azure client secret stops ingestion, the dashboard reports "0 active threats"
(which reads like good news), and nobody is left to notice.

This module evaluates the platform's own health every few minutes and hands any
issues to the alerting layer. It is deliberately conservative: it only claims
"stale ingestion" when there is genuinely something that should be producing
events, so an idle demo install never cries wolf.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta

from sqlmodel import Session, func, select

from app.core import runtime
from app.core.config import settings
from app.core.time import utcnow
from app.models.tables import Connection, Event, SystemHealth

logger = logging.getLogger("sentinel.health")

# Severity of a health issue, used to phrase the alert.
CRITICAL = "critical"
WARNING = "warning"


@dataclass(frozen=True)
class HealthIssue:
    key: str          # stable identifier, used for dedup (e.g. "connector_down:3")
    severity: str     # CRITICAL | WARNING
    title: str        # short human summary
    detail: str       # what to do about it

    def line(self) -> str:
        return f"[{self.severity.upper()}] {self.title} — {self.detail}"


# --- heartbeat ------------------------------------------------------------

def get_state(session: Session) -> SystemHealth:
    state = session.get(SystemHealth, 1)
    if state is None:
        state = SystemHealth(id=1)
        session.add(state)
        session.commit()
        session.refresh(state)
    return state


def record_cycle(session: Session, events_ingested: int) -> None:
    """Heartbeat from the ingest job — proves the scheduler is alive."""
    state = get_state(session)
    now = utcnow()
    state.last_cycle_at = now
    if events_ingested > 0:
        state.last_ingest_at = now
    state.updated_at = now
    session.add(state)
    session.commit()


# --- checks ---------------------------------------------------------------

def _check_connectors(session: Session) -> list[HealthIssue]:
    """Enabled integrations that are failing to poll."""
    issues: list[HealthIssue] = []
    conns = session.exec(select(Connection).where(Connection.enabled == True)).all()  # noqa: E712
    for c in conns:
        broken = c.status == "error" or c.consecutive_failures >= settings.health_connector_failures
        if not broken:
            continue
        name = c.display_name or c.provider
        failures = (f"{c.consecutive_failures} consecutive failure(s). "
                    if c.consecutive_failures else "")
        issues.append(HealthIssue(
            key=f"connector_down:{c.id}",
            severity=CRITICAL,
            title=f"Integration '{name}' is not collecting data",
            detail=(f"{failures}Last error: {c.last_error or 'unknown'}. "
                    "Check the credentials/permissions on the Integrations page — "
                    "while this is broken, that source is NOT being monitored."),
        ))
    return issues


def _check_ingestion(session: Session) -> list[HealthIssue]:
    """No events arriving while a live integration is enabled = we are blind."""
    if not runtime.is_live():
        return []                      # demo/simulated traffic isn't a health signal
    enabled = session.exec(
        select(func.count(Connection.id)).where(Connection.enabled == True)  # noqa: E712
    ).one()
    if not enabled:
        return []                      # nothing configured yet — not a fault
    cutoff = utcnow() - timedelta(minutes=settings.health_stale_minutes)
    latest = session.exec(
        select(func.max(Event.timestamp)).where(Event.origin == "live")
    ).one()
    if latest is not None and latest >= cutoff:
        return []
    when = latest.isoformat(sep=" ", timespec="minutes") if latest else "never"
    return [HealthIssue(
        key="ingestion_stale",
        severity=CRITICAL,
        title="No security events received recently",
        detail=(f"Last event ingested: {when} (threshold "
                f"{settings.health_stale_minutes} min). The platform is not "
                "receiving telemetry — an empty dashboard right now does NOT mean "
                "you are safe."),
    )]


def _check_scheduler(session: Session) -> list[HealthIssue]:
    """The background scheduler stopped running cycles."""
    state = get_state(session)
    if state.last_cycle_at is None:
        return []                      # never started yet (fresh boot) — not a fault
    cutoff = utcnow() - timedelta(minutes=settings.health_cycle_stale_minutes)
    if state.last_cycle_at >= cutoff:
        return []
    return [HealthIssue(
        key="scheduler_stalled",
        severity=CRITICAL,
        title="Monitoring engine has stopped running",
        detail=(f"No ingestion cycle since "
                f"{state.last_cycle_at.isoformat(sep=' ', timespec='minutes')}. "
                "The worker process may have died — restart it."),
    )]


def evaluate_health(session: Session) -> list[HealthIssue]:
    """Run every check. Never raises — a broken check must not break the app."""
    issues: list[HealthIssue] = []
    for check in (_check_connectors, _check_ingestion, _check_scheduler):
        try:
            issues.extend(check(session))
        except Exception:  # noqa: BLE001
            logger.exception("health check %s failed", check.__name__)
    return issues


def issue_key(issues: list[HealthIssue]) -> str:
    """Stable key for the current set of issues (drives alert dedup)."""
    return ",".join(sorted(i.key for i in issues))


def _as_dict(issue: HealthIssue) -> dict:
    return {"key": issue.key, "severity": issue.severity,
            "title": issue.title, "detail": issue.detail}


def run_health_check(session: Session) -> dict:
    """Evaluate health, persist the state, and alert on *transitions*.

    Alerting policy (so operators get signal, not spam):
      - healthy  -> degraded : alert immediately
      - degraded -> different issues : alert (the situation changed)
      - degraded -> same issues : alert only after the cooldown expires
      - degraded -> healthy : send one recovery notice
    """
    from app.notifications.service import notify_health

    issues = evaluate_health(session)
    state = get_state(session)
    now = utcnow()
    new_state = "degraded" if issues else "healthy"
    new_key = issue_key(issues)
    was_degraded = state.state == "degraded"

    alerted = False
    if issues:
        cooled = (state.last_alert_at is None or
                  state.last_alert_at <= now - timedelta(minutes=settings.health_alert_cooldown_minutes))
        if not was_degraded or new_key != state.issue_key or cooled:
            notify_health(session, issues)
            state.last_alert_at = now
            alerted = True
        logger.warning("platform health degraded: %s", new_key)
    elif was_degraded:
        notify_health(session, [], recovered=True)
        state.last_alert_at = now
        alerted = True
        logger.info("platform health recovered")

    state.state = new_state
    state.issue_key = new_key
    state.detail = "; ".join(i.title for i in issues)
    state.issues = [_as_dict(i) for i in issues]
    state.updated_at = now
    session.add(state)
    session.commit()
    return {"state": new_state, "issues": len(issues), "alerted": alerted}


def health_snapshot(session: Session, fresh: bool = False) -> dict:
    """Current health for the API/dashboard.

    By default this reports the state the watchdog job already computed (it runs
    every few minutes), so a dashboard open on twenty desks doesn't re-run every
    check on every poll. Pass ``fresh=True`` to force a live evaluation.
    """
    state = get_state(session)
    # Never claim "healthy" on the strength of a check that has not happened:
    # before the watchdog's first run there is no stored verdict, so evaluate now.
    if fresh or state.state == "unknown":
        issues = evaluate_health(session)
        payload = [_as_dict(i) for i in issues]
        status = "degraded" if issues else "healthy"
        fresh = True
    else:
        payload = list(state.issues or [])
        status = state.state
    return {
        "state": status,
        "issues": payload,
        "last_cycle_at": state.last_cycle_at,
        "last_ingest_at": state.last_ingest_at,
        "checked_at": state.updated_at if not fresh else utcnow(),
        "cached": not fresh,
    }
