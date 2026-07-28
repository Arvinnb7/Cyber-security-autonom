"""Shared analytics used by the dashboard (F9), chat (F7) and reports (F10).

Every query is scoped to the current data mode's ``origin`` so demo and live
datasets never bleed into each other when the user switches modes in-app.
"""
from __future__ import annotations

from datetime import timedelta

from sqlmodel import Session, func, select

from app.core import runtime
from app.core.config import settings
from app.core.limits import BoundedTTLCache
from app.core.time import utcnow
from app.models.tables import Asset, AuditAction, Event, Incident, User


def _risk_band(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def org_risk(session: Session) -> dict:
    """Overall organization risk = blend of worst active incident and load (F9).

    Aggregated in SQL — the dashboard polls this constantly, so it must not scale
    with how many incidents are open.
    """
    top, count = session.exec(
        select(func.max(Incident.final_score), func.count(Incident.id))
        .where(Incident.status.in_(["open", "investigating"]),
               Incident.origin == runtime.current_mode())
    ).one()
    count = count or 0
    if not count:
        score = 0.0
    else:
        load = min(count * 4, 30)
        score = min(100.0, 0.8 * (top or 0.0) + load)
    return {
        "score": round(score, 1),
        "band": _risk_band(score),
        "active_incidents": count,
    }


def top_incidents(session: Session, limit: int = 10, since_hours: int | None = None,
                  status: str | None = None) -> list[Incident]:
    q = select(Incident).where(Incident.origin == runtime.current_mode())
    if status:
        q = q.where(Incident.status == status)
    if since_hours:
        cutoff = utcnow() - timedelta(hours=since_hours)
        q = q.where(Incident.created_at >= cutoff)
    q = q.order_by(Incident.final_score.desc(), Incident.created_at.desc()).limit(limit)
    return list(session.exec(q))


def riskiest_users(session: Session, limit: int = 10) -> list[User]:
    return list(session.exec(
        select(User).where(User.origin == runtime.current_mode())
        .order_by(User.risk_score.desc()).limit(limit)
    ))


def riskiest_assets(session: Session, limit: int = 10) -> list[Asset]:
    return list(session.exec(
        select(Asset).where(Asset.origin == runtime.current_mode())
        .order_by(Asset.risk_score.desc()).limit(limit)
    ))


def active_threats(session: Session) -> list[dict]:
    """Active threats grouped by catalog detection (F9)."""
    rows = session.exec(
        select(Incident.threat_type, Incident.det_id, func.count(Incident.id), func.max(Incident.final_score))
        .where(Incident.status.in_(["open", "investigating"]), Incident.origin == runtime.current_mode())
        .group_by(Incident.threat_type, Incident.det_id)
    ).all()
    return [
        {"threat_type": t, "det_id": d, "count": c, "max_score": round(m or 0, 1)}
        for t, d, c, m in sorted(rows, key=lambda r: r[3] or 0, reverse=True)
    ]


def detections_by_severity(session: Session) -> dict[str, int]:
    """Active-incident counts per severity band (catalog scoring_model)."""
    rows = session.exec(
        select(Incident.severity, func.count(Incident.id))
        .where(Incident.status.in_(["open", "investigating"]), Incident.origin == runtime.current_mode())
        .group_by(Incident.severity)
    ).all()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sev, c in rows:
        counts[sev or "low"] = c
    return counts


# Short-lived in-process cache for the SLA figures. They are polled by every open
# dashboard and embedded in reports, but they move slowly — a minute-old answer is
# indistinguishable from a fresh one and costs nothing.
#
# Bounded on purpose: the cache key includes the caller-supplied window, so an
# unbounded dict here would let `?days=1,2,3,…` grow memory without limit.
_SLA_CACHE_TTL = 60.0
_sla_cache = BoundedTTLCache(maxsize=128, ttl_seconds=_SLA_CACHE_TTL)


def invalidate_sla_cache() -> None:
    _sla_cache.clear()


def _minutes_between(start, end) -> float | None:
    if start is None or end is None:
        return None
    return max((end - start).total_seconds() / 60.0, 0.0)


def _avg(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 1) if values else None


def sla_metrics(session: Session, days: int = 30) -> dict:
    """Response-time & accuracy metrics — the evidence that the automation is
    doing the tier-1 job.

    MTTA  = incident created -> a human acknowledged it
    MTTR  = incident created -> case closed (resolved/dismissed)
    Anything Sentinel triaged and closed without a human ever acknowledging it
    counts as *autonomously handled* — that is the headcount argument, stated
    honestly rather than assumed.

    Computed with SQL aggregates: this is polled by the dashboard and embedded in
    reports, so it must not depend on how many incidents exist.
    """
    mode = runtime.current_mode()
    # Clamp defensively: this is also called from the report generator, and an
    # absurd window would overflow the date arithmetic below.
    days = max(1, min(int(days), settings.max_sla_window_days))
    cached = _sla_cache.get((mode, days))
    if cached is not None:
        return cached

    cutoff = utcnow() - timedelta(days=days)
    scope = (Incident.origin == mode, Incident.created_at >= cutoff)
    closed_states = ["resolved", "dismissed"]

    # Only the timestamps needed for the duration averages — computed in Python
    # because SQLite and Postgres disagree on datetime arithmetic, but over a
    # projection of two columns rather than whole ORM objects.
    ack_rows = session.exec(
        select(Incident.created_at, Incident.acknowledged_at)
        .where(*scope, Incident.acknowledged_at.is_not(None))
    ).all()
    res_rows = session.exec(
        select(Incident.created_at, Incident.resolved_at)
        .where(*scope, Incident.resolved_at.is_not(None))
    ).all()
    ack_times = [m for m in (_minutes_between(a, b) for a, b in ack_rows) if m is not None]
    res_times = [m for m in (_minutes_between(a, b) for a, b in res_rows) if m is not None]

    total = session.exec(select(func.count(Incident.id)).where(*scope)).one()
    closed = session.exec(
        select(func.count(Incident.id)).where(*scope, Incident.status.in_(closed_states))
    ).one()
    autonomous = session.exec(
        select(func.count(Incident.id)).where(*scope, Incident.status.in_(closed_states),
                                              Incident.acknowledged_at.is_(None))
    ).one()

    # Closed cases carrying an analyst verdict, grouped per detection.
    verdict_rows = session.exec(
        select(Incident.det_id, Incident.closed_reason, func.count(Incident.id))
        .where(*scope, Incident.status.in_(closed_states), Incident.closed_reason != "")
        .group_by(Incident.det_id, Incident.closed_reason)
    ).all()
    by_detection: dict[str, dict[str, int]] = {}
    with_reason = 0
    false_positives = 0
    for det_id, reason, count in verdict_rows:
        row = by_detection.setdefault(det_id or "unknown", {"closed": 0, "false_positive": 0})
        row["closed"] += count
        with_reason += count
        if reason == "false_positive":
            row["false_positive"] += count
            false_positives += count

    result = {
        "window_days": days,
        "incidents": total or 0,
        "closed": closed or 0,
        "mtta_minutes": _avg(ack_times),
        "mttr_minutes": _avg(res_times),
        "acknowledged": len(ack_times),
        "triaged_with_reason": with_reason,
        "false_positives": false_positives,
        "false_positive_rate": (round(100.0 * false_positives / with_reason, 1)
                                if with_reason else None),
        "autonomously_handled": autonomous or 0,
        "autonomous_pct": round(100.0 * (autonomous or 0) / closed, 1) if closed else None,
        "by_detection": by_detection,
    }
    _sla_cache.set((mode, days), result)
    return result


def stats_overview(session: Session) -> dict:
    mode = runtime.current_mode()
    total = session.exec(select(func.count(Incident.id)).where(Incident.origin == mode)).one()
    resolved = session.exec(
        select(func.count(Incident.id)).where(Incident.status == "resolved", Incident.origin == mode)
    ).one()
    events = session.exec(select(func.count(Event.id)).where(Event.origin == mode)).one()
    pending_actions = session.exec(
        select(func.count(AuditAction.id)).where(AuditAction.status == "pending", AuditAction.origin == mode)
    ).one()
    return {
        "total_incidents": total,
        "resolved_incidents": resolved,
        "total_events": events,
        "pending_actions": pending_actions,
    }
