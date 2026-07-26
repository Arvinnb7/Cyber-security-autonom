"""Shared analytics used by the dashboard (F9), chat (F7) and reports (F10).

Every query is scoped to the current data mode's ``origin`` so demo and live
datasets never bleed into each other when the user switches modes in-app.
"""
from __future__ import annotations

from datetime import timedelta

from sqlmodel import Session, func, select

from app.core import runtime
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
    """Overall organization risk = blend of worst active incident and load (F9)."""
    open_incidents = list(session.exec(
        select(Incident).where(Incident.status.in_(["open", "investigating"]),
                               Incident.origin == runtime.current_mode())
    ))
    if not open_incidents:
        score = 0.0
    else:
        top = max(i.final_score for i in open_incidents)
        load = min(len(open_incidents) * 4, 30)
        score = min(100.0, 0.8 * top + load)
    return {
        "score": round(score, 1),
        "band": _risk_band(score),
        "active_incidents": len(open_incidents),
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
    """
    cutoff = utcnow() - timedelta(days=days)
    incidents = list(session.exec(
        select(Incident).where(Incident.origin == runtime.current_mode(),
                               Incident.created_at >= cutoff)
    ))
    total = len(incidents)
    ack_times = [m for m in (_minutes_between(i.created_at, i.acknowledged_at) for i in incidents)
                 if m is not None]
    res_times = [m for m in (_minutes_between(i.created_at, i.resolved_at) for i in incidents)
                 if m is not None]
    closed = [i for i in incidents if i.status in ("resolved", "dismissed")]
    with_reason = [i for i in closed if i.closed_reason]
    false_positives = [i for i in with_reason if i.closed_reason == "false_positive"]
    # Closed with no human acknowledgement = handled without analyst attention.
    autonomous = [i for i in closed if i.acknowledged_at is None]

    by_detection: dict[str, dict[str, int]] = {}
    for i in with_reason:
        row = by_detection.setdefault(i.det_id or "unknown", {"closed": 0, "false_positive": 0})
        row["closed"] += 1
        if i.closed_reason == "false_positive":
            row["false_positive"] += 1

    return {
        "window_days": days,
        "incidents": total,
        "closed": len(closed),
        "mtta_minutes": _avg(ack_times),
        "mttr_minutes": _avg(res_times),
        "acknowledged": len(ack_times),
        "triaged_with_reason": len(with_reason),
        "false_positives": len(false_positives),
        "false_positive_rate": (round(100.0 * len(false_positives) / len(with_reason), 1)
                                if with_reason else None),
        "autonomously_handled": len(autonomous),
        "autonomous_pct": round(100.0 * len(autonomous) / len(closed), 1) if closed else None,
        "by_detection": by_detection,
    }


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
