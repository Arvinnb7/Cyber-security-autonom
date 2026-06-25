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
