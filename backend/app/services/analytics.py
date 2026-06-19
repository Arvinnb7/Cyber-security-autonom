"""Shared analytics used by the dashboard (F9), chat (F7) and reports (F10)."""
from __future__ import annotations

from datetime import timedelta

from sqlmodel import Session, func, select

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
        select(Incident).where(Incident.status.in_(["open", "investigating"]))
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
    q = select(Incident)
    if status:
        q = q.where(Incident.status == status)
    if since_hours:
        cutoff = utcnow() - timedelta(hours=since_hours)
        q = q.where(Incident.created_at >= cutoff)
    q = q.order_by(Incident.final_score.desc(), Incident.created_at.desc()).limit(limit)
    return list(session.exec(q))


def riskiest_users(session: Session, limit: int = 10) -> list[User]:
    return list(session.exec(
        select(User).order_by(User.risk_score.desc()).limit(limit)
    ))


def riskiest_assets(session: Session, limit: int = 10) -> list[Asset]:
    return list(session.exec(
        select(Asset).order_by(Asset.risk_score.desc()).limit(limit)
    ))


def active_threats(session: Session) -> list[dict]:
    """Active threats grouped by type (F9)."""
    rows = session.exec(
        select(Incident.threat_type, func.count(Incident.id), func.max(Incident.final_score))
        .where(Incident.status.in_(["open", "investigating"]))
        .group_by(Incident.threat_type)
    ).all()
    return [
        {"threat_type": t, "count": c, "max_score": round(m or 0, 1)}
        for t, c, m in sorted(rows, key=lambda r: r[2] or 0, reverse=True)
    ]


def stats_overview(session: Session) -> dict:
    total = session.exec(select(func.count(Incident.id))).one()
    resolved = session.exec(
        select(func.count(Incident.id)).where(Incident.status == "resolved")
    ).one()
    events = session.exec(select(func.count(Event.id))).one()
    pending_actions = session.exec(
        select(func.count(AuditAction.id)).where(AuditAction.status == "pending")
    ).one()
    return {
        "total_incidents": total,
        "resolved_incidents": resolved,
        "total_events": events,
        "pending_actions": pending_actions,
    }
