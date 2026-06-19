"""Correlation (F3): fresh signals -> scored, AI-enriched incidents."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from sqlmodel import Session, select

from app.ai.analysis import enrich_incident
from app.core.time import utcnow
from app.models.tables import Event, Incident, Signal
from app.scoring.engine import recompute_asset_risk, recompute_user_risk, score_incident

CORRELATE_WINDOW_MINUTES = 180

THREAT_TITLES = {
    "account_takeover": "Account Takeover",
    "ransomware": "Ransomware Activity",
    "data_exfiltration": "Data Exfiltration",
    "anomalous_activity": "Anomalous Privileged Activity",
    "suspicious_login": "Suspicious Login",
}


def _build_timeline(session: Session, signals: list[Signal]) -> list[dict]:
    event_ids: set[int] = set()
    for s in signals:
        event_ids.update(s.event_ids or [])
    if not event_ids:
        return []
    events = list(session.exec(select(Event).where(Event.id.in_(event_ids)).order_by(Event.timestamp)))
    # Collapse very long chains so the UI stays readable.
    if len(events) > 12:
        events = events[:6] + events[-6:]
    timeline = []
    for e in events:
        loc = f"{e.city}, {e.country}" if e.country else ""
        timeline.append({
            "time": e.timestamp.isoformat(),
            "source": e.source,
            "action": e.action,
            "actor": e.actor_username,
            "location": loc,
            "asset": e.target_asset,
            "detail": e.raw,
        })
    return timeline


def _find_open_incident(session: Session, threat_type: str, username: str | None) -> Incident | None:
    cutoff = utcnow() - timedelta(minutes=CORRELATE_WINDOW_MINUTES)
    return session.exec(
        select(Incident).where(
            Incident.threat_type == threat_type,
            Incident.actor_username == username,
            Incident.status.in_(["open", "investigating"]),
            Incident.created_at >= cutoff,
        ).order_by(Incident.created_at.desc())
    ).first()


def correlate_and_score(session: Session, fresh_signals: list[Signal]) -> list[Incident]:
    """Turn newly-fired signals into incidents, score and AI-enrich them."""
    groups: dict[tuple[str, str | None], list[Signal]] = defaultdict(list)
    for s in fresh_signals:
        groups[(s.threat_type, s.actor_username)].append(s)

    touched: list[Incident] = []
    for (threat_type, username), sigs in groups.items():
        asset_name = next((s.target_asset for s in sigs if s.target_asset), None)
        incident = _find_open_incident(session, threat_type, username)
        created = incident is None
        if incident is None:
            incident = Incident(threat_type=threat_type, actor_username=username,
                                target_asset=asset_name, status="open")
            session.add(incident)
            session.commit()
            session.refresh(incident)

        # Attach signals to the incident.
        for s in sigs:
            s.incident_id = incident.id
            session.add(s)
        session.commit()

        all_sigs = list(session.exec(select(Signal).where(Signal.incident_id == incident.id)))
        breakdown = score_incident(session, all_sigs, threat_type, username, asset_name)

        incident.title = THREAT_TITLES.get(threat_type, threat_type.title())
        if username:
            incident.title += f" — {username}"
        incident.target_asset = asset_name or incident.target_asset
        incident.confidence = breakdown.confidence
        incident.threat_score = breakdown.threat_score
        incident.user_risk = breakdown.user_risk
        incident.asset_risk = breakdown.asset_risk
        incident.business_impact = breakdown.business_impact
        incident.final_score = breakdown.final_score
        incident.timeline = _build_timeline(session, all_sigs)
        incident.updated_at = utcnow()
        session.add(incident)
        session.commit()
        session.refresh(incident)

        # AI narrative + executive summary (F5/F6) — only (re)generate for new
        # incidents or when none exists yet, to limit token spend.
        if created or not incident.ai_analysis:
            enrich_incident(session, incident, all_sigs)

        recompute_user_risk(session, username)
        recompute_asset_risk(session, asset_name)
        touched.append(incident)

    return touched
