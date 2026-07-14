"""Correlation (F3): fresh signals -> scored, AI-enriched, catalog-aligned incidents."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from sqlmodel import Session, select

from app.ai.analysis import enrich_incident
from app.core import runtime
from app.core.time import utcnow
from app.detection.catalog import get_definition, severity_for_score
from app.models.tables import Event, Incident, Signal
from app.notifications.service import notify_incident
from app.scoring.engine import recompute_asset_risk, recompute_user_risk, score_incident

CORRELATE_WINDOW_MINUTES = 180


def _build_timeline(session: Session, signals: list[Signal]) -> tuple[list[dict], list[Event]]:
    event_ids: set[int] = set()
    for s in signals:
        event_ids.update(s.event_ids or [])
    if not event_ids:
        return [], []
    events = list(session.exec(select(Event).where(Event.id.in_(event_ids)).order_by(Event.timestamp)))
    shown = events[:6] + events[-6:] if len(events) > 12 else events
    timeline = [{
        "time": e.timestamp.isoformat(),
        "source": e.source,
        "action": e.action,
        "actor": e.actor_username,
        "location": f"{e.city}, {e.country}" if e.country else "",
        "asset": e.target_asset,
        "detail": e.raw,
    } for e in shown]
    return timeline, events


def _collect_evidence(definition: dict | None, signals: list[Signal], events: list[Event]) -> list[dict]:
    """Map the catalog's required_evidence fields to observed values (F-investigation)."""
    if not definition:
        return []
    first = events[0] if events else None
    last = events[-1] if events else None
    actor = next((e.actor_username for e in events if e.actor_username), None)
    asset = next((e.target_asset for e in events if e.target_asset), None)
    country = next((e.country for e in events if e.country), None)
    src_ip = next((e.src_ip for e in events if e.src_ip), None)
    lookup = {
        "user_id": actor, "admin_user_id": actor, "change_actor": actor,
        "hostname": asset, "source_host": asset, "source_device": asset, "resource_id": asset,
        "target_user_or_resource": asset, "target_hosts": asset, "target_role_or_group": asset,
        "source_ip": src_ip, "device_id": (first.raw.get("device_id") if first else None),
        "country": country, "destination_domain": next(
            (e.raw.get("destination") for e in events if e.raw.get("destination")), None),
        "timestamp": first.timestamp.isoformat() if first else None,
        "delivery_timestamp": first.timestamp.isoformat() if first else None,
        "affected_file_count": sum(1 for e in events if e.action == "file_rename") or None,
        "data_volume": next((e.raw.get("bytes") for e in events if e.raw.get("bytes")), None),
        "process_name": next((e.raw.get("process") for e in events if e.raw.get("process")), None),
        "file_hash": next((e.raw.get("hash") for e in events if e.raw.get("hash")), None),
        "action_type": last.action if last else None,
        "change_type": next((e.raw.get("change") for e in events if e.raw.get("change")), None),
        "sender": next((e.raw.get("sender_domain") for e in events if e.raw.get("sender_domain")), None),
    }
    evidence = []
    for field in definition.get("required_evidence", []):
        val = lookup.get(field)
        evidence.append({"field": field, "value": str(val) if val is not None else "n/a",
                         "observed": val is not None})
    return evidence


def _find_open_incident(session: Session, det_id: str, username: str | None) -> Incident | None:
    cutoff = utcnow() - timedelta(minutes=CORRELATE_WINDOW_MINUTES)
    return session.exec(
        select(Incident).where(
            Incident.det_id == det_id,
            Incident.actor_username == username,
            Incident.origin == runtime.current_mode(),
            Incident.status.in_(["open", "investigating"]),
            Incident.created_at >= cutoff,
        ).order_by(Incident.created_at.desc())
    ).first()


def correlate_and_score(session: Session, fresh_signals: list[Signal]) -> list[Incident]:
    groups: dict[tuple[str, str | None], list[Signal]] = defaultdict(list)
    for s in fresh_signals:
        groups[(s.det_id, s.actor_username)].append(s)

    touched: list[Incident] = []
    for (det_id, username), sigs in groups.items():
        definition = get_definition(det_id)
        asset_name = next((s.target_asset for s in sigs if s.target_asset), None)
        incident = _find_open_incident(session, det_id, username)
        created = incident is None
        if incident is None:
            incident = Incident(det_id=det_id, threat_type=sigs[0].threat_type,
                                actor_username=username, target_asset=asset_name, status="open",
                                origin=runtime.current_mode())
            session.add(incident)
            session.commit()
            session.refresh(incident)

        for s in sigs:
            s.incident_id = incident.id
            session.add(s)
        session.commit()

        all_sigs = list(session.exec(select(Signal).where(Signal.incident_id == incident.id)))
        breakdown = score_incident(session, all_sigs, det_id, username, asset_name)
        timeline, events = _build_timeline(session, all_sigs)

        name = definition["name_en"] if definition else det_id
        incident.title = f"{name}" + (f" — {username}" if username else "")
        incident.target_asset = asset_name or incident.target_asset
        incident.confidence = breakdown.confidence
        incident.threat_score = breakdown.threat_score
        incident.user_risk = breakdown.user_risk
        incident.asset_risk = breakdown.asset_risk
        incident.business_impact = breakdown.business_impact
        incident.final_score = breakdown.final_score
        incident.severity = severity_for_score(breakdown.final_score)
        incident.human_approval_required = definition["human_approval_required"] if definition else "high"
        incident.matched_factors = breakdown.matched_factors
        incident.evidence = _collect_evidence(definition, all_sigs, events)
        incident.timeline = timeline
        incident.updated_at = utcnow()
        session.add(incident)
        session.commit()
        session.refresh(incident)

        if created or not incident.ai_analysis:
            enrich_incident(session, incident, all_sigs)

        recompute_user_risk(session, username)
        recompute_asset_risk(session, asset_name)

        # Operational alerting: notify the org's channels (severity-gated, deduped,
        # resilient — never breaks the pipeline).
        notify_incident(session, incident, created=created)
        touched.append(incident)

    return touched
