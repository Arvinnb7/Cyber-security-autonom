"""Ingestion + analysis pipeline.

    connectors -> normalize -> dedup -> persist (Event)
              -> detectors -> signals -> correlate+score+AI -> Incident
"""
from __future__ import annotations

import logging
import random

from sqlmodel import Session, select

from app.connectors.base import RawEvent
from app.connectors.real.factory import poll_enabled_connections
from app.connectors.simulators import get_connectors
from app.core import runtime
from app.core.config import settings
from app.detection.correlation import correlate_and_score
from app.detection.detectors import run_detectors
from app.ingestion.dedup import is_duplicate
from app.ingestion.normalizer import normalize
from app.models.tables import Asset, User
from app.simulation.scenarios import random_scenario

logger = logging.getLogger("sentinel.pipeline")


# Asset-name keywords -> business sensitivity (1..5). A first guess only: the
# customer refines it in the UI, because only they know what is actually crown
# jewels. Without this every real asset scored a flat 3 and asset_risk was a
# constant 60 for the whole org, flattening the final score.
_SENSITIVITY_HINTS: list[tuple[tuple[str, ...], int]] = [
    (("finance", "payroll", "invoice", "billing", "accounting", "bank"), 5),
    (("legal", "contract", "compliance", "audit"), 5),
    (("exec", "board", "ceo", "cfo", "director"), 5),
    (("hr", "people", "recruit", "personnel"), 4),
    (("sharepoint", "onedrive", "fileserver", "database", "backup", "vault"), 4),
    (("exchange", "mail", "email", "outlook"), 4),
    (("prod", "production", "vpc", "server", "domain"), 4),
    (("crm", "sales", "salesforce"), 3),
    (("test", "dev", "sandbox", "staging"), 2),
]


def _guess_sensitivity(name: str) -> int:
    lowered = (name or "").lower()
    for keywords, score in _SENSITIVITY_HINTS:
        if any(k in lowered for k in keywords):
            return score
    return 3


def _guess_asset_type(name: str) -> str:
    lowered = (name or "").lower()
    if any(k in lowered for k in ("sharepoint", "onedrive", "exchange", "crm", "salesforce")):
        return "saas"
    if any(k in lowered for k in ("fileserver", "database", "vpc", "server", "backup")):
        return "server"
    if any(k in lowered for k in ("azure-ad", "identity", "directory")):
        return "identity"
    return "saas"


def _provision_identities(session: Session, raw_events: list[RawEvent], mode: str) -> None:
    """Auto-create User/Asset rows from real events so scoring has subjects to
    score in live mode (demo seeds its own). Idempotent."""
    usernames = {r.actor_username for r in raw_events if r.actor_username}
    assets = {r.target_asset for r in raw_events if r.target_asset}
    # Identities the source told us hold admin/directory roles.
    privileged = {r.actor_username for r in raw_events
                  if r.actor_username and r.raw.get("is_privileged")}
    for uname in usernames:
        user = session.exec(select(User).where(User.username == uname)).first()
        if user is None:
            session.add(User(username=uname, display_name=uname, email=uname, origin=mode,
                             is_privileged=uname in privileged))
        elif uname in privileged and not user.is_privileged:
            # Promote once discovered; never auto-demote (an admin may override).
            user.is_privileged = True
            session.add(user)
    for aname in assets:
        if session.exec(select(Asset).where(Asset.name == aname)).first() is None:
            session.add(Asset(name=aname, asset_type=_guess_asset_type(aname),
                              sensitivity=_guess_sensitivity(aname), origin=mode))
    session.commit()


def ingest_raw_events(session: Session, raw_events: list[RawEvent]) -> int:
    """Normalize, de-duplicate and persist a batch of raw events (stamped with mode)."""
    mode = runtime.current_mode()
    inserted = 0
    for raw in raw_events:
        event = normalize(raw)
        event.origin = mode
        if is_duplicate(session, event.fingerprint):
            continue
        session.add(event)
        inserted += 1
    session.commit()
    # In live mode, learn the org's users/assets from their real activity.
    if mode == "live" and raw_events:
        _provision_identities(session, raw_events, mode)
    return inserted


def ingest_cycle(session: Session, inject_scenario_prob: float = 0.25) -> int:
    """One poll of connectors for the *current* data mode.

    In live mode the DB is fed exclusively by real org integrations; in demo mode
    by the simulators. Each mode's data is tagged so switching never mixes them.
    """
    raw: list[RawEvent] = []

    if runtime.is_live():
        raw.extend(poll_enabled_connections(session))
    elif settings.sim_enabled:  # demo
        for connector in get_connectors():
            raw.extend(connector.fetch_events())
        if random.random() < inject_scenario_prob:
            raw.extend(random_scenario())

    return ingest_raw_events(session, raw)


def analyze(session: Session) -> int:
    """Run detectors over recent events and build/score/enrich incidents."""
    fresh = run_detectors(session)
    if not fresh:
        return 0
    incidents = correlate_and_score(session, fresh)
    return len(incidents)


def run_full_cycle(session: Session, inject_scenario_prob: float = 0.25) -> dict:
    events = ingest_cycle(session, inject_scenario_prob)
    incidents = analyze(session)
    if incidents:
        logger.info("cycle: %d events, %d incidents touched", events, incidents)
    return {"events_ingested": events, "incidents_touched": incidents}
