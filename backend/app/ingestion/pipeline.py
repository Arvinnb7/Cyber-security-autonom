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
from app.detection.baseline import update_baselines
from app.detection.correlation import correlate_and_score
from app.detection.detectors import run_detectors
from app.ingestion.dedup import existing_fingerprints
from app.ingestion.normalizer import normalize
from app.models.tables import Asset, Event, User
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
    score in live mode (demo seeds its own). Idempotent.

    Looks up all identities in two batched queries rather than one per row — a
    busy cycle would otherwise issue a query per distinct user and asset.
    """
    usernames = sorted({r.actor_username for r in raw_events if r.actor_username})
    assets = sorted({r.target_asset for r in raw_events if r.target_asset})
    # Identities the source told us hold admin/directory roles.
    privileged = {r.actor_username for r in raw_events
                  if r.actor_username and r.raw.get("is_privileged")}

    existing_users = {u.username: u for u in _in_chunks(session, User, User.username, usernames)}
    for uname in usernames:
        user = existing_users.get(uname)
        if user is None:
            session.add(User(username=uname, display_name=uname, email=uname, origin=mode,
                             is_privileged=uname in privileged))
        elif uname in privileged and not user.is_privileged:
            # Promote once discovered; never auto-demote (an admin may override).
            user.is_privileged = True
            session.add(user)

    existing_assets = {a.name for a in _in_chunks(session, Asset, Asset.name, assets)}
    for aname in assets:
        if aname not in existing_assets:
            session.add(Asset(name=aname, asset_type=_guess_asset_type(aname),
                              sensitivity=_guess_sensitivity(aname), origin=mode))
    session.commit()


def _in_chunks(session: Session, model, column, values: list[str], chunk: int = 500):
    """Fetch rows whose ``column`` is in ``values`` using chunked IN queries."""
    out = []
    for i in range(0, len(values), chunk):
        out.extend(session.exec(select(model).where(column.in_(values[i:i + chunk]))).all())
    return out


def ingest_raw_events(session: Session, raw_events: list[RawEvent]) -> int:
    """Normalize, de-duplicate and persist a batch of raw events (stamped with mode).

    De-duplication is done for the whole batch in a few queries (both against
    what is already stored and within the batch itself) instead of one query per
    event, so cost scales with batch count rather than event count.
    """
    mode = runtime.current_mode()
    events = []
    for raw in raw_events:
        event = normalize(raw)
        event.origin = mode
        events.append(event)

    known = existing_fingerprints(session, [e.fingerprint for e in events])
    fresh: list[Event] = []
    seen: set[str] = set()
    for event in events:
        if event.fingerprint in known or event.fingerprint in seen:
            continue
        seen.add(event.fingerprint)
        fresh.append(event)
    if fresh:
        # One multi-row INSERT rather than a statement per event: on a networked
        # database the round trips, not the rows, are the cost. Downstream code
        # re-reads events from the database, so not populating IDs here is fine.
        session.bulk_save_objects(fresh)
        session.commit()

    if fresh:
        # Teach the behavioural baseline incrementally — no full history rescan.
        update_baselines(session, fresh, mode)
    # In live mode, learn the org's users/assets from their real activity.
    if mode == "live" and raw_events:
        _provision_identities(session, raw_events, mode)
    return len(fresh)


def _collect_raw(session: Session, inject_scenario_prob: float = 0.25) -> list[RawEvent]:
    """Poll the connectors for the *current* data mode.

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
    return raw


def ingest_cycle(session: Session, inject_scenario_prob: float = 0.25) -> int:
    """One poll of connectors, persisted. Returns the number of new events."""
    return ingest_raw_events(session, _collect_raw(session, inject_scenario_prob))


def analyze(session: Session, active_users: set[str] | None = None,
            active_assets: set[str] | None = None) -> int:
    """Run detectors over recent events and build/score/enrich incidents."""
    fresh = run_detectors(session, active_users, active_assets)
    if not fresh:
        return 0
    incidents = correlate_and_score(session, fresh)
    return len(incidents)


def run_full_cycle(session: Session, inject_scenario_prob: float = 0.25) -> dict:
    raw = _collect_raw(session, inject_scenario_prob)
    events = ingest_raw_events(session, raw)
    # Only re-examine the subjects this cycle actually touched.
    active_users = {r.actor_username for r in raw if r.actor_username}
    active_assets = {r.target_asset for r in raw if r.target_asset}
    incidents = analyze(session, active_users, active_assets)
    if incidents:
        logger.info("cycle: %d events, %d incidents touched", events, incidents)
    return {"events_ingested": events, "incidents_touched": incidents}
