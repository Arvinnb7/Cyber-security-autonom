"""Ingestion + analysis pipeline.

    connectors -> normalize -> dedup -> persist (Event)
              -> detectors -> signals -> correlate+score+AI -> Incident
"""
from __future__ import annotations

import logging
import random

from sqlmodel import Session

from app.connectors.base import RawEvent
from app.connectors.real.factory import poll_enabled_connections
from app.connectors.simulators import get_connectors
from app.core import runtime
from app.core.config import settings
from app.detection.correlation import correlate_and_score
from app.detection.detectors import run_detectors
from app.ingestion.dedup import is_duplicate
from app.ingestion.normalizer import normalize
from app.simulation.scenarios import random_scenario

logger = logging.getLogger("sentinel.pipeline")


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
