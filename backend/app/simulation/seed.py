"""Seed the catalog, the demo organization, and an initial set of incidents."""
from __future__ import annotations

import logging

from sqlmodel import Session, select

from app.detection.catalog import seed_catalog
from app.ingestion.pipeline import analyze, ingest_raw_events
from app.models.tables import Asset, Incident, User
from app.simulation.org import DEMO_ASSETS, DEMO_USERS
from app.simulation.scenarios import SCENARIOS, generate_scenario

logger = logging.getLogger("sentinel.seed")


def seed_org(session: Session) -> None:
    if session.exec(select(User).where(User.origin == "demo")).first() is None:
        for u in DEMO_USERS:
            session.add(User(origin="demo", **u))
    if session.exec(select(Asset).where(Asset.origin == "demo")).first() is None:
        for a in DEMO_ASSETS:
            session.add(Asset(origin="demo", **a))
    session.commit()


def seed_scenarios(session: Session) -> int:
    """Generate one incident for each of the 10 catalog detections."""
    for name in SCENARIOS:
        ingest_raw_events(session, generate_scenario(name))
    count = analyze(session)
    logger.info("seeded %d initial incidents", count)
    return count


def seed_all(session: Session, demo: bool = True) -> None:
    # The detection catalog is product config (source of truth), not demo data —
    # it is always seeded so detections/scoring work in live mode too.
    added = seed_catalog(session)
    if added:
        logger.info("seeded %d catalog detections", added)
    # Demo organization + attack scenarios are mock data — demo mode only.
    if demo:
        seed_org(session)
        if session.exec(select(Incident).where(Incident.origin == "demo")).first() is None:
            seed_scenarios(session)
