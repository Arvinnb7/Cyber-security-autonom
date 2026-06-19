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
    if session.exec(select(User)).first() is None:
        for u in DEMO_USERS:
            session.add(User(**u))
    if session.exec(select(Asset)).first() is None:
        for a in DEMO_ASSETS:
            session.add(Asset(**a))
    session.commit()


def seed_scenarios(session: Session) -> int:
    """Generate one incident for each of the 10 catalog detections."""
    for name in SCENARIOS:
        ingest_raw_events(session, generate_scenario(name))
    count = analyze(session)
    logger.info("seeded %d initial incidents", count)
    return count


def seed_all(session: Session) -> None:
    added = seed_catalog(session)
    if added:
        logger.info("seeded %d catalog detections", added)
    seed_org(session)
    if session.exec(select(Incident)).first() is None:
        seed_scenarios(session)
