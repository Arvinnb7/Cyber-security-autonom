"""Seed the demo organization and an initial set of incidents."""
from __future__ import annotations

import logging

from sqlmodel import Session, select

from app.ingestion.pipeline import analyze, ingest_raw_events
from app.models.tables import Asset, User
from app.simulation.org import DEMO_ASSETS, DEMO_USERS
from app.simulation.scenarios import SCENARIOS, generate_scenario

logger = logging.getLogger("sentinel.seed")


def seed_org(session: Session) -> None:
    """Insert demo users and assets if not present."""
    if session.exec(select(User)).first() is None:
        for u in DEMO_USERS:
            session.add(User(**u))
    if session.exec(select(Asset)).first() is None:
        for a in DEMO_ASSETS:
            session.add(Asset(**a))
    session.commit()


def seed_scenarios(session: Session) -> int:
    """Generate one incident per built-in scenario type plus a couple extras."""
    names = list(SCENARIOS) + ["account_takeover", "ransomware"]
    for name in names:
        ingest_raw_events(session, generate_scenario(name))
    count = analyze(session)
    logger.info("seeded %d initial incidents", count)
    return count


def seed_all(session: Session) -> None:
    seed_org(session)
    from app.models.tables import Incident

    if session.exec(select(Incident)).first() is None:
        seed_scenarios(session)
