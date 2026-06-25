"""DATA_MODE behaviour: catalog always seeds; demo data only in demo mode."""
from __future__ import annotations

from sqlmodel import select

from app.models.tables import DetectionDefinition, Incident, User
from app.simulation.seed import seed_all


def test_live_mode_seeds_catalog_only(session):
    seed_all(session, demo=False)
    # Catalog (product config / source of truth) is present...
    assert len(list(session.exec(select(DetectionDefinition)))) == 10
    # ...but no demo users or demo incidents exist in live mode.
    assert session.exec(select(User)).first() is None
    assert session.exec(select(Incident)).first() is None


def test_demo_mode_seeds_mock_data(session):
    seed_all(session, demo=True)
    assert len(list(session.exec(select(DetectionDefinition)))) == 10
    assert session.exec(select(User)).first() is not None
    assert session.exec(select(Incident)).first() is not None
