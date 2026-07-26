"""Phase 5: real-data scoring fidelity + case management & the SLA evidence.

These cover the parts that decide whether the platform can genuinely stand in for
tier-1 analysts: does it score real identities/assets correctly, and can it prove
what it handled?
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlmodel import select

from app.api import api_router
from app.connectors.base import RawEvent
from app.core.db import get_session
from app.core.security import hash_password
from app.core.time import utcnow
from app.detection.baseline import Baselines
from app.detection.detectors import run_detectors
from app.ingestion.pipeline import _guess_sensitivity, ingest_raw_events
from app.models.tables import Account, Asset, Incident, Organization, User
from app.services import analytics


def _login(user: str, country: str, ts, device: str = "laptop-1") -> RawEvent:
    return RawEvent(source="microsoft_365", timestamp=ts, category="authentication",
                    action="login_success", actor_username=user, country=country, city=country,
                    src_ip="203.0.113.10", raw={"device_id": device})


# --- privilege now comes from the database, not the demo fixture ----------

def test_privilege_read_from_database_not_demo_fixture(session):
    """A real customer admin (not one of the 8 demo usernames) must count as
    privileged — previously is_privileged() only knew the simulator's users."""
    session.add(User(username="ceo@realcorp.com", display_name="CEO", origin="demo",
                     is_privileged=True))
    session.add(User(username="intern@realcorp.com", display_name="Intern", origin="demo"))
    session.commit()
    bl = Baselines(session, "demo")
    assert bl.is_privileged("ceo@realcorp.com")
    assert not bl.is_privileged("intern@realcorp.com")
    assert not bl.is_privileged(None)


def test_privileged_factor_fires_for_real_admin(session):
    """DET-001 should award the privileged_user factor to a real tenant admin."""
    from app.detection.catalog import seed_catalog

    seed_catalog(session)
    user = "admin@realcorp.com"
    session.add(User(username=user, display_name="Admin", origin="demo", is_privileged=True))
    session.commit()
    now = utcnow()
    # Baseline of French logins, then an impossible hop to Japan.
    ingest_raw_events(session, [_login(user, "FR", now - timedelta(days=d)) for d in range(1, 11)])
    base = now - timedelta(minutes=20)
    ingest_raw_events(session, [_login(user, "FR", base),
                                _login(user, "JP", base + timedelta(minutes=10))])
    signals = run_detectors(session)
    det1 = [s for s in signals if s.det_id == "DET-001"]
    assert det1, f"DET-001 did not fire; got {[s.det_id for s in signals]}"
    factors = det1[0].matched_factors
    assert "impossible_travel" in factors, "FR->JP impossible travel missed (geo gap)"
    assert "privileged_user" in factors, "real admin not scored as privileged"


# --- asset sensitivity is no longer a flat 3 -----------------------------

def test_sensitivity_heuristic_differentiates_assets():
    assert _guess_sensitivity("finance-fileserver") == 5
    assert _guess_sensitivity("legal-contracts") == 5
    assert _guess_sensitivity("hr-portal") == 4
    assert _guess_sensitivity("dev-sandbox") == 2
    assert _guess_sensitivity("some-random-thing") == 3      # sane default


def test_live_provisioning_sets_privilege_and_sensitivity(session, monkeypatch):
    monkeypatch.setattr("app.core.runtime.current_mode", lambda: "live")
    events = [
        RawEvent(source="microsoft_365", category="authentication", action="login_success",
                 actor_username="admin@corp.com", country="US", target_asset="finance-fileserver",
                 raw={"is_privileged": True}),
        RawEvent(source="microsoft_365", category="authentication", action="login_success",
                 actor_username="bob@corp.com", country="US", target_asset="dev-sandbox"),
    ]
    ingest_raw_events(session, events)
    admin = session.exec(select(User).where(User.username == "admin@corp.com")).first()
    bob = session.exec(select(User).where(User.username == "bob@corp.com")).first()
    finance = session.exec(select(Asset).where(Asset.name == "finance-fileserver")).first()
    sandbox = session.exec(select(Asset).where(Asset.name == "dev-sandbox")).first()
    assert admin.is_privileged is True and bob.is_privileged is False
    assert finance.sensitivity == 5 and sandbox.sensitivity == 2
    assert finance.sensitivity != sandbox.sensitivity     # no longer a flat 3


# --- SLA / ROI metrics ----------------------------------------------------

def _incident(session, **kw) -> Incident:
    defaults = dict(title="case", det_id="DET-001", severity="high", status="open",
                    origin="demo", final_score=70.0, created_at=utcnow() - timedelta(hours=2))
    defaults.update(kw)
    inc = Incident(**defaults)
    session.add(inc)
    session.commit()
    session.refresh(inc)
    return inc


def test_sla_metrics_compute_mtta_mttr_and_fp_rate(session):
    now = utcnow()
    created = now - timedelta(hours=2)
    # Acknowledged after 30 min, resolved after 60 min.
    _incident(session, created_at=created, status="resolved", closed_reason="true_positive",
              acknowledged_at=created + timedelta(minutes=30),
              resolved_at=created + timedelta(minutes=60))
    # A false positive.
    _incident(session, created_at=created, status="dismissed", closed_reason="false_positive",
              acknowledged_at=created + timedelta(minutes=10),
              resolved_at=created + timedelta(minutes=20))
    # Closed with no human ever looking = handled autonomously.
    _incident(session, created_at=created, status="resolved", closed_reason="true_positive",
              resolved_at=created + timedelta(minutes=5))

    m = analytics.sla_metrics(session, days=7)
    assert m["incidents"] == 3 and m["closed"] == 3
    assert m["mtta_minutes"] == 20.0                 # (30 + 10) / 2
    assert m["mttr_minutes"] == 28.3                 # (60 + 20 + 5) / 3
    assert m["false_positive_rate"] == round(100 / 3, 1)
    assert m["autonomously_handled"] == 1
    assert m["autonomous_pct"] == round(100 / 3, 1)
    assert m["by_detection"]["DET-001"] == {"closed": 3, "false_positive": 1}


def test_sla_metrics_empty_is_safe(session):
    m = analytics.sla_metrics(session, days=7)
    assert m["incidents"] == 0
    assert m["mtta_minutes"] is None and m["false_positive_rate"] is None


def test_weekly_report_includes_effort_saved(session):
    from app.reporting.weekly import generate_weekly_report

    created = utcnow() - timedelta(hours=3)
    _incident(session, created_at=created, status="resolved", closed_reason="true_positive",
              resolved_at=created + timedelta(minutes=6))
    report = generate_weekly_report(session)
    assert "Operations & effort saved" in report.content_md
    assert "Estimated analyst time avoided" in report.content_md
    assert report.stats["sla"]["autonomously_handled"] == 1


# --- casework API ---------------------------------------------------------

@pytest.fixture
def client(session):
    session.add(Organization(id=1, name="Test Org", slug="default"))
    for uname, role in (("admin", "admin"), ("ana", "analyst"), ("view", "viewer")):
        session.add(Account(org_id=1, username=uname, role=role,
                            hashed_password=hash_password(f"{uname}-pw"), is_active=True))
    session.commit()
    app = FastAPI()
    app.include_router(api_router)
    app.dependency_overrides[get_session] = lambda: session
    return TestClient(app)


def _auth(client, username):
    r = client.post("/api/auth/login", data={"username": username, "password": f"{username}-pw"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_acknowledge_assign_and_note(session, client):
    inc = _incident(session)
    h = _auth(client, "ana")

    r = client.post(f"/api/incidents/{inc.id}/acknowledge", headers=h)
    assert r.status_code == 200 and r.json()["acknowledged_by"] == "ana"

    r = client.post(f"/api/incidents/{inc.id}/assign", json={"assignee": "admin"}, headers=h)
    assert r.status_code == 200 and r.json()["assigned_to"] == "admin"

    r = client.post(f"/api/incidents/{inc.id}/notes", json={"body": "Checked with the user."}, headers=h)
    assert r.status_code == 200 and r.json()["author"] == "ana"

    detail = client.get(f"/api/incidents/{inc.id}", headers=h).json()
    assert detail["notes"][0]["body"] == "Checked with the user."


def test_assign_rejects_unknown_account(session, client):
    inc = _incident(session)
    r = client.post(f"/api/incidents/{inc.id}/assign", json={"assignee": "ghost"},
                    headers=_auth(client, "ana"))
    assert r.status_code == 400


def test_close_with_reason_feeds_false_positive_rate(session, client):
    inc = _incident(session)
    h = _auth(client, "ana")
    r = client.post(f"/api/incidents/{inc.id}/status",
                    json={"status": "dismissed", "closed_reason": "false_positive"}, headers=h)
    assert r.status_code == 200 and r.json()["closed_reason"] == "false_positive"
    session.refresh(inc)
    assert inc.resolved_at is not None          # MTTR clock stopped
    assert inc.acknowledged_at is not None      # a human touched it
    assert analytics.sla_metrics(session, days=7)["false_positive_rate"] == 100.0


def test_invalid_closed_reason_rejected(session, client):
    inc = _incident(session)
    r = client.post(f"/api/incidents/{inc.id}/status",
                    json={"status": "resolved", "closed_reason": "nonsense"},
                    headers=_auth(client, "ana"))
    assert r.status_code == 400


def test_viewer_cannot_do_casework(session, client):
    inc = _incident(session)
    h = _auth(client, "view")
    assert client.post(f"/api/incidents/{inc.id}/acknowledge", headers=h).status_code == 403
    assert client.post(f"/api/incidents/{inc.id}/notes", json={"body": "x"}, headers=h).status_code == 403


def test_admin_can_override_asset_sensitivity(session, client):
    asset = Asset(name="sharepoint-hr", asset_type="saas", sensitivity=3, origin="demo")
    session.add(asset)
    session.commit()
    session.refresh(asset)
    r = client.put(f"/api/assets/{asset.id}", json={"sensitivity": 5},
                   headers=_auth(client, "admin"))
    assert r.status_code == 200 and r.json()["sensitivity"] == 5
    # Out-of-range is rejected.
    assert client.put(f"/api/assets/{asset.id}", json={"sensitivity": 9},
                      headers=_auth(client, "admin")).status_code == 400
    # Analysts may not reclassify the business.
    assert client.put(f"/api/assets/{asset.id}", json={"sensitivity": 1},
                      headers=_auth(client, "ana")).status_code == 403


def test_admin_can_mark_user_privileged(session, client):
    user = User(username="new.admin@corp.com", display_name="New Admin", origin="demo")
    session.add(user)
    session.commit()
    session.refresh(user)
    r = client.put(f"/api/users/{user.id}", json={"is_privileged": True},
                   headers=_auth(client, "admin"))
    assert r.status_code == 200 and r.json()["is_privileged"] is True
    assert Baselines(session, "demo").is_privileged("new.admin@corp.com")


def test_sla_endpoint_returns_metrics(session, client):
    _incident(session, status="resolved", closed_reason="true_positive",
              resolved_at=utcnow() - timedelta(hours=1))
    r = client.get("/api/metrics/sla?days=7", headers=_auth(client, "view"))
    assert r.status_code == 200
    assert r.json()["closed"] == 1


def test_system_health_endpoint(session, client):
    r = client.get("/api/system/health", headers=_auth(client, "view"))
    assert r.status_code == 200
    assert r.json()["state"] in ("healthy", "degraded")
