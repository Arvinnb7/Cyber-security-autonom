"""Auth, RBAC and audit-log tests (Phase 1 enterprise hardening)."""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import api_router
from app.core.db import get_session
from app.core.security import hash_password, verify_password
from app.models.tables import Account, AuditLog, Organization


@pytest.fixture
def client(session):
    # Seed an org + one account per role.
    session.add(Organization(id=1, name="Test Org", slug="default"))
    for uname, role in (("admin", "admin"), ("ana", "analyst"), ("view", "viewer")):
        session.add(Account(org_id=1, username=uname, role=role,
                            hashed_password=hash_password(f"{uname}-pw"), is_active=True))
    session.commit()

    app = FastAPI()
    app.include_router(api_router)
    app.dependency_overrides[get_session] = lambda: session
    return TestClient(app)


def _token(client, username, password):
    r = client.post("/api/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_password_hashing_roundtrip():
    h = hash_password("s3cret!")
    assert h != "s3cret!"
    assert verify_password("s3cret!", h)
    assert not verify_password("wrong", h)


def test_login_success_and_wrong_password(client):
    assert client.post("/api/auth/login", data={"username": "admin", "password": "admin-pw"}).status_code == 200
    assert client.post("/api/auth/login", data={"username": "admin", "password": "nope"}).status_code == 401


def test_me_returns_role(client):
    r = client.get("/api/me", headers=_token(client, "view", "view-pw"))
    assert r.status_code == 200
    assert r.json()["role"] == "viewer"


def test_viewer_cannot_switch_mode(client):
    r = client.post("/api/mode", json={"data_mode": "live"}, headers=_token(client, "view", "view-pw"))
    assert r.status_code == 403


def test_analyst_cannot_approve_action(client):
    r = client.post("/api/actions/1/approve", headers=_token(client, "ana", "ana-pw"))
    assert r.status_code == 403


def test_admin_can_switch_mode_and_it_is_audited(client):
    headers = _token(client, "admin", "admin-pw")
    assert client.post("/api/mode", json={"data_mode": "live"}, headers=headers).status_code == 200
    audit = client.get("/api/audit", headers=headers)
    assert audit.status_code == 200
    actions = {row["action"] for row in audit.json()}
    assert "mode.switch" in actions
    assert "auth.login" in actions


def test_non_admin_cannot_read_audit_or_manage_accounts(client):
    headers = _token(client, "ana", "ana-pw")
    assert client.get("/api/audit", headers=headers).status_code == 403
    assert client.get("/api/accounts", headers=headers).status_code == 403


def test_admin_creates_account_with_role(client):
    headers = _token(client, "admin", "admin-pw")
    r = client.post("/api/accounts", json={"username": "newbie", "password": "pw12345", "role": "analyst"},
                    headers=headers)
    assert r.status_code == 200
    assert r.json()["role"] == "analyst"
    # the new account can log in
    assert client.post("/api/auth/login", data={"username": "newbie", "password": "pw12345"}).status_code == 200


def test_unauthenticated_is_rejected(client):
    assert client.get("/api/me").status_code == 401
    assert client.get("/api/dashboard/overview").status_code == 401
