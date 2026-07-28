"""Phase 7: the platform must refuse abusive input instead of dying on it.

Every case here was a real crash or leak vector before this phase: an unbounded
``limit`` that would materialize a whole table, in-memory dictionaries keyed by
attacker-controlled values, and expensive AI endpoints with no quota.
"""
from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import api_router, routes
from app.core.db import get_session
from app.core.limits import BoundedTTLCache, SlidingWindowLimiter
from app.core.security import hash_password
from app.models.tables import Account, Incident, Organization
from app.services import analytics


@pytest.fixture
def client(session):
    session.add(Organization(id=1, name="Test Org", slug="default"))
    for uname, role in (("admin", "admin"), ("ana", "analyst")):
        session.add(Account(org_id=1, username=uname, role=role,
                            hashed_password=hash_password(f"{uname}-pw"), is_active=True))
    session.commit()
    app = FastAPI()
    app.include_router(api_router)
    app.dependency_overrides[get_session] = lambda: session
    return TestClient(app)


def _auth(client, username="admin"):
    r = client.post("/api/auth/login", data={"username": username, "password": f"{username}-pw"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# --- bounded pagination ---------------------------------------------------

@pytest.mark.parametrize("path", ["/api/incidents", "/api/audit", "/api/notifications"])
def test_absurd_limit_is_rejected_not_served(session, client, path):
    """Previously returned 200 and tried to materialize the whole table."""
    h = _auth(client)
    r = client.get(f"{path}?limit=999999999", headers=h)
    assert r.status_code == 422, f"{path} accepted an unbounded limit ({r.status_code})"


@pytest.mark.parametrize("path", ["/api/incidents", "/api/audit", "/api/notifications"])
def test_sane_limit_still_works(session, client, path):
    h = _auth(client)
    assert client.get(f"{path}?limit=10", headers=h).status_code == 200
    assert client.get(path, headers=h).status_code == 200        # default unchanged


def test_zero_and_negative_limits_rejected(session, client):
    h = _auth(client)
    assert client.get("/api/incidents?limit=0", headers=h).status_code == 422
    assert client.get("/api/incidents?limit=-5", headers=h).status_code == 422


def test_absurd_sla_window_rejected(session, client):
    """`?days=999999999` used to raise OverflowError -> HTTP 500."""
    h = _auth(client)
    assert client.get("/api/metrics/sla?days=999999999", headers=h).status_code == 422
    assert client.get("/api/metrics/sla?days=30", headers=h).status_code == 200


def test_sla_helper_clamps_defensively(session):
    """Called directly by the report generator, so it must not trust its input."""
    session.add(Incident(title="x", det_id="DET-001", origin="demo"))
    session.commit()
    assert analytics.sla_metrics(session, days=10**9)["window_days"] <= 365
    analytics.invalidate_sla_cache()
    assert analytics.sla_metrics(session, days=-5)["window_days"] >= 1


# --- payload caps ---------------------------------------------------------

def test_oversized_chat_payload_rejected(session, client):
    h = _auth(client)
    assert client.post("/api/chat", json={"question": "x" * 50_000}, headers=h).status_code == 422
    # A long conversation history is also capped (it is forwarded to Claude).
    long_history = [{"role": "user", "content": "hi"} for _ in range(500)]
    r = client.post("/api/chat", json={"question": "hi", "history": long_history}, headers=h)
    assert r.status_code == 422


def test_oversized_note_rejected(session, client):
    inc = Incident(title="case", det_id="DET-001", origin="demo")
    session.add(inc)
    session.commit()
    session.refresh(inc)
    h = _auth(client, "ana")
    assert client.post(f"/api/incidents/{inc.id}/notes",
                       json={"body": "x" * 50_000}, headers=h).status_code == 422
    assert client.post(f"/api/incidents/{inc.id}/notes",
                       json={"body": ""}, headers=h).status_code == 422


# --- bounded cache --------------------------------------------------------

def test_cache_never_exceeds_its_cap():
    """An attacker varying the cache key must not grow memory without limit."""
    cache = BoundedTTLCache(maxsize=50, ttl_seconds=60)
    for i in range(5000):
        cache.set(("demo", i), {"value": i})
    assert len(cache) == 50


def test_cache_evicts_least_recently_used():
    cache = BoundedTTLCache(maxsize=2, ttl_seconds=60)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.get("a")               # 'a' is now the most recent
    cache.set("c", 3)            # evicts 'b'
    assert cache.get("a") == 1
    assert cache.get("b") is None
    assert cache.get("c") == 3


def test_cache_entries_expire():
    cache = BoundedTTLCache(maxsize=10, ttl_seconds=0.05)
    cache.set("k", "v")
    assert cache.get("k") == "v"
    time.sleep(0.06)
    assert cache.get("k") is None


def test_sla_cache_is_bounded_against_varied_windows(session, client):
    """`?days=1,2,3,…` previously created an unbounded cache entry each time."""
    h = _auth(client)
    for days in range(1, 200):
        client.get(f"/api/metrics/sla?days={days}", headers=h)
    assert len(analytics._sla_cache) <= 128


# --- bounded rate limiter -------------------------------------------------

def test_limiter_key_table_is_bounded():
    """Login spam with rotating usernames must not grow memory."""
    limiter = SlidingWindowLimiter(limit=5, window_seconds=60, max_keys=100)
    for i in range(10_000):
        limiter.check(f"user-{i}")
    assert len(limiter) == 100


def test_limiter_blocks_past_quota_and_reports_retry_after():
    limiter = SlidingWindowLimiter(limit=3, window_seconds=60)
    for _ in range(3):
        allowed, _ = limiter.check("k")
        assert allowed
    allowed, retry_after = limiter.check("k")
    assert not allowed and retry_after >= 1


def test_limiter_window_expires():
    limiter = SlidingWindowLimiter(limit=1, window_seconds=0.05)
    assert limiter.check("k")[0]
    assert not limiter.check("k")[0]
    time.sleep(0.06)
    assert limiter.check("k")[0], "quota should recover after the window"


def test_peek_does_not_consume_quota():
    limiter = SlidingWindowLimiter(limit=2, window_seconds=60)
    for _ in range(10):
        assert limiter.is_blocked("k") == (False, 0)
    limiter.record("k")
    limiter.record("k")
    blocked, retry_after = limiter.is_blocked("k")
    assert blocked and retry_after >= 1


# --- login throttle semantics --------------------------------------------

def test_successful_logins_are_not_throttled(session, client):
    """A busy office behind one NAT must not lock itself out by logging in."""
    for _ in range(20):
        r = client.post("/api/auth/login", data={"username": "admin", "password": "admin-pw"})
        assert r.status_code == 200


def test_repeated_failures_are_throttled(session, client):
    codes = [client.post("/api/auth/login",
                         data={"username": "admin", "password": "wrong"}).status_code
             for _ in range(15)]
    assert 401 in codes
    assert 429 in codes, "brute force was never throttled"


def test_throttle_survives_username_rotation(session, client):
    """Rotating the username must not sidestep the limit — it is keyed by IP too."""
    for i in range(30):
        client.post("/api/auth/login", data={"username": f"ghost{i}", "password": "x"})
    r = client.post("/api/auth/login", data={"username": "someone-else", "password": "x"})
    assert r.status_code == 429
    assert len(routes._login_limiter) < 10_000       # and stayed bounded
