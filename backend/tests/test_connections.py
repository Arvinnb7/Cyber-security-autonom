"""Tests for org integrations: secret encryption, masking, and live M365 mapping."""
from __future__ import annotations

import types

from app.connectors.real.microsoft365 import Microsoft365Connector
from app.connectors.registry import split_credentials
from app.core.crypto import decrypt_dict, encrypt_dict


def test_secret_roundtrip_and_masking():
    public, secrets = split_credentials("microsoft_365",
                                        {"tenant_id": "t1", "client_id": "c1", "client_secret": "shh"})
    assert public == {"tenant_id": "t1", "client_id": "c1"}
    assert secrets == {"client_secret": "shh"}
    blob = encrypt_dict(secrets)
    assert "shh" not in blob               # encrypted at rest
    assert decrypt_dict(blob) == secrets   # recoverable server-side


class _Resp:
    def __init__(self, status, payload=None, text=""):
        self.status_code = status
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


def test_m365_signin_mapping(monkeypatch):
    import app.connectors.real.microsoft365 as m

    def fake_post(url, **kw):
        return _Resp(200, {"access_token": "tok"})

    def fake_get(url, **kw):
        if "signIns" in url:
            return _Resp(200, {"value": [{
                "createdDateTime": "2026-06-20T03:00:00Z",
                "userPrincipalName": "alice@corp.com",
                "ipAddress": "5.6.7.8",
                "status": {"errorCode": 0},
                "location": {"countryOrRegion": "RU", "city": "Moscow"},
                "deviceDetail": {"deviceId": "d1", "isManaged": False},
                "riskLevelDuringSignIn": "high",
                "appDisplayName": "Office365",
            }]})
        return _Resp(200, {"value": []})  # directoryAudits

    monkeypatch.setattr(m, "httpx", types.SimpleNamespace(post=fake_post, get=fake_get, HTTPError=Exception))

    conn = Microsoft365Connector({"tenant_id": "t", "client_id": "c"}, {"client_secret": "s"})
    events = conn.fetch_events()
    assert len(events) == 1
    e = events[0]
    assert e.source == "microsoft_365"
    assert e.action == "login_success"
    assert e.actor_username == "alice@corp.com"
    assert e.country == "RU"
    assert e.raw["risky_ip"] is True     # high risk -> flagged for DET-001
    assert e.raw["new_device"] is True   # unmanaged device


def test_m365_auth_failure_message(monkeypatch):
    import app.connectors.real.microsoft365 as m

    def fake_post(url, **kw):
        return _Resp(401, text="invalid_client")

    monkeypatch.setattr(m, "httpx", types.SimpleNamespace(post=fake_post, get=lambda *a, **k: _Resp(200),
                                                          HTTPError=Exception))
    conn = Microsoft365Connector({"tenant_id": "t", "client_id": "c"}, {"client_secret": "bad"})
    ok, message = conn.test()
    assert ok is False
    assert "Auth failed" in message
