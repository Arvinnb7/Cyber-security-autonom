"""Tests for real (live) response-action execution and its safety guardrail."""
from __future__ import annotations

import types

from app.connectors.base import ActionResult
from app.connectors.real.microsoft365 import Microsoft365Connector
from app.models.tables import Connection
from app.response import actions as resp


class _Resp:
    def __init__(self, status, text=""):
        self.status_code = status
        self.text = text

    def json(self):
        return {"access_token": "tok"}


def test_m365_block_user_calls_graph_patch(monkeypatch):
    import app.connectors.real.microsoft365 as m

    calls = {}

    def fake_post(url, **kw):  # token endpoint
        return _Resp(200)

    def fake_request(method, url, **kw):
        calls["method"] = method
        calls["url"] = url
        calls["json"] = kw.get("json")
        return _Resp(204)

    monkeypatch.setattr(m, "httpx", types.SimpleNamespace(post=fake_post, request=fake_request, HTTPError=Exception))
    conn = Microsoft365Connector({"tenant_id": "t", "client_id": "c"}, {"client_secret": "s"})
    result = conn.execute_action("block_user", "alice@corp.com")
    assert result.success
    assert calls["method"] == "PATCH"
    assert calls["url"].endswith("users/alice@corp.com")
    assert calls["json"] == {"accountEnabled": False}


def test_live_action_blocked_without_allow(session, monkeypatch):
    monkeypatch.setattr("app.core.runtime.is_live", lambda: True)
    session.add(Connection(provider="microsoft_365", display_name="M365", enabled=True, allow_actions=False))
    session.commit()
    action = resp.request_action(session, "block_user", "bob@corp.com")
    resp.approve_action(session, action.id, approved_by="admin")
    session.refresh(action)
    assert action.status == "blocked"
    assert "enable automated response" in action.result.lower()


def test_live_action_executes_with_allow(session, monkeypatch):
    monkeypatch.setattr("app.core.runtime.is_live", lambda: True)
    session.add(Connection(provider="microsoft_365", display_name="M365", enabled=True, allow_actions=True))
    session.commit()

    class _Fake:
        def execute_action(self, a, t):
            return ActionResult(success=True, detail=f"disabled {t}")

    monkeypatch.setattr(resp, "build_connector", lambda conn: _Fake())
    action = resp.request_action(session, "block_user", "bob@corp.com")
    resp.approve_action(session, action.id, approved_by="admin")
    session.refresh(action)
    assert action.status == "executed"
    assert action.result == "disabled bob@corp.com"


def test_live_action_no_integration(session, monkeypatch):
    monkeypatch.setattr("app.core.runtime.is_live", lambda: True)
    action = resp.request_action(session, "block_user", "bob@corp.com")
    resp.approve_action(session, action.id, approved_by="admin")
    session.refresh(action)
    assert action.status == "failed"
    assert "no enabled integration" in action.result.lower()
