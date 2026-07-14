"""Phase 4: operational alerting — senders deliver, alerts are severity-gated and
deduped, and the incident/approval hooks actually close the loop."""
from __future__ import annotations

import types
from datetime import timedelta

from sqlmodel import select

from app.core.time import utcnow
from app.detection.catalog import seed_catalog
from app.detection.correlation import correlate_and_score
from app.detection.detectors import run_detectors
from app.ingestion.pipeline import ingest_raw_events
from app.models.tables import AuditAction, Incident, Notification, NotificationChannel
from app.notifications import service as notif_service
from app.notifications.channels import EmailSender, SlackSender, TeamsSender
from app.simulation.scenarios import generate_scenario
from app.simulation.seed import seed_org


class _FakeSender:
    """Records what it was asked to send instead of hitting the network."""

    def __init__(self):
        self.calls: list[tuple] = []

    def send(self, subject, body, meta):
        self.calls.append((subject, body, meta))
        return True, "ok (fake)"


def _channel(session, **kw) -> NotificationChannel:
    defaults = dict(kind="slack", display_name="test", enabled=True, min_severity="low",
                    notify_on_incident=True, notify_on_approval=True, secrets_enc="")
    defaults.update(kw)
    ch = NotificationChannel(**defaults)
    session.add(ch)
    session.commit()
    session.refresh(ch)
    return ch


def _incident(session, severity="high", **kw) -> Incident:
    defaults = dict(title="Test incident", threat_type="account_takeover", det_id="DET-001",
                    severity=severity, final_score=80.0, confidence=0.9, status="open", origin="demo")
    defaults.update(kw)
    inc = Incident(**defaults)
    session.add(inc)
    session.commit()
    session.refresh(inc)
    return inc


# --- channel senders ------------------------------------------------------

def test_email_sender_formats_and_sends(monkeypatch):
    sent: dict = {}

    class _SMTP:
        def __init__(self, host, port, timeout=None):
            sent["host"], sent["port"] = host, port

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            sent["tls"] = True

        def login(self, u, p):
            sent["login"] = (u, p)

        def send_message(self, msg):
            sent["to"] = msg["To"]
            sent["subject"] = msg["Subject"]

    monkeypatch.setattr("app.notifications.channels.smtplib.SMTP", _SMTP)
    s = EmailSender({"host": "smtp.x", "port": 587, "from_addr": "a@x", "to_addrs": "b@x, c@x"},
                    {"username": "u", "password": "p"})
    ok, detail = s.send("Subj", "Body", {"severity": "high"})
    assert ok, detail
    assert sent["to"] == "b@x, c@x"
    assert sent["tls"] is True
    assert sent["login"] == ("u", "p")


def test_email_sender_requires_recipients():
    ok, detail = EmailSender({"host": "smtp.x"}, {}).send("s", "b", {})
    assert not ok and "recipient" in detail


def test_teams_sender_posts_card(monkeypatch):
    captured: dict = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"], captured["payload"] = url, json
        return types.SimpleNamespace(status_code=200, text="1")

    monkeypatch.setattr("app.notifications.channels.httpx",
                        types.SimpleNamespace(post=fake_post, HTTPError=Exception))
    ok, detail = TeamsSender({}, {"webhook_url": "https://teams/hook"}).send("Subj", "Body", {"severity": "critical"})
    assert ok, detail
    assert captured["url"] == "https://teams/hook"
    assert captured["payload"]["@type"] == "MessageCard"
    assert captured["payload"]["title"] == "Subj"


def test_slack_sender_posts_attachment(monkeypatch):
    captured: dict = {}

    def fake_post(url, json=None, timeout=None):
        captured["payload"] = json
        return types.SimpleNamespace(status_code=200, text="ok")

    monkeypatch.setattr("app.notifications.channels.httpx",
                        types.SimpleNamespace(post=fake_post, HTTPError=Exception))
    ok, _ = SlackSender({}, {"webhook_url": "https://hooks.slack/x"}).send("Subj", "Body", {"severity": "low"})
    assert ok
    assert captured["payload"]["text"] == "Subj"
    assert captured["payload"]["attachments"][0]["color"].startswith("#")


def test_webhook_failure_is_reported(monkeypatch):
    def fake_post(url, json=None, timeout=None):
        return types.SimpleNamespace(status_code=500, text="boom")

    monkeypatch.setattr("app.notifications.channels.httpx",
                        types.SimpleNamespace(post=fake_post, HTTPError=Exception))
    ok, detail = SlackSender({}, {"webhook_url": "https://x"}).send("s", "b", {})
    assert not ok and "500" in detail


# --- dispatch: severity gating, dedup, escalation -------------------------

def test_notify_incident_respects_min_severity(session, monkeypatch):
    fake = _FakeSender()
    monkeypatch.setattr(notif_service, "build_sender", lambda ch: fake)
    _channel(session, min_severity="critical")
    inc = _incident(session, severity="high")
    notif_service.notify_incident(session, inc, created=True)
    assert fake.calls == []                       # high < critical → not alerted
    assert session.exec(select(Notification)).all() == []


def test_notify_incident_sends_and_updates_channel_health(session, monkeypatch):
    fake = _FakeSender()
    monkeypatch.setattr(notif_service, "build_sender", lambda ch: fake)
    ch = _channel(session, min_severity="high")
    inc = _incident(session, severity="high")
    notif_service.notify_incident(session, inc, created=True)
    assert len(fake.calls) == 1
    rows = session.exec(select(Notification)).all()
    assert len(rows) == 1 and rows[0].status == "sent" and rows[0].incident_id == inc.id
    session.refresh(ch)
    assert ch.status == "connected" and ch.last_sent is not None


def test_notify_incident_dedups_then_escalates_on_severity_rise(session, monkeypatch):
    fake = _FakeSender()
    monkeypatch.setattr(notif_service, "build_sender", lambda ch: fake)
    _channel(session, min_severity="low")
    inc = _incident(session, severity="high")
    notif_service.notify_incident(session, inc)
    notif_service.notify_incident(session, inc)   # same severity → deduped
    assert len(fake.calls) == 1
    inc.severity = "critical"
    session.add(inc)
    session.commit()
    notif_service.notify_incident(session, inc)   # escalation → fresh alert
    assert len(fake.calls) == 2
    assert len(session.exec(select(Notification)).all()) == 2


def test_broken_channel_never_raises(session, monkeypatch):
    def boom(ch):
        raise RuntimeError("channel exploded")

    monkeypatch.setattr(notif_service, "build_sender", boom)
    _channel(session, min_severity="low")
    inc = _incident(session, severity="critical")
    # Must swallow the error — alerting cannot break the pipeline.
    notif_service.notify_incident(session, inc, created=True)


# --- hooks: approval + escalation -----------------------------------------

def test_request_action_notifies_pending_approval(session, monkeypatch):
    fake = _FakeSender()
    monkeypatch.setattr(notif_service, "build_sender", lambda ch: fake)
    _channel(session, min_severity="low", notify_on_incident=False, notify_on_approval=True)
    from app.response.actions import request_action

    inc = _incident(session, severity="high")
    action = request_action(session, "block_user", "alice@corp.com",
                            incident_id=inc.id, requested_by="analyst")
    assert len(fake.calls) == 1
    rows = session.exec(select(Notification).where(Notification.kind == "approval")).all()
    assert len(rows) == 1 and rows[0].action_id == action.id


def test_escalation_renotifies_stale_pending_approval(session, monkeypatch):
    fake = _FakeSender()
    monkeypatch.setattr(notif_service, "build_sender", lambda ch: fake)
    _channel(session, min_severity="low", notify_on_approval=True)
    inc = _incident(session, severity="high")
    stale = utcnow() - timedelta(minutes=45)     # older than the 30-min window
    action = AuditAction(incident_id=inc.id, action_type="block_user", target="x",
                         status="pending", requested_by="sys", origin="demo", requested_at=stale)
    session.add(action)
    session.commit()
    n = notif_service.escalate_pending_approvals(session)
    assert n == 1 and len(fake.calls) == 1
    rows = session.exec(select(Notification).where(Notification.kind == "approval")).all()
    assert rows and rows[0].action_id == action.id


# --- secrets never leak ---------------------------------------------------

def test_channel_brief_hides_secrets(session):
    from app.api.routes import _channel_brief
    from app.core.crypto import encrypt_dict

    ch = _channel(session, kind="slack", secrets_enc=encrypt_dict({"webhook_url": "https://secret/hook"}))
    brief = _channel_brief(ch)
    assert "webhook_url" in brief["secrets_set"]
    assert "https://secret/hook" not in str(brief)


# --- end-to-end: the loop closes ------------------------------------------

def test_pipeline_alerts_on_new_incident(session, monkeypatch):
    """Real detection cycle → incident → a Notification row is produced and the
    channel's sender is invoked. Proves the operational loop is closed."""
    fake = _FakeSender()
    monkeypatch.setattr(notif_service, "build_sender", lambda ch: fake)
    seed_catalog(session)
    seed_org(session)
    _channel(session, min_severity="low")
    ingest_raw_events(session, generate_scenario("ransomware"))
    signals = run_detectors(session)
    correlate_and_score(session, signals)
    rows = session.exec(select(Notification).where(Notification.kind == "incident")).all()
    assert rows, "pipeline produced no incident notification"
    assert fake.calls, "channel sender was never invoked"
