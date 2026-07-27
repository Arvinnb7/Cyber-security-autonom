"""Phase 5: the platform notices when IT goes blind.

The failure mode that makes replacing human watchers dangerous is silent: a
broken connector stops ingestion, the dashboard shows "0 active threats", and
nobody is left to notice. These tests pin that behaviour down.
"""
from __future__ import annotations

from datetime import timedelta

from sqlmodel import select

from app.core.time import utcnow
from app.detection.geo import distance_km, implied_speed_kmh, known_country
from app.models.tables import Connection, Event, Notification, NotificationChannel
from app.monitoring.health import (
    evaluate_health,
    get_state,
    health_snapshot,
    record_cycle,
    run_health_check,
)
from app.notifications import service as notif_service


class _FakeSender:
    def __init__(self):
        self.calls: list[tuple] = []

    def send(self, subject, body, meta):
        self.calls.append((subject, body, meta))
        return True, "ok (fake)"


def _channel(session, **kw) -> NotificationChannel:
    defaults = dict(kind="slack", display_name="soc", enabled=True, min_severity="high",
                    notify_on_incident=True, notify_on_approval=True, notify_on_health=True,
                    secrets_enc="")
    defaults.update(kw)
    ch = NotificationChannel(**defaults)
    session.add(ch)
    session.commit()
    session.refresh(ch)
    return ch


def _broken_connection(session) -> Connection:
    conn = Connection(provider="microsoft_365", display_name="M365", enabled=True,
                      status="error", last_error="AADSTS7000215: invalid client secret",
                      consecutive_failures=4)
    session.add(conn)
    session.commit()
    session.refresh(conn)
    return conn


# --- detection of blindness ----------------------------------------------

def test_broken_connector_is_detected(session):
    _broken_connection(session)
    issues = evaluate_health(session)
    assert any(i.key.startswith("connector_down") for i in issues)
    assert any("not collecting data" in i.title for i in issues)


def test_healthy_install_reports_no_issues(session):
    session.add(Connection(provider="microsoft_365", enabled=True, status="connected",
                           consecutive_failures=0))
    session.commit()
    assert evaluate_health(session) == []


def test_stale_ingestion_detected_in_live_mode(session, monkeypatch):
    monkeypatch.setattr("app.core.runtime.current_mode", lambda: "live")
    monkeypatch.setattr("app.core.runtime.is_live", lambda: True)
    session.add(Connection(provider="microsoft_365", enabled=True, status="connected"))
    session.add(Event(source="microsoft_365", action="login_success", origin="live",
                      timestamp=utcnow() - timedelta(hours=3)))
    session.commit()
    issues = evaluate_health(session)
    assert any(i.key == "ingestion_stale" for i in issues), [i.key for i in issues]


def test_no_false_alarm_without_any_integration(session, monkeypatch):
    """A fresh install with nothing connected is not 'broken'."""
    monkeypatch.setattr("app.core.runtime.current_mode", lambda: "live")
    monkeypatch.setattr("app.core.runtime.is_live", lambda: True)
    assert evaluate_health(session) == []


def test_dead_scheduler_detected(session):
    state = get_state(session)
    state.last_cycle_at = utcnow() - timedelta(hours=2)
    session.add(state)
    session.commit()
    assert any(i.key == "scheduler_stalled" for i in evaluate_health(session))


def test_heartbeat_clears_scheduler_issue(session):
    state = get_state(session)
    state.last_cycle_at = utcnow() - timedelta(hours=2)
    session.add(state)
    session.commit()
    record_cycle(session, events_ingested=5)
    assert not any(i.key == "scheduler_stalled" for i in evaluate_health(session))
    assert get_state(session).last_ingest_at is not None


# --- alerting behaviour ---------------------------------------------------

def test_health_alert_ignores_min_severity(session, monkeypatch):
    """A blind SOC is always critical — even on a 'critical only' channel it must
    alert, and even on channels tuned to ignore low-severity incidents."""
    fake = _FakeSender()
    monkeypatch.setattr(notif_service, "build_sender", lambda ch: fake)
    _channel(session, min_severity="critical")
    _broken_connection(session)
    run_health_check(session)
    assert len(fake.calls) == 1
    assert "PLATFORM ALERT" in fake.calls[0][0]


def test_channel_can_opt_out_of_health_alerts(session, monkeypatch):
    fake = _FakeSender()
    monkeypatch.setattr(notif_service, "build_sender", lambda ch: fake)
    _channel(session, notify_on_health=False)
    _broken_connection(session)
    run_health_check(session)
    assert fake.calls == []


def test_repeat_check_does_not_spam(session, monkeypatch):
    fake = _FakeSender()
    monkeypatch.setattr(notif_service, "build_sender", lambda ch: fake)
    _channel(session)
    _broken_connection(session)
    first = run_health_check(session)
    second = run_health_check(session)
    assert first["alerted"] is True
    assert second["alerted"] is False        # same issue, still inside cooldown
    assert len(fake.calls) == 1


def test_recovery_notice_sent_when_fixed(session, monkeypatch):
    fake = _FakeSender()
    monkeypatch.setattr(notif_service, "build_sender", lambda ch: fake)
    _channel(session)
    conn = _broken_connection(session)
    run_health_check(session)
    conn.status = "connected"
    conn.consecutive_failures = 0
    session.add(conn)
    session.commit()
    result = run_health_check(session)
    assert result["state"] == "healthy" and result["alerted"] is True
    assert "RECOVERED" in fake.calls[-1][0]
    kinds = [n.kind for n in session.exec(select(Notification)).all()]
    assert kinds.count("health") == 2


def test_health_snapshot_shape(session):
    _broken_connection(session)
    snap = health_snapshot(session)
    assert snap["state"] == "degraded"
    assert snap["issues"] and "detail" in snap["issues"][0]


def test_snapshot_never_claims_healthy_before_first_check(session):
    """A never-evaluated watchdog must not report 'healthy' — it must go and look."""
    _broken_connection(session)
    assert get_state(session).state == "unknown"
    snap = health_snapshot(session)             # default (cached) path
    assert snap["state"] == "degraded"
    assert snap["cached"] is False              # it evaluated rather than guessing


def test_snapshot_serves_stored_verdict_once_evaluated(session, monkeypatch):
    """After the watchdog has run, polling is cheap: it reuses the stored result
    (with full issue detail) instead of re-running every check."""
    fake = _FakeSender()
    monkeypatch.setattr(notif_service, "build_sender", lambda ch: fake)
    _broken_connection(session)
    run_health_check(session)

    snap = health_snapshot(session)
    assert snap["cached"] is True
    assert snap["state"] == "degraded"
    assert snap["issues"][0]["title"] and snap["issues"][0]["detail"]

    # ...and an explicit refresh still re-evaluates on demand.
    assert health_snapshot(session, fresh=True)["cached"] is False


# --- worldwide geo (previously silent for most of the planet) -------------

def test_geo_covers_countries_outside_the_demo_set():
    """Before Phase 5 the distance table held nine countries and returned 0.0 for
    everything else, so impossible travel could never fire for most of the world."""
    for a, b in (("FR", "JP"), ("IN", "CA"), ("SA", "BR"), ("AU", "NO")):
        km = distance_km(a, b)
        assert km is not None and km > 5000, (a, b, km)


def test_unknown_country_returns_none_not_zero():
    assert distance_km("ZZ", "FR") is None
    assert implied_speed_kmh("ZZ", "FR", 1.0) is None
    assert not known_country("ZZ")
    assert known_country("fr")          # case-insensitive


def test_same_country_is_zero_distance():
    assert distance_km("DE", "DE") == 0.0
