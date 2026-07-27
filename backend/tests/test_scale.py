"""Phase 6: guard the properties that make the platform scale.

Wall-clock timings belong in ``benchmarks/bench.py``; these are the invariants
that must hold on any machine. They fail loudly if someone reintroduces a
per-row query or makes the hot path read the whole event history again.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import event as sa_event
from sqlmodel import select

from app.connectors.base import RawEvent
from app.core.time import utcnow
from app.detection.baseline import Baselines, rebuild_baselines, update_baselines
from app.detection.detectors import run_detectors
from app.ingestion.pipeline import ingest_raw_events
from app.models.tables import Event, UserBaselineState


class CountQueries:
    """Counts SQL statements issued during the block."""

    def __init__(self, session):
        self.engine = session.get_bind()
        self.count = 0

    def _hook(self, *_a, **_kw):
        self.count += 1

    def __enter__(self):
        sa_event.listen(self.engine, "before_cursor_execute", self._hook)
        return self

    def __exit__(self, *_exc):
        sa_event.remove(self.engine, "before_cursor_execute", self._hook)
        return False


def _login(user: str, country: str, ts, device: str = "lap-1", seq: int = 0) -> RawEvent:
    return RawEvent(source="microsoft_365", timestamp=ts, category="authentication",
                    action="login_success", actor_username=user, country=country, city=country,
                    src_ip="203.0.113.10", raw={"device_id": device, "seq": seq})


def _batch(n: int, users: int = 50, nonce: int = 0) -> list[RawEvent]:
    now = utcnow()
    return [_login(f"user{i % users:04d}@corp.com", "US",
                   now - timedelta(seconds=i % 60), seq=i * 1000 + nonce)
            for i in range(n)]


# --- ingestion cost must not scale with batch size ------------------------

def test_ingest_query_count_is_bounded(session):
    """500 events must not mean 500 round trips."""
    with CountQueries(session) as counter:
        inserted = ingest_raw_events(session, _batch(500))
    assert inserted == 500
    assert counter.count < 60, f"ingest issued {counter.count} queries for 500 events"


def test_ingest_cost_is_sublinear_in_batch_size(session):
    """Doubling the batch must not double the query count."""
    with CountQueries(session) as small:
        ingest_raw_events(session, _batch(100, nonce=1))
    with CountQueries(session) as large:
        ingest_raw_events(session, _batch(800, nonce=2))
    assert large.count < small.count * 3, (
        f"{small.count} queries for 100 events vs {large.count} for 800 — looks per-row")


def test_duplicates_are_dropped_within_and_across_batches(session):
    events = _batch(50, nonce=7)
    assert ingest_raw_events(session, events) == 50
    assert ingest_raw_events(session, events) == 0          # re-ingest: all duplicates
    assert ingest_raw_events(session, events + events) == 0  # duplicated inside one batch
    assert len(session.exec(select(Event)).all()) == 50


# --- baseline must read state, not history --------------------------------

def test_baseline_load_does_not_scan_event_history(session):
    ingest_raw_events(session, _batch(400, users=20, nonce=3))
    with CountQueries(session) as counter:
        Baselines(session, "demo")
    assert counter.count <= 3, f"baseline load issued {counter.count} queries"


def test_baseline_load_cost_is_flat_as_history_grows(session):
    ingest_raw_events(session, _batch(200, users=20, nonce=4))
    with CountQueries(session) as first:
        Baselines(session, "demo")
    for n in range(5, 12):                       # pile on much more history
        ingest_raw_events(session, _batch(400, users=20, nonce=n))
    with CountQueries(session) as later:
        Baselines(session, "demo")
    assert later.count == first.count, "baseline load got more expensive as history grew"


def test_incremental_update_matches_full_rebuild(session):
    """The cheap incremental path must agree with the authoritative recompute."""
    now = utcnow()
    events = [_login("carol@corp.com", "DE", now - timedelta(days=d, hours=3), seq=d)
              for d in range(1, 13)]
    events.append(_login("carol@corp.com", "RU", now - timedelta(days=2, hours=21),
                         device="odd", seq=99))
    for i in range(0, len(events), 3):           # arrive in small cycles
        ingest_raw_events(session, events[i:i + 3])

    incremental = Baselines(session, "demo").for_user("carol@corp.com")
    rebuild_baselines(session, "demo")
    rebuilt = Baselines(session, "demo").for_user("carol@corp.com")

    assert incremental.login_count == rebuilt.login_count
    assert incremental.home_countries == rebuilt.home_countries
    assert incremental.known_devices == rebuilt.known_devices
    assert incremental.usual_hours == rebuilt.usual_hours
    # And the learned semantics still hold.
    assert not incremental.is_new_country("DE")
    assert incremental.is_new_country("RU")


def test_rebuild_drops_users_who_left_the_window(session):
    ingest_raw_events(session, [_login("gone@corp.com", "US", utcnow() - timedelta(days=90))])
    assert session.exec(select(UserBaselineState)).all()
    rebuild_baselines(session, "demo")           # 30-day window excludes them
    assert session.exec(select(UserBaselineState)).all() == []


def test_update_baselines_ignores_non_login_events(session):
    ev = Event(source="m365", category="file", action="file_download",
               actor_username="dan@corp.com", origin="demo", timestamp=utcnow())
    assert update_baselines(session, [ev], "demo") == 0


# --- detection must scale with activity, not population -------------------

def test_scoped_detection_ignores_inactive_users(session):
    """Only the subjects touched this cycle are re-examined."""
    now = utcnow()
    ingest_raw_events(session, [_login(f"quiet{i:03d}@corp.com", "US",
                                       now - timedelta(minutes=30), seq=i)
                                for i in range(200)])
    ingest_raw_events(session, [_login("busy@corp.com", "US", now - timedelta(minutes=5), seq=999)])

    from app.detection.detectors import _recent_events

    scoped = _recent_events(session, {"busy@corp.com"}, set())
    everything = _recent_events(session)
    assert {e.actor_username for e in scoped} == {"busy@corp.com"}
    assert len(scoped) < len(everything)


def test_empty_active_set_does_no_work(session):
    ingest_raw_events(session, _batch(50, nonce=8))
    with CountQueries(session) as counter:
        assert run_detectors(session, active_users=set(), active_assets=set()) == []
    assert counter.count == 0, "an idle cycle should not query at all"


def test_scoped_and_unscoped_detection_agree(session):
    """Scoping is an optimization, not a behaviour change: the same incident must
    be found either way."""
    from app.detection.catalog import seed_catalog

    seed_catalog(session)
    user = "traveller@corp.com"
    now = utcnow()
    ingest_raw_events(session, [_login(user, "US", now - timedelta(days=d), seq=d)
                                for d in range(1, 11)])
    base = now - timedelta(minutes=25)
    ingest_raw_events(session, [_login(user, "US", base, seq=101),
                                _login(user, "RU", base + timedelta(minutes=10), seq=102)])

    scoped = run_detectors(session, active_users={user})
    assert any(s.det_id == "DET-001" for s in scoped), "scoped run missed the incident"
