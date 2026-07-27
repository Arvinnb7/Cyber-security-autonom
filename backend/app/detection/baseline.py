"""Per-user behavioural baseline learned from event history.

Detectors use this instead of hardcoded assumptions (e.g. a fixed "home" country)
so anomalies are judged relative to what is normal *for this organization and
this user* — which is what makes detection work on real tenant data.

**Scale note.** The learned state is persisted in ``UserBaselineState`` and kept
up to date incrementally as events are ingested. Recomputing it from raw history
on every cycle meant reading the entire 30-day event window every 20 seconds
(millions of rows for a large tenant); now a cycle reads one small row per user.
A nightly job (``rebuild_baselines``) does the full recompute so counters can't
drift as old events age out of the window.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlmodel import Session, select

from app.core.time import utcnow
from app.models.tables import Event, User, UserBaselineState

# How far back to learn "normal" behaviour, and how much history is needed
# before the baseline is trusted enough to flag deviations.
BASELINE_DAYS = 30
MIN_LOGINS = 8


@dataclass
class UserBaseline:
    login_count: int = 0
    home_countries: set[str] = field(default_factory=set)
    known_devices: set[str] = field(default_factory=set)
    usual_hours: set[int] = field(default_factory=set)

    @property
    def established(self) -> bool:
        """True once we've seen enough history to judge deviations meaningfully."""
        return self.login_count >= MIN_LOGINS

    def is_new_country(self, country: str | None) -> bool:
        return bool(country) and self.established and country not in self.home_countries

    def is_new_device(self, device_id: str | None) -> bool:
        return bool(device_id) and self.established and device_id not in self.known_devices

    def is_unusual_time(self, ts: datetime | None) -> bool:
        return ts is not None and self.established and ts.hour not in self.usual_hours


def _from_counts(login_count: int, country_counts: dict, hour_counts: dict,
                 devices) -> UserBaseline:
    """Derive the baseline from running counters.

    "Home" = countries/hours seen often enough to be considered normal, so a
    single anomalous login doesn't poison the baseline.
    """
    n = login_count
    country_floor = max(2, int(0.10 * n))
    hour_floor = max(2, int(0.05 * n))
    return UserBaseline(
        login_count=n,
        home_countries={c for c, cnt in (country_counts or {}).items() if cnt >= country_floor},
        known_devices={d for d in (devices or []) if d},
        usual_hours={int(h) for h, cnt in (hour_counts or {}).items() if cnt >= hour_floor},
    )


def _counts_from_events(logins: list[Event]) -> tuple[int, dict, dict, list]:
    country_counts = Counter(e.country for e in logins if e.country)
    hour_counts = Counter(str(e.timestamp.hour) for e in logins if e.timestamp)
    devices = {e.raw.get("device_id") for e in logins if e.raw.get("device_id")}
    return len(logins), dict(country_counts), dict(hour_counts), sorted(d for d in devices if d)


# --- maintaining the persisted state --------------------------------------

def _states_for(session: Session, origin: str, usernames: list[str]) -> dict[str, UserBaselineState]:
    """Fetch baseline rows for the given users in as few queries as possible."""
    out: dict[str, UserBaselineState] = {}
    chunk = 500
    for i in range(0, len(usernames), chunk):
        rows = session.exec(
            select(UserBaselineState).where(
                UserBaselineState.origin == origin,
                UserBaselineState.username.in_(usernames[i:i + chunk]),
            )
        ).all()
        for row in rows:
            out[row.username] = row
    return out


def update_baselines(session: Session, events: list[Event], origin: str) -> int:
    """Fold a freshly-ingested batch into the stored baselines. Returns users touched.

    Only successful logins teach the baseline — the same signal the original
    in-memory implementation learned from.
    """
    logins = [e for e in events if e.action == "login_success" and e.actor_username]
    if not logins:
        return 0
    by_user: dict[str, list[Event]] = {}
    for e in logins:
        by_user.setdefault(e.actor_username, []).append(e)

    states = _states_for(session, origin, list(by_user))
    now = utcnow()
    new_rows: list[UserBaselineState] = []
    updates: list[dict] = []
    for username, evs in by_user.items():
        state = states.get(username)
        is_new = state is None
        if is_new:
            state = UserBaselineState(username=username, origin=origin,
                                      window_start=min(e.timestamp for e in evs))
        countries = dict(state.country_counts or {})
        hours = dict(state.hour_counts or {})
        devices = set(state.known_devices or [])
        for e in evs:
            if e.country:
                countries[e.country] = countries.get(e.country, 0) + 1
            if e.timestamp:
                key = str(e.timestamp.hour)
                hours[key] = hours.get(key, 0) + 1
            device = e.raw.get("device_id")
            if device:
                devices.add(device)
        state.login_count = (state.login_count or 0) + len(evs)
        state.country_counts = countries
        state.hour_counts = hours
        state.known_devices = sorted(devices)
        state.updated_at = now
        if is_new:
            new_rows.append(state)
        else:
            updates.append({"id": state.id, "login_count": state.login_count,
                            "country_counts": countries, "hour_counts": hours,
                            "known_devices": state.known_devices, "updated_at": now})
    # Batched writes: a busy cycle touches thousands of identities, and one
    # statement each would dominate the cycle on a networked database.
    if new_rows:
        session.bulk_save_objects(new_rows)
    if updates:
        session.bulk_update_mappings(UserBaselineState, updates)
    session.commit()
    return len(by_user)


def rebuild_baselines(session: Session, origin: str, window_days: int = BASELINE_DAYS) -> int:
    """Full recompute from raw history — run nightly.

    Incremental updates only ever add, so counts would slowly overstate reality as
    events age out of the window. This resets them to the truth.
    """
    cutoff = utcnow() - timedelta(days=window_days)
    logins = session.exec(
        select(Event).where(
            Event.origin == origin,
            Event.action == "login_success",
            Event.timestamp >= cutoff,
        )
    ).all()
    by_user: dict[str, list[Event]] = {}
    for e in logins:
        if e.actor_username:
            by_user.setdefault(e.actor_username, []).append(e)

    existing = {s.username: s for s in session.exec(
        select(UserBaselineState).where(UserBaselineState.origin == origin)
    ).all()}
    now = utcnow()
    new_rows: list[UserBaselineState] = []
    updates: list[dict] = []
    for username, evs in by_user.items():
        count, countries, hours, devices = _counts_from_events(evs)
        state = existing.pop(username, None)
        if state is None:
            new_rows.append(UserBaselineState(
                username=username, origin=origin, login_count=count,
                country_counts=countries, hour_counts=hours, known_devices=devices,
                window_start=cutoff, updated_at=now,
            ))
        else:
            updates.append({"id": state.id, "login_count": count,
                            "country_counts": countries, "hour_counts": hours,
                            "known_devices": devices, "window_start": cutoff,
                            "updated_at": now})
    if new_rows:
        session.bulk_save_objects(new_rows)
    if updates:
        session.bulk_update_mappings(UserBaselineState, updates)
    # Users with no logins left in the window no longer have a baseline.
    for stale in existing.values():
        session.delete(stale)
    session.commit()
    return len(by_user)


class Baselines:
    """Baselines for all users in the current data mode, loaded once per cycle.

    Reads the small persisted state table rather than the raw event history, so
    the cost is proportional to the number of users, not to how much history the
    organization has accumulated.
    """

    def __init__(self, session: Session, origin: str, window_days: int = BASELINE_DAYS):
        self._by_user = {
            s.username: _from_counts(s.login_count, s.country_counts, s.hour_counts,
                                     s.known_devices)
            for s in session.exec(
                select(UserBaselineState).where(UserBaselineState.origin == origin)
            )
        }
        # Privileged identities come from the monitored-user table for THIS data
        # mode — never from the demo fixture — so the customer's real admins are
        # scored as privileged on live data.
        self._privileged = {
            u.username for u in session.exec(
                select(User).where(User.origin == origin, User.is_privileged == True)  # noqa: E712
            )
        }

    def for_user(self, username: str | None) -> UserBaseline:
        if not username:
            return UserBaseline()
        return self._by_user.get(username, UserBaseline())

    def is_privileged(self, username: str | None) -> bool:
        return bool(username) and username in self._privileged
