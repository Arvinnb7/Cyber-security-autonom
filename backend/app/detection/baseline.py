"""Per-user behavioural baseline learned from event history.

Detectors use this instead of hardcoded assumptions (e.g. a fixed "home" country)
so anomalies are judged relative to what is normal *for this organization and
this user* — which is what makes detection work on real tenant data.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlmodel import Session, select

from app.core.time import utcnow
from app.models.tables import Event, User

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


def _build_user_baseline(logins: list[Event]) -> UserBaseline:
    n = len(logins)
    country_counts = Counter(e.country for e in logins if e.country)
    hour_counts = Counter(e.timestamp.hour for e in logins if e.timestamp)
    devices = {e.raw.get("device_id") for e in logins if e.raw.get("device_id")}
    # "Home" = countries/hours seen often enough to be considered normal, so a
    # single anomalous login doesn't poison the baseline.
    country_floor = max(2, int(0.10 * n))
    hour_floor = max(2, int(0.05 * n))
    return UserBaseline(
        login_count=n,
        home_countries={c for c, cnt in country_counts.items() if cnt >= country_floor},
        known_devices={d for d in devices if d},
        usual_hours={h for h, cnt in hour_counts.items() if cnt >= hour_floor},
    )


class Baselines:
    """Baselines for all users in the current data mode, built once per cycle."""

    def __init__(self, session: Session, origin: str, window_days: int = BASELINE_DAYS):
        cutoff = utcnow() - timedelta(days=window_days)
        logins = list(session.exec(
            select(Event).where(
                Event.origin == origin,
                Event.action == "login_success",
                Event.timestamp >= cutoff,
            )
        ))
        by_user: dict[str, list[Event]] = {}
        for e in logins:
            if e.actor_username:
                by_user.setdefault(e.actor_username, []).append(e)
        self._by_user = {u: _build_user_baseline(evs) for u, evs in by_user.items()}
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
