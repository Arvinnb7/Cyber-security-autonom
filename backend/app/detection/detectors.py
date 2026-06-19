"""Threat detection engine (F3).

Each detector is a pure function over a recent window of canonical events that
yields candidate :class:`Signal` objects (not yet persisted). Detectors are
rule/heuristic based and intentionally transparent — the user's attack-model
file can later add data-driven rules alongside these.
"""
from __future__ import annotations

import math
from collections import defaultdict
from datetime import timedelta

from sqlmodel import Session, select

from app.core.time import utcnow
from app.models.tables import Event, Signal
from app.simulation.org import GEO

# Look back this far when correlating an event chain.
WINDOW_MINUTES = 180


def _haversine_km(c1: str, c2: str) -> float:
    if c1 not in GEO or c2 not in GEO:
        return 0.0
    _, lat1, lon1 = GEO[c1]
    _, lat2, lon2 = GEO[c2]
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def _recent_events(session: Session) -> list[Event]:
    cutoff = utcnow() - timedelta(minutes=WINDOW_MINUTES)
    return list(session.exec(
        select(Event).where(Event.timestamp >= cutoff).order_by(Event.timestamp)
    ))


def _by_user(events: list[Event]) -> dict[str, list[Event]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.actor_username:
            grouped[e.actor_username].append(e)
    return grouped


# --- Detectors ------------------------------------------------------------

def detect_impossible_travel(events: list[Event]) -> list[Signal]:
    signals: list[Signal] = []
    for user, evs in _by_user(events).items():
        logins = [e for e in evs if e.action == "login_success" and e.country]
        for a, b in zip(logins, logins[1:]):
            if a.country == b.country:
                continue
            dt_hours = max((b.timestamp - a.timestamp).total_seconds() / 3600, 1 / 60)
            dist = _haversine_km(a.country, b.country)
            speed = dist / dt_hours
            if speed > 900:  # faster than a commercial flight => impossible
                signals.append(Signal(
                    detector="impossible_travel", threat_type="account_takeover",
                    actor_username=user, target_asset=b.target_asset, severity=4,
                    confidence=min(0.6 + speed / 5000, 0.95),
                    description=(f"{user} logged in from {a.country} then {b.country} "
                                f"{dt_hours*60:.0f} min apart ({dist:.0f} km, ~{speed:.0f} km/h)."),
                    event_ids=[a.id, b.id],
                ))
    return signals


def detect_account_takeover(events: list[Event]) -> list[Signal]:
    signals: list[Signal] = []
    for user, evs in _by_user(events).items():
        mfa_fails = [e for e in evs if e.action == "mfa_failed"]
        foreign_login = [e for e in evs if e.action == "login_success"
                         and e.country and e.country not in ("IR",)]
        downloads = [e for e in evs if e.action == "file_download"]
        if mfa_fails and foreign_login and len(downloads) >= 15:
            ids = [e.id for e in (mfa_fails + foreign_login + downloads)]
            signals.append(Signal(
                detector="account_takeover", threat_type="account_takeover",
                actor_username=user, target_asset=downloads[-1].target_asset, severity=5,
                confidence=0.92,
                description=(f"{user}: {len(mfa_fails)} MFA failures, foreign login, then "
                            f"{len(downloads)} file downloads — classic account takeover."),
                event_ids=ids,
            ))
    return signals


def detect_ransomware(events: list[Event]) -> list[Signal]:
    signals: list[Signal] = []
    by_asset: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.target_asset:
            by_asset[e.target_asset].append(e)
    for asset, evs in by_asset.items():
        renames = [e for e in evs if e.action == "file_rename"]
        malware = [e for e in evs if e.action == "malware_detected"]
        if len(renames) >= 20 or malware:
            conf = 0.97 if malware else min(0.7 + len(renames) / 200, 0.95)
            user = next((e.actor_username for e in (malware + renames) if e.actor_username), None)
            signals.append(Signal(
                detector="ransomware", threat_type="ransomware",
                actor_username=user, target_asset=asset, severity=5, confidence=conf,
                description=(f"{asset}: {len(renames)} rapid file renames"
                            + (" + EDR malware verdict" if malware else "")
                            + " — ransomware encryption pattern."),
                event_ids=[e.id for e in (renames + malware)],
            ))
    return signals


def detect_data_exfiltration(events: list[Event]) -> list[Signal]:
    signals: list[Signal] = []
    for user, evs in _by_user(events).items():
        downloads = [e for e in evs if e.action == "file_download"]
        uploads = [e for e in evs if e.action == "large_upload"]
        if len(downloads) >= 20 and uploads:
            dest = uploads[-1].raw.get("destination", "external")
            signals.append(Signal(
                detector="data_exfiltration", threat_type="data_exfiltration",
                actor_username=user, target_asset=downloads[-1].target_asset, severity=4,
                confidence=0.88,
                description=(f"{user} downloaded {len(downloads)} files then uploaded a large "
                            f"volume to {dest} — likely data exfiltration."),
                event_ids=[e.id for e in (downloads + uploads)],
            ))
    return signals


def detect_anomalous_activity(events: list[Event]) -> list[Signal]:
    signals: list[Signal] = []
    for user, evs in _by_user(events).items():
        risky = [e for e in evs if e.action in ("privilege_escalation", "config_change")]
        if risky:
            signals.append(Signal(
                detector="anomalous_activity", threat_type="anomalous_activity",
                actor_username=user, target_asset=risky[-1].target_asset, severity=4,
                confidence=0.8,
                description=(f"{user} performed {len(risky)} sensitive operations "
                            f"({', '.join(sorted({e.action for e in risky}))}) — abnormal for this account."),
                event_ids=[e.id for e in risky],
            ))
    return signals


DETECTORS = [
    detect_impossible_travel,
    detect_account_takeover,
    detect_ransomware,
    detect_data_exfiltration,
    detect_anomalous_activity,
]


def _signal_fingerprint(s: Signal) -> str:
    return f"{s.detector}:{s.actor_username}:{s.target_asset}:{min(s.event_ids or [0])}"


def run_detectors(session: Session) -> list[Signal]:
    """Run all detectors over recent events, skipping already-known signals."""
    events = _recent_events(session)
    candidates: list[Signal] = []
    for det in DETECTORS:
        candidates.extend(det(events))

    # De-duplicate against signals already stored (idempotent cycles).
    existing = session.exec(select(Signal).where(
        Signal.created_at >= utcnow() - timedelta(minutes=WINDOW_MINUTES * 2)
    ))
    seen = {_signal_fingerprint(s) for s in existing}
    fresh: list[Signal] = []
    for s in candidates:
        fp = _signal_fingerprint(s)
        if fp in seen:
            continue
        seen.add(fp)
        session.add(s)
        fresh.append(s)
    session.commit()
    for s in fresh:
        session.refresh(s)
    return fresh
