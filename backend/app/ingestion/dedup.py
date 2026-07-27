"""Deduplication (F2).

Events from overlapping sources (e.g. a login seen by both Azure AD and M365)
collapse to one canonical record. The fingerprint is a stable hash over the
identifying fields, bucketed to a short time window so true repeats are dropped
but distinct events are kept.
"""
from __future__ import annotations

import hashlib
import json

from sqlmodel import Session, select

from app.connectors.base import RawEvent
from app.models.tables import Event

# Events with the same identity within this window are treated as duplicates.
DEDUP_WINDOW_SECONDS = 30


def event_fingerprint(evt: RawEvent) -> str:
    # Include a digest of the payload so genuinely distinct rapid events (e.g.
    # different files downloaded in the same 30s bucket) are NOT collapsed,
    # while exact re-ingests of the same event still dedup.
    bucket = int(evt.timestamp.timestamp() // DEDUP_WINDOW_SECONDS)
    payload = json.dumps(evt.raw, sort_keys=True, default=str)
    key = "|".join(str(x) for x in (
        evt.category, evt.action, evt.actor_username,
        evt.src_ip, evt.target_asset, bucket, payload,
    ))
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def is_duplicate(session: Session, fingerprint: str) -> bool:
    # The time bucket is already baked into the fingerprint, so an identity match
    # means the event falls in the same dedup window — no extra time filter needed.
    existing = session.exec(
        select(Event.id).where(Event.fingerprint == fingerprint).limit(1)
    ).first()
    return existing is not None


# Fingerprints per IN-clause; keeps the statement well within driver limits.
_CHUNK = 500


def existing_fingerprints(session: Session, fingerprints: list[str]) -> set[str]:
    """Which of these fingerprints are already stored — in O(1) queries per chunk.

    Checking one fingerprint at a time meant a round trip per event, so a single
    polling cycle could issue thousands of queries. This collapses that to a
    handful of ``IN`` lookups.
    """
    found: set[str] = set()
    unique = list({f for f in fingerprints if f})
    for i in range(0, len(unique), _CHUNK):
        rows = session.exec(
            select(Event.fingerprint).where(Event.fingerprint.in_(unique[i:i + _CHUNK]))
        ).all()
        found.update(r for r in rows if r)
    return found
