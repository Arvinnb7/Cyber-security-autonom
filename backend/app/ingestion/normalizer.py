"""Normalization (F2): source-native RawEvent -> canonical Event."""
from __future__ import annotations

from app.connectors.base import RawEvent
from app.ingestion.dedup import event_fingerprint
from app.models.tables import Event


def normalize(evt: RawEvent) -> Event:
    return Event(
        timestamp=evt.timestamp,
        source=evt.source,
        category=evt.category,
        action=evt.action,
        actor_username=evt.actor_username,
        src_ip=evt.src_ip,
        country=evt.country,
        city=evt.city,
        target_asset=evt.target_asset,
        severity=evt.severity,
        fingerprint=event_fingerprint(evt),
        raw=evt.raw,
    )
