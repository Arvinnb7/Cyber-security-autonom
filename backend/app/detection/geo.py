"""Geographic distance for impossible-travel detection — worldwide.

The demo simulator only ever produced nine countries, and the original distance
helper returned ``0.0`` for anything it didn't know. On a real tenant that made
impossible-travel *silently* undetectable for most of the world: a login from
France followed by one from Japan scored zero km/h and never fired.

This module covers every ISO-3166 country and — crucially — returns ``None`` for
an unknown code so callers can **skip** the pair instead of treating it as "no
travel happened".
"""
from __future__ import annotations

import json
import logging
import math
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger("sentinel.geo")

EARTH_RADIUS_KM = 6371.0
_DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "country_centroids.json"


@lru_cache(maxsize=1)
def _centroids() -> dict[str, tuple[float, float]]:
    try:
        raw = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.exception("could not load country centroids from %s", _DATA_FILE)
        return {}
    out: dict[str, tuple[float, float]] = {}
    for code, value in raw.items():
        if code.startswith("_") or not isinstance(value, list) or len(value) != 2:
            continue
        out[code.upper()] = (float(value[0]), float(value[1]))
    return out


def known_country(code: str | None) -> bool:
    return bool(code) and code.strip().upper() in _centroids()


def distance_km(country_a: str | None, country_b: str | None) -> float | None:
    """Great-circle distance between two country centroids.

    Returns ``None`` when either country is unknown — the caller must then skip
    the comparison rather than assume zero distance.
    """
    if not country_a or not country_b:
        return None
    a, b = country_a.strip().upper(), country_b.strip().upper()
    points = _centroids()
    if a not in points or b not in points:
        return None
    if a == b:
        return 0.0
    lat1, lon1 = points[a]
    lat2, lon2 = points[b]
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    h = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(h))


def implied_speed_kmh(country_a: str | None, country_b: str | None, hours: float) -> float | None:
    """Travel speed implied by two logins, or ``None`` if it can't be judged."""
    km = distance_km(country_a, country_b)
    if km is None:
        return None
    return km / max(hours, 1 / 60)
