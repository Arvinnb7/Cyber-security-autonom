"""Bounded in-memory primitives.

Anything the API keeps in process memory and keys by user-supplied data is a
denial-of-service waiting to happen: a client that varies the key (a random
username, an arbitrary ``days`` value) grows the structure without limit until
the worker is OOM-killed. Both helpers here are therefore hard-capped — they
evict rather than grow, so worst-case memory is a constant we choose up front.

Deliberately dependency-free and per-process. That is enough to stop the platform
harming *itself*; genuine abuse protection belongs at the edge (see README).
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any


class BoundedTTLCache:
    """Small LRU cache with per-entry expiry.

    ``maxsize`` is the safety property: even if every request supplies a distinct
    key, memory use stays bounded.
    """

    def __init__(self, maxsize: int = 256, ttl_seconds: float = 60.0):
        self.maxsize = max(1, maxsize)
        self.ttl = ttl_seconds
        self._data: OrderedDict[Any, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: Any) -> Any | None:
        now = time.monotonic()
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            stored_at, value = entry
            if now - stored_at >= self.ttl:
                self._data.pop(key, None)
                return None
            self._data.move_to_end(key)     # mark as recently used
            return value

    def set(self, key: Any, value: Any) -> None:
        with self._lock:
            self._data[key] = (time.monotonic(), value)
            self._data.move_to_end(key)
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)   # evict least-recently-used

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        return len(self._data)


class SlidingWindowLimiter:
    """Per-key request quota over a sliding window, with bounded key space.

    Tracks hit timestamps per key and drops those older than the window. The key
    table itself is capped: a flood of unique keys evicts the oldest instead of
    growing, so the limiter cannot become the leak it exists to prevent.
    """

    def __init__(self, limit: int, window_seconds: float, max_keys: int = 10_000):
        self.limit = max(1, limit)
        self.window = window_seconds
        self.max_keys = max(1, max_keys)
        self._hits: OrderedDict[str, list[float]] = OrderedDict()
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> list[float]:
        hits = [t for t in self._hits.get(key, ()) if t > now - self.window]
        self._hits[key] = hits
        self._hits.move_to_end(key)
        while len(self._hits) > self.max_keys:
            self._hits.popitem(last=False)
        return hits

    def check(self, key: str) -> tuple[bool, int]:
        """Record a hit and report whether it was within quota.

        Returns ``(allowed, retry_after_seconds)``.
        """
        now = time.monotonic()
        with self._lock:
            hits = self._prune(key, now)
            allowed = len(hits) < self.limit
            if allowed:
                hits.append(now)
                return True, 0
            return False, max(1, int(self.window - (now - hits[0])))

    def is_blocked(self, key: str) -> tuple[bool, int]:
        """Peek at the quota without consuming any of it."""
        now = time.monotonic()
        with self._lock:
            hits = self._prune(key, now)
            if len(hits) < self.limit:
                return False, 0
            return True, max(1, int(self.window - (now - hits[0])))

    def record(self, key: str) -> None:
        """Count one hit against the quota."""
        now = time.monotonic()
        with self._lock:
            self._prune(key, now).append(now)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()

    def __len__(self) -> int:
        return len(self._hits)
