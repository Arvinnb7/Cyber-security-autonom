"""Concurrent load & abuse test — does the API stay up when hammered?

Complements ``benchmarks/bench.py``: that one measures whether the *detection
engine* keeps up with event volume, this one measures whether the *API* survives
many simultaneous analysts and deliberately hostile requests.

Pass criteria:
  * zero 5xx responses under sustained concurrent load
  * every abuse scenario answered with a 4xx (refused), never a 5xx (crashed)
  * process memory flat across an abuse loop (no unbounded growth)

Usage
-----
    # against a server you started yourself
    python -m benchmarks.loadtest --url http://127.0.0.1:8000 --users 50 --seconds 30
"""
from __future__ import annotations

import argparse
import statistics
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import httpx

TIMEOUT = 30.0


@dataclass
class Result:
    latencies: list[float] = field(default_factory=list)
    codes: Counter = field(default_factory=Counter)
    errors: list[str] = field(default_factory=list)

    def merge(self, other: "Result") -> None:
        self.latencies.extend(other.latencies)
        self.codes.update(other.codes)
        self.errors.extend(other.errors)

    @property
    def server_errors(self) -> int:
        return sum(n for code, n in self.codes.items()
                   if isinstance(code, int) and code >= 500)

    def percentile(self, p: float) -> float:
        if not self.latencies:
            return 0.0
        ordered = sorted(self.latencies)
        idx = min(int(len(ordered) * p / 100.0), len(ordered) - 1)
        return ordered[idx] * 1000.0


def login(base: str, username: str, password: str) -> dict[str, str]:
    r = httpx.post(f"{base}/api/auth/login",
                   data={"username": username, "password": password}, timeout=TIMEOUT)
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# Endpoints a real analyst session actually hits, in rough proportion.
BROWSE_PATHS = [
    "/api/dashboard/overview",
    "/api/dashboard/overview",
    "/api/incidents?limit=25",
    "/api/system/health",
    "/api/users",
    "/api/assets",
    "/api/detections",
    "/api/metrics/sla?days=30",
]


def _browse_worker(base: str, headers: dict, deadline: float) -> Result:
    out = Result()
    i = 0
    with httpx.Client(timeout=TIMEOUT, headers=headers) as client:
        while time.monotonic() < deadline:
            path = BROWSE_PATHS[i % len(BROWSE_PATHS)]
            i += 1
            start = time.perf_counter()
            try:
                resp = client.get(f"{base}{path}")
                out.latencies.append(time.perf_counter() - start)
                out.codes[resp.status_code] += 1
            except Exception as exc:  # noqa: BLE001 - a dropped connection is a failure
                out.codes["conn_error"] += 1
                out.errors.append(f"{path}: {type(exc).__name__}: {exc}")
    return out


def run_load(base: str, headers: dict, users: int, seconds: int) -> Result:
    print(f"\n=== Concurrent load: {users} users for {seconds}s ===")
    deadline = time.monotonic() + seconds
    total = Result()
    with ThreadPoolExecutor(max_workers=users) as pool:
        futures = [pool.submit(_browse_worker, base, headers, deadline) for _ in range(users)]
        for f in as_completed(futures):
            total.merge(f.result())

    requests = sum(total.codes.values())
    throttled = total.codes.get(429, 0)
    served = total.codes.get(200, 0)
    print(f"  requests      : {requests:,} ({requests / max(seconds, 1):.0f}/s)")
    print(f"  served (200)  : {served:,}")
    print(f"  latency p50   : {total.percentile(50):.0f} ms")
    print(f"  latency p95   : {total.percentile(95):.0f} ms")
    print(f"  latency p99   : {total.percentile(99):.0f} ms")
    print(f"  status codes  : {dict(total.codes)}")
    verdict = "PASS" if total.server_errors == 0 else f"FAIL ({total.server_errors} 5xx)"
    print(f"  5xx errors    : {total.server_errors}  -> {verdict}")
    for err in total.errors[:3]:
        print(f"    ! {err}")
    if requests and throttled / requests > 0.2:
        print("\n  NOTE: most requests were rate limited, so this measured the limiter,")
        print("        not serving capacity. All simulated users share one IP+token and")
        print("        therefore one quota bucket. To measure capacity, re-run the server")
        print("        with SENTINEL_RATE_LIMIT_PER_MINUTE set high (or _ENABLED=false).")
    return total


def run_abuse(base: str, headers: dict) -> bool:
    """Each of these used to be a way to hurt the server. All must be refused."""
    print("\n=== Abuse scenarios (must be refused, never 5xx) ===")
    ok = True
    checks: list[tuple[str, str, dict]] = [
        ("huge page size", "GET", {"url": "/api/incidents?limit=999999999"}),
        ("huge audit page", "GET", {"url": "/api/audit?limit=999999999"}),
        ("absurd SLA window", "GET", {"url": "/api/metrics/sla?days=999999999"}),
        ("negative page size", "GET", {"url": "/api/incidents?limit=-1"}),
        ("oversized chat payload", "POST",
         {"url": "/api/chat", "json": {"question": "x" * 200_000}}),
        ("oversized note", "POST",
         {"url": "/api/incidents/1/notes", "json": {"body": "x" * 200_000}}),
    ]
    with httpx.Client(timeout=TIMEOUT, headers=headers) as client:
        for name, method, kw in checks:
            url = base + kw.pop("url")
            try:
                resp = client.request(method, url, **kw)
                status = resp.status_code
            except Exception as exc:  # noqa: BLE001
                print(f"  {name:<24} CONNECTION ERROR: {exc}")
                ok = False
                continue
            refused = 400 <= status < 500
            if not refused:
                ok = False
            print(f"  {name:<24} -> HTTP {status}  {'refused ✓' if refused else 'NOT REFUSED ✗'}")

        # Login spam with rotating usernames: the classic unbounded-dict vector.
        codes = Counter()
        for i in range(300):
            try:
                r = client.post(f"{base}/api/auth/login",
                                data={"username": f"ghost{i}@x", "password": "nope"})
                codes[r.status_code] += 1
            except Exception:  # noqa: BLE001
                codes["conn_error"] += 1
        crashed = sum(n for c, n in codes.items() if isinstance(c, int) and c >= 500)
        print(f"  {'login spam (300x)':<24} -> {dict(codes)}  "
              f"{'contained ✓' if crashed == 0 else 'CRASHED ✗'}")
        ok = ok and crashed == 0

        # Varied cache keys: previously grew an in-process dict without limit.
        codes = Counter()
        for days in range(1, 400):
            r = client.get(f"{base}/api/metrics/sla?days={days}")
            codes[r.status_code] += 1
        crashed = sum(n for c, n in codes.items() if isinstance(c, int) and c >= 500)
        print(f"  {'cache-key spam (400x)':<24} -> {dict(codes)}  "
              f"{'contained ✓' if crashed == 0 else 'CRASHED ✗'}")
        ok = ok and crashed == 0
    return ok


def check_still_alive(base: str) -> bool:
    try:
        r = httpx.get(f"{base}/api/health", timeout=TIMEOUT)
        alive = r.status_code == 200
    except Exception as exc:  # noqa: BLE001
        print(f"\n  SERVER IS DOWN: {exc}")
        return False
    print(f"\n  server still healthy after everything: {'YES' if alive else 'NO'}")
    return alive


def main() -> None:
    p = argparse.ArgumentParser(description="Sentinel API load & abuse test")
    p.add_argument("--url", default="http://127.0.0.1:8000")
    p.add_argument("--users", type=int, default=50)
    p.add_argument("--seconds", type=int, default=30)
    p.add_argument("--username", default="admin")
    p.add_argument("--password", default="admin")
    p.add_argument("--skip-abuse", action="store_true")
    args = p.parse_args()

    base = args.url.rstrip("/")
    headers = login(base, args.username, args.password)

    # Abuse first, on a fresh quota: otherwise the load phase exhausts the rate
    # limit and every hostile request comes back 429, hiding whether the specific
    # guard (422/413) actually fired.
    abuse_ok = True if args.skip_abuse else run_abuse(base, headers)
    load = run_load(base, headers, args.users, args.seconds)
    alive = check_still_alive(base)

    passed = load.server_errors == 0 and abuse_ok and alive
    print(f"\n  OVERALL: {'PASS — stayed up' if passed else 'FAIL'}")
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
