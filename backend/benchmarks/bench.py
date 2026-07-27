"""Scale benchmark — measures whether Sentinel keeps up at enterprise volume.

The scheduler polls every ``SENTINEL_INGEST_INTERVAL_SECONDS`` (default 20s). If a
full cycle takes longer than that, detection latency grows without bound and the
platform silently falls behind — so the number that matters is
**cycle wall-time vs the ingest interval**.

Usage
-----
    python -m benchmarks.bench --users 5000 --days 30
    python -m benchmarks.bench --users 1000 --days 30 --db postgresql+psycopg://...

Reports wall-time AND SQL query counts for each stage: query count is what
distinguishes an O(1) batched implementation from an O(n) per-row one, and it
stays meaningful regardless of how fast the machine is.
"""
from __future__ import annotations

import argparse
import os
import random
import statistics
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import timedelta

# Benchmarks drive the engine directly; keep the simulator out of the way.
os.environ.setdefault("SENTINEL_SIM_ENABLED", "false")
os.environ.setdefault("SENTINEL_RUN_SCHEDULER", "false")
os.environ.setdefault("SENTINEL_SEED_ON_STARTUP", "false")

from sqlalchemy import event as sa_event  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

import app.models  # noqa: F401,E402 - register tables
from app.connectors.base import RawEvent  # noqa: E402
from app.core.time import utcnow  # noqa: E402
from app.models.tables import Event, User  # noqa: E402

COUNTRIES = ["US", "GB", "DE", "FR", "NL", "IN", "JP", "BR", "CA", "AU"]
ASSETS = ["sharepoint-finance", "exchange-online", "hr-portal", "crm-salesforce",
          "prod-vpc", "legal-vault", "dev-sandbox", "onedrive"]


@dataclass
class Stage:
    name: str
    seconds: float
    queries: int
    note: str = ""


@dataclass
class Report:
    scale: str
    stages: list[Stage] = field(default_factory=list)

    def add(self, stage: Stage) -> None:
        self.stages.append(stage)
        flag = ""
        if stage.name.startswith("full cycle"):
            flag = "  <-- must stay under the ingest interval"
        print(f"  {stage.name:<34} {stage.seconds:>8.2f}s  {stage.queries:>7} queries"
              f"  {stage.note}{flag}")


class QueryCounter:
    """Counts SQL statements issued on an engine."""

    def __init__(self, engine):
        self.engine = engine
        self.count = 0
        self._hook = None

    def _on_execute(self, *_args, **_kw):
        self.count += 1

    def __enter__(self):
        self._hook = self._on_execute
        sa_event.listen(self.engine, "before_cursor_execute", self._hook)
        return self

    def __exit__(self, *_exc):
        sa_event.remove(self.engine, "before_cursor_execute", self._hook)
        return False


@contextmanager
def measure(engine, report: Report, name: str, note: str = ""):
    counter = QueryCounter(engine)
    with counter:
        start = time.perf_counter()
        yield
        elapsed = time.perf_counter() - start
    report.add(Stage(name, elapsed, counter.count, note))


def seed_history(session: Session, users: int, days: int, logins_per_user_per_day: int) -> int:
    """Populate realistic login history — the data the baseline learns from."""
    rng = random.Random(1337)
    now = utcnow()
    total = 0
    batch: list[Event] = []
    for u in range(users):
        username = f"user{u:05d}@corp.com"
        home = COUNTRIES[u % len(COUNTRIES)]
        session.add(User(username=username, display_name=username, email=username,
                         origin="demo", is_privileged=(u % 50 == 0)))
        for d in range(days):
            for k in range(logins_per_user_per_day):
                ts = now - timedelta(days=d, hours=rng.randint(8, 18), minutes=rng.randint(0, 59))
                batch.append(Event(
                    timestamp=ts, source="microsoft_365", category="authentication",
                    action="login_success", actor_username=username,
                    src_ip=f"203.0.113.{u % 250}", country=home, city=home,
                    target_asset=ASSETS[(u + k) % len(ASSETS)], severity=2,
                    fingerprint=f"seed-{u}-{d}-{k}", origin="demo",
                    raw={"device_id": f"dev-{u % 3}", "app": "Office365"},
                ))
                total += 1
        if len(batch) >= 20000:
            session.bulk_save_objects(batch)
            session.commit()
            batch.clear()
    if batch:
        session.bulk_save_objects(batch)
    session.commit()
    return total


def make_cycle_batch(users: int, events: int, nonce: int = 0) -> list[RawEvent]:
    """A single polling cycle's worth of fresh events from the connector.

    ``nonce`` must differ between cycles: without it the batches are identical and
    de-duplication would discard them, making a cycle look far cheaper than a real
    one where every event is new.
    """
    rng = random.Random(99 + nonce)
    now = utcnow()
    out: list[RawEvent] = []
    for i in range(events):
        u = rng.randrange(users)
        out.append(RawEvent(
            source="microsoft_365", timestamp=now - timedelta(seconds=rng.randint(0, 60)),
            category="authentication", action="login_success",
            actor_username=f"user{u:05d}@corp.com",
            src_ip=f"203.0.113.{u % 250}",
            country=COUNTRIES[u % len(COUNTRIES)], city=COUNTRIES[u % len(COUNTRIES)],
            target_asset=ASSETS[i % len(ASSETS)], severity=2,
            raw={"device_id": f"dev-{u % 3}", "seq": i, "cycle": nonce},
        ))
    return out


def run(users: int, days: int, per_day: int, cycle_events: int, db_url: str) -> Report:
    from app.detection.baseline import Baselines
    from app.detection.catalog import seed_catalog
    from app.detection.detectors import run_detectors
    from app.ingestion.pipeline import ingest_raw_events
    from app.services import analytics

    engine = create_engine(db_url, echo=False)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)

    report = Report(scale=f"{users} users x {days} days")
    print(f"\n=== Sentinel scale benchmark — {users} users, {days} days history, "
          f"{cycle_events} events/cycle ===")
    print(f"    database: {db_url.split('://')[0]}")

    from app.detection.baseline import rebuild_baselines

    with Session(engine) as session:
        seed_catalog(session)
        t0 = time.perf_counter()
        total = seed_history(session, users, days, per_day)
        print(f"  (seeded {total:,} historical events in {time.perf_counter() - t0:.1f}s)\n")

        # Nightly job — the only place the full history is read.
        with measure(engine, report, "baseline rebuild (nightly)", f"{users} users"):
            rebuild_baselines(session, "demo")

        # Per-cycle cost — this is what used to re-read the whole 30-day history.
        with measure(engine, report, "baseline load (per cycle)", f"{users} users"):
            Baselines(session, "demo")

        batch = make_cycle_batch(users, cycle_events, nonce=1)
        with measure(engine, report, "ingest batch", f"{cycle_events} events"):
            ingest_raw_events(session, batch)

        active = {e.actor_username for e in batch if e.actor_username}
        with measure(engine, report, "run_detectors (scoped)", f"{len(active)} active users"):
            run_detectors(session, active_users=active)

        with measure(engine, report, "analytics: org_risk"):
            analytics.org_risk(session)
        with measure(engine, report, "analytics: sla_metrics"):
            analytics.sla_metrics(session, days=30)

        # The number that decides whether the platform keeps up.
        batch2 = make_cycle_batch(users, cycle_events, nonce=2)
        active2 = {e.actor_username for e in batch2 if e.actor_username}
        with measure(engine, report, "full cycle (ingest+detect)"):
            ingest_raw_events(session, batch2)
            run_detectors(session, active_users=active2)

    return report


def main() -> None:
    p = argparse.ArgumentParser(description="Sentinel scale benchmark")
    p.add_argument("--users", type=int, default=1000)
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--logins-per-day", type=int, default=4,
                   help="logins per user per day of history")
    p.add_argument("--cycle-events", type=int, default=2000,
                   help="events arriving in one polling cycle")
    p.add_argument("--db", default="sqlite:///./bench.db",
                   help="database URL (use postgresql+psycopg://... for a prod-like run)")
    p.add_argument("--interval", type=float, default=20.0,
                   help="ingest interval the cycle must stay under")
    args = p.parse_args()

    report = run(args.users, args.days, args.logins_per_day, args.cycle_events, args.db)

    cycle = next((s for s in report.stages if s.name.startswith("full cycle")), None)
    print()
    if cycle:
        verdict = "KEEPS UP" if cycle.seconds < args.interval else "FALLS BEHIND"
        print(f"  VERDICT: full cycle {cycle.seconds:.2f}s vs {args.interval:.0f}s "
              f"interval -> {verdict}")
    slowest = max(report.stages, key=lambda s: s.seconds)
    print(f"  slowest stage: {slowest.name} ({slowest.seconds:.2f}s, {slowest.queries} queries)")
    total_q = sum(s.queries for s in report.stages)
    print(f"  total queries across stages: {total_q:,}")
    times = [s.seconds for s in report.stages]
    print(f"  median stage time: {statistics.median(times):.3f}s")


if __name__ == "__main__":
    main()
