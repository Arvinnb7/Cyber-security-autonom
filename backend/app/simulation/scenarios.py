"""Realistic attack scenarios (F3 demo input).

Each scenario emits a chain of :class:`RawEvent` that, once ingested and run
through the detection engine, correlates into a single incident.

>>> PLUG-IN POINT <<<
The user's "attack model" file drops into ``data/attack_models/`` and is loaded
by ``load_external_scenarios()`` to extend or override these built-ins.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

from app.connectors.base import RawEvent
from app.core.config import settings
from app.core.time import utcnow
from app.simulation.org import DEMO_ASSETS, DEMO_USERS, GEO, user_home

ATTACK_MODELS_DIR = (
    Path(settings.attack_models_dir)
    if settings.attack_models_dir
    else Path(__file__).resolve().parents[3] / "data" / "attack_models"
)


def _now() -> datetime:
    return utcnow()


def _ip(country: str) -> str:
    random.seed(country + str(random.random()))
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _login(source: str, user: str, country: str, action: str, ts: datetime, asset: str | None = None) -> RawEvent:
    city, _, _ = GEO[country]
    return RawEvent(
        source=source, timestamp=ts, category="authentication", action=action,
        actor_username=user, src_ip=_ip(country), country=country, city=city,
        target_asset=asset, severity=2 if action == "login_success" else 3,
        raw={"auth_method": "password", "mfa": action != "mfa_failed"},
    )


# --- Individual scenarios -------------------------------------------------

def scenario_account_takeover(user: str | None = None) -> list[RawEvent]:
    """Impossible travel + MFA brute + mass download => account takeover."""
    user = user or random.choice([u["username"] for u in DEMO_USERS if not u["is_privileged"]])
    home = user_home(user)
    foreign = random.choice([c for c in ("RU", "CN", "NG") if c != home])
    base = _now() - timedelta(minutes=random.randint(20, 90))
    asset = random.choice([a["name"] for a in DEMO_ASSETS if a["asset_type"] in ("saas", "data_store")])
    evts = [
        _login("microsoft_365", user, home, "login_success", base),
        _login("azure", user, foreign, "mfa_failed", base + timedelta(minutes=8)),
        _login("azure", user, foreign, "mfa_failed", base + timedelta(minutes=9)),
        _login("microsoft_365", user, foreign, "login_success", base + timedelta(minutes=10), asset),
    ]
    for i in range(random.randint(25, 60)):
        evts.append(RawEvent(
            source="microsoft_365", timestamp=base + timedelta(minutes=12, seconds=i * 7),
            category="file", action="file_download", actor_username=user,
            country=foreign, city=GEO[foreign][0], target_asset=asset, severity=2,
            raw={"file": f"confidential_{i}.xlsx", "size_kb": random.randint(200, 9000)},
        ))
    return evts


def scenario_ransomware(user: str | None = None) -> list[RawEvent]:
    """Mass file-encrypt activity on an endpoint + EDR detection."""
    user = user or random.choice([u["username"] for u in DEMO_USERS])
    asset = random.choice([a["name"] for a in DEMO_ASSETS if a["asset_type"] in ("endpoint", "server")])
    base = _now() - timedelta(minutes=random.randint(5, 40))
    evts = [RawEvent(
        source="crowdstrike", timestamp=base, category="process", action="process_start",
        actor_username=user, target_asset=asset, severity=3,
        raw={"process": "vssadmin.exe", "cmdline": "delete shadows /all /quiet"},
    )]
    for i in range(random.randint(40, 120)):
        evts.append(RawEvent(
            source="microsoft_defender", timestamp=base + timedelta(seconds=i * 2),
            category="file", action="file_rename", actor_username=user, target_asset=asset, severity=3,
            raw={"from": f"report_{i}.docx", "to": f"report_{i}.docx.lockbit"},
        ))
    evts.append(RawEvent(
        source="microsoft_defender", timestamp=base + timedelta(minutes=4), category="alert",
        action="malware_detected", actor_username=user, target_asset=asset, severity=5,
        raw={"signature": "Ransom:Win32/LockBit", "verdict": "blocked_partial"},
    ))
    return evts


def scenario_data_exfiltration(user: str | None = None) -> list[RawEvent]:
    """Bulk internal download followed by upload to an external destination."""
    user = user or random.choice([u["username"] for u in DEMO_USERS])
    home = user_home(user)
    asset = random.choice([a["name"] for a in DEMO_ASSETS if a["sensitivity"] >= 4])
    base = _now() - timedelta(minutes=random.randint(10, 60))
    evts = []
    for i in range(random.randint(30, 80)):
        evts.append(RawEvent(
            source="google_workspace", timestamp=base + timedelta(seconds=i * 5),
            category="file", action="file_download", actor_username=user, country=home,
            city=GEO[home][0], target_asset=asset, severity=2,
            raw={"file": f"customer_db_part{i}.csv", "size_kb": random.randint(1000, 50000)},
        ))
    evts.append(RawEvent(
        source="cloudflare", timestamp=base + timedelta(minutes=12), category="network",
        action="large_upload", actor_username=user, country=home, city=GEO[home][0],
        target_asset=asset, severity=4,
        raw={"destination": "mega.nz", "bytes": random.randint(500_000_000, 4_000_000_000)},
    ))
    return evts


def scenario_anomalous_privileged(user: str | None = None) -> list[RawEvent]:
    """Privileged/service account behaving abnormally at odd hours."""
    user = user or random.choice([u["username"] for u in DEMO_USERS if u["is_privileged"]])
    home = user_home(user)
    base = _now() - timedelta(minutes=random.randint(5, 60))
    asset = random.choice([a["name"] for a in DEMO_ASSETS if a["sensitivity"] >= 4])
    evts = [
        _login("aws", user, home, "login_success", base, asset),
        RawEvent(source="aws", timestamp=base + timedelta(minutes=2), category="process",
                 action="privilege_escalation", actor_username=user, target_asset=asset, severity=4,
                 raw={"role": "AdministratorAccess", "via": "AssumeRole", "hour_local": "03:00"}),
        RawEvent(source="aws", timestamp=base + timedelta(minutes=5), category="file",
                 action="config_change", actor_username=user, target_asset=asset, severity=3,
                 raw={"change": "disabled_cloudtrail"}),
    ]
    return evts


SCENARIOS = {
    "account_takeover": scenario_account_takeover,
    "ransomware": scenario_ransomware,
    "data_exfiltration": scenario_data_exfiltration,
    "anomalous_privileged": scenario_anomalous_privileged,
}


def generate_scenario(name: str, user: str | None = None) -> list[RawEvent]:
    if name not in SCENARIOS:
        raise ValueError(f"unknown scenario: {name}")
    return SCENARIOS[name](user)


def random_scenario() -> list[RawEvent]:
    return generate_scenario(random.choice(list(SCENARIOS)))


def load_external_scenarios() -> list[dict]:
    """Load any user-provided attack-model definitions from data/attack_models/.

    Supports a simple JSON format: a list of {"source","action","category",...}
    event dicts grouped under a "scenario" name. Returns [] if the folder/files
    are absent so the platform still runs on built-ins.
    """
    out: list[dict] = []
    if not ATTACK_MODELS_DIR.exists():
        return out
    for path in sorted(ATTACK_MODELS_DIR.glob("*.json")):
        try:
            out.append({"file": path.name, "data": json.loads(path.read_text())})
        except (json.JSONDecodeError, OSError):
            continue
    return out
