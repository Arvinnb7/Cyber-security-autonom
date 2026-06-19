"""Realistic attack scenarios covering the 10 catalog detections (F3 demo input).

Each scenario emits a chain of :class:`RawEvent` that correlates into one incident
matching a specific catalog detection (DET-001..DET-010).

>>> PLUG-IN POINT <<<
User-provided attack-model files in ``data/attack_models/`` are loaded by
``load_external_scenarios()`` to extend these built-ins.
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
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _evt(source: str, category: str, action: str, ts: datetime, **kw) -> RawEvent:
    return RawEvent(source=source, timestamp=ts, category=category, action=action,
                    actor_username=kw.pop("user", None), src_ip=kw.pop("src_ip", None),
                    country=kw.pop("country", None), city=kw.pop("city", None),
                    target_asset=kw.pop("asset", None), severity=kw.pop("severity", 2),
                    raw=kw.pop("raw", {}))


def _pick_user(privileged: bool | None = None) -> str:
    pool = [u for u in DEMO_USERS if privileged is None or u["is_privileged"] == privileged]
    return random.choice(pool)["username"]


def _asset(min_sens: int = 1, types: tuple[str, ...] | None = None) -> str:
    pool = [a for a in DEMO_ASSETS if a["sensitivity"] >= min_sens and (not types or a["asset_type"] in types)]
    return random.choice(pool or DEMO_ASSETS)["name"]


# --- DET-001 Suspicious Login --------------------------------------------

def scenario_suspicious_login(user: str | None = None) -> list[RawEvent]:
    user = user or _pick_user(privileged=False)
    home = user_home(user)
    foreign = random.choice([c for c in ("RU", "CN", "NG") if c != home])
    base = _now() - timedelta(minutes=random.randint(10, 60))
    asset = _asset(types=("saas",))
    return [
        _evt("microsoft_365", "authentication", "login_success", base, user=user, country=home,
             city=GEO[home][0], src_ip=_ip(home), raw={"home": home, "new_device": False}),
        _evt("azure", "authentication", "login_failed", base + timedelta(minutes=4), user=user,
             country=foreign, city=GEO[foreign][0], src_ip=_ip(foreign), severity=3,
             raw={"risky_ip": True}),
        _evt("microsoft_365", "authentication", "login_success", base + timedelta(minutes=6), user=user,
             country=foreign, city=GEO[foreign][0], src_ip=_ip(foreign), asset=asset, severity=3,
             raw={"home": home, "new_device": True, "risky_ip": True, "off_hours": True}),
    ]


# --- DET-002 Account Compromise ------------------------------------------

def scenario_account_compromise(user: str | None = None) -> list[RawEvent]:
    user = user or _pick_user(privileged=False)
    home = user_home(user)
    foreign = random.choice(["RU", "CN", "NG"])
    base = _now() - timedelta(minutes=random.randint(20, 80))
    asset = _asset(min_sens=4, types=("saas", "data_store"))
    evts = [
        _evt("microsoft_365", "authentication", "login_success", base, user=user, country=foreign,
             city=GEO[foreign][0], src_ip=_ip(foreign), severity=3, raw={"home": home, "new_device": True}),
        _evt("azure", "authentication", "mfa_disabled", base + timedelta(minutes=2), user=user,
             country=foreign, severity=4, raw={}),
        _evt("azure", "authentication", "password_changed", base + timedelta(minutes=3), user=user,
             country=foreign, severity=3, raw={}),
    ]
    for i in range(random.randint(20, 45)):
        evts.append(_evt("microsoft_365", "file", "file_download", base + timedelta(minutes=5, seconds=i * 6),
                         user=user, country=foreign, asset=asset,
                         raw={"file": f"confidential_{i}.xlsx", "size_kb": random.randint(200, 9000)}))
    return evts


# --- DET-003 Phishing -----------------------------------------------------

def scenario_phishing(user: str | None = None) -> list[RawEvent]:
    base = _now() - timedelta(minutes=random.randint(5, 50))
    domain = random.choice(["m1crosoft-support.com", "secure-paypa1.com", "company-it-helpdesk.net"])
    targets = random.sample([u["username"] for u in DEMO_USERS], k=random.randint(5, 7))
    raw_common = {"sender_domain": domain, "lookalike_domain": True, "malicious_url": True,
                  "attachment": random.random() > 0.4, "cred_keywords": True, "auth_fail": True}
    return [
        _evt("microsoft_365", "alert", "email_received", base + timedelta(seconds=i * 20), user=t,
             asset="exchange-online", severity=3,
             raw={**raw_common, "recipient": t, "subject": "Urgent: verify your account"})
        for i, t in enumerate(targets)
    ]


# --- DET-004 Malware Execution -------------------------------------------

def scenario_malware_execution(user: str | None = None) -> list[RawEvent]:
    user = user or _pick_user()
    asset = _asset(types=("endpoint", "server"))
    base = _now() - timedelta(minutes=random.randint(5, 40))
    return [
        _evt("crowdstrike", "process", "process_start", base, user=user, asset=asset, severity=4,
             raw={"process": "powershell.exe", "powershell_suspicious": True, "unknown_hash": True,
                  "cmdline": "-enc aQB3AHIA...", "privileged": True}),
        _evt("crowdstrike", "network", "process_start", base + timedelta(minutes=1), user=user, asset=asset,
             severity=4, raw={"process": "rundll32.exe", "bad_network": True, "tamper": True}),
        _evt("microsoft_defender", "alert", "malware_detected", base + timedelta(minutes=2), user=user,
             asset=asset, severity=5, raw={"signature": "Trojan:Win32/Emotet", "hash_match": True}),
    ]


# --- DET-005 Ransomware ---------------------------------------------------

def scenario_ransomware(user: str | None = None) -> list[RawEvent]:
    user = user or _pick_user()
    asset = _asset(types=("endpoint", "server"))
    base = _now() - timedelta(minutes=random.randint(3, 30))
    evts = [
        _evt("crowdstrike", "process", "shadow_copy_delete", base, user=user, asset=asset, severity=4,
             raw={"process": "vssadmin.exe", "cmdline": "delete shadows /all /quiet"}),
        _evt("crowdstrike", "process", "backup_tamper", base + timedelta(seconds=20), user=user, asset=asset,
             severity=4, raw={"action": "disabled_backup_agent"}),
    ]
    for i in range(random.randint(30, 90)):
        evts.append(_evt("microsoft_defender", "file", "file_rename", base + timedelta(seconds=30 + i * 2),
                         user=user, asset=asset, severity=3,
                         raw={"from": f"report_{i}.docx", "to": f"report_{i}.docx.lockbit",
                              "network_share": i % 5 == 0}))
    evts.append(_evt("microsoft_defender", "alert", "malware_detected", base + timedelta(minutes=4),
                     user=user, asset=asset, severity=5,
                     raw={"signature": "Ransom:Win32/LockBit", "hash_match": True}))
    return evts


# --- DET-006 Data Exfiltration -------------------------------------------

def scenario_data_exfiltration(user: str | None = None) -> list[RawEvent]:
    user = user or _pick_user()
    home = user_home(user)
    asset = _asset(min_sens=4)
    base = _now() - timedelta(minutes=random.randint(10, 60))
    evts = []
    for i in range(random.randint(25, 70)):
        evts.append(_evt("google_workspace", "file", "file_download", base + timedelta(seconds=i * 5),
                         user=user, country=home, asset=asset,
                         raw={"file": f"customer_db_part{i}.csv", "size_kb": random.randint(1000, 50000),
                              "off_hours": True}))
    evts.append(_evt("google_workspace", "file", "archive_create", base + timedelta(minutes=10), user=user,
                     asset=asset, severity=3, raw={"archive": "export.7z", "encrypted": True}))
    evts.append(_evt("cloudflare", "network", "large_upload", base + timedelta(minutes=12), user=user,
                     country=home, asset=asset, severity=4,
                     raw={"destination": "mega.nz", "external": True, "off_hours": True,
                          "bytes": random.randint(500_000_000, 4_000_000_000)}))
    return evts


# --- DET-007 Privilege Abuse ---------------------------------------------

def scenario_privilege_abuse(user: str | None = None) -> list[RawEvent]:
    user = user or _pick_user(privileged=True)
    asset = _asset(min_sens=4)
    base = _now() - timedelta(minutes=random.randint(5, 50))
    return [
        _evt("azure", "process", "admin_activity", base, user=user, asset=asset, severity=3,
             raw={"new_device": True, "off_hours": True}),
        _evt("azure", "process", "admin_create_user", base + timedelta(minutes=1), user=user, asset=asset,
             severity=4, raw={"new_user": "temp_admin01"}),
        _evt("azure", "process", "permission_change", base + timedelta(minutes=2), user=user, asset=asset,
             severity=4, raw={"sensitive": True, "grant": "GlobalAdmin"}),
        _evt("azure", "process", "permission_change", base + timedelta(minutes=3), user=user, asset=asset,
             severity=3, raw={"sensitive": True, "grant": "MailboxFullAccess"}),
        _evt("azure", "process", "permission_change", base + timedelta(minutes=4), user=user, asset=asset,
             severity=3, raw={"sensitive": True}),
        _evt("microsoft_defender", "alert", "security_control_disabled", base + timedelta(minutes=5),
             user=user, asset=asset, severity=4, raw={"control": "Defender_RealTimeProtection"}),
    ]


# --- DET-008 Security Configuration Changes ------------------------------

def scenario_security_config_change(user: str | None = None) -> list[RawEvent]:
    user = user or _pick_user(privileged=True)
    asset = _asset(types=("server", "saas"))
    base = _now() - timedelta(minutes=random.randint(5, 50))
    changes = ["mfa_disabled", "firewall_rule_removed", "logging_disabled", "public_exposure"]
    return [
        _evt("aws", "process", "config_change", base + timedelta(minutes=i), user=user, asset=asset,
             severity=4, raw={"change": c, "source_ip": _ip("RU")})
        for i, c in enumerate(changes)
    ]


# --- DET-009 Lateral Movement --------------------------------------------

def scenario_lateral_movement(user: str | None = None) -> list[RawEvent]:
    user = user or _pick_user()
    base = _now() - timedelta(minutes=random.randint(5, 50))
    hosts = random.sample([a["name"] for a in DEMO_ASSETS if a["asset_type"] in ("server", "endpoint")],
                          k=min(4, len([a for a in DEMO_ASSETS if a["asset_type"] in ("server", "endpoint")])))
    evts = []
    for i, host in enumerate(hosts):
        evts.append(_evt("aws", "authentication", "remote_login", base + timedelta(minutes=i * 2), user=user,
                         asset=host, severity=3,
                         raw={"shared_creds": True, "admin_protocol": True, "sensitive_server": i == 0,
                              "protocol": "WinRM"}))
    evts.append(_evt("crowdstrike", "process", "remote_exec", base + timedelta(minutes=len(hosts) * 2),
                     user=user, asset=hosts[-1], severity=4, raw={"tool": "PsExec"}))
    return evts


# --- DET-010 Privilege Escalation ----------------------------------------

def scenario_privilege_escalation(user: str | None = None) -> list[RawEvent]:
    user = user or _pick_user()
    asset = _asset(min_sens=4)
    base = _now() - timedelta(minutes=random.randint(5, 50))
    return [
        _evt("aws", "process", "privilege_escalation", base, user=user, asset=asset, severity=4,
             raw={"tool": True, "exploit": True, "cve": "CVE-2024-1234"}),
        _evt("azure", "process", "group_add_admin", base + timedelta(minutes=1), user=user, asset=asset,
             severity=4, raw={"group": "Domain Admins"}),
        _evt("azure", "process", "role_change_admin", base + timedelta(minutes=2), user=user, asset=asset,
             severity=4, raw={"role": "Owner"}),
        _evt("aws", "process", "access_key_create", base + timedelta(minutes=3), user=user, asset=asset,
             severity=3, raw={"key_id": "AKIA..."}),
        _evt("azure", "process", "permission_change", base + timedelta(minutes=4), user=user, asset=asset,
             severity=3, raw={"sensitive_granted": True}),
    ]


SCENARIOS = {
    "suspicious_login": scenario_suspicious_login,
    "account_compromise": scenario_account_compromise,
    "phishing": scenario_phishing,
    "malware_execution": scenario_malware_execution,
    "ransomware": scenario_ransomware,
    "data_exfiltration": scenario_data_exfiltration,
    "privilege_abuse": scenario_privilege_abuse,
    "security_config_change": scenario_security_config_change,
    "lateral_movement": scenario_lateral_movement,
    "privilege_escalation": scenario_privilege_escalation,
}


def generate_scenario(name: str, user: str | None = None) -> list[RawEvent]:
    if name not in SCENARIOS:
        raise ValueError(f"unknown scenario: {name}")
    return SCENARIOS[name](user)


def random_scenario() -> list[RawEvent]:
    return generate_scenario(random.choice(list(SCENARIOS)))


def load_external_scenarios() -> list[dict]:
    """Load user-provided attack-model JSON files from data/attack_models/."""
    out: list[dict] = []
    if not ATTACK_MODELS_DIR.exists():
        return out
    for path in sorted(ATTACK_MODELS_DIR.glob("*.json")):
        try:
            out.append({"file": path.name, "data": json.loads(path.read_text())})
        except (json.JSONDecodeError, OSError):
            continue
    return out
