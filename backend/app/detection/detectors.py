"""Threat detection engine (F3) — aligned to the MVP Detection Catalog.

Each detector maps to a catalog entry (DET-001..DET-010). When a pattern fires it
reports exactly which catalog ``scoring_factors`` matched; the scoring engine sums
those points into ``threat_score``. Detectors stay transparent and rule-based.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from sqlalchemy import or_
from sqlmodel import Session, select

from app.core import runtime
from app.core.config import settings
from app.core.time import utcnow
from app.detection.baseline import Baselines
from app.detection.catalog import get_definition
from app.detection.geo import implied_speed_kmh
from app.models.tables import Event, Signal

# Look back this far when correlating an event chain.
WINDOW_MINUTES = 180


def _recent_events(session: Session, active_users: set[str] | None = None,
                   active_assets: set[str] | None = None) -> list[Event]:
    """Events in the correlation window.

    When the caller knows which subjects were touched this cycle, the window is
    read only for them: detection then costs what the organization *did* in the
    last cycle rather than what its entire population did in three hours. Passing
    ``None`` scans everything (used by tests and manual runs).
    """
    cutoff = utcnow() - timedelta(minutes=WINDOW_MINUTES)
    query = select(Event).where(Event.timestamp >= cutoff,
                                Event.origin == runtime.current_mode())
    if active_users is not None or active_assets is not None:
        users = sorted(active_users or set())
        assets = sorted(active_assets or set())
        if not users and not assets:
            return []
        clauses = []
        if users:
            clauses.append(Event.actor_username.in_(users))
        if assets:
            clauses.append(Event.target_asset.in_(assets))
        query = query.where(or_(*clauses) if len(clauses) > 1 else clauses[0])
    return list(session.exec(query.order_by(Event.timestamp)))


def _by_user(events: list[Event]) -> dict[str, list[Event]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.actor_username:
            grouped[e.actor_username].append(e)
    return grouped


def _by_asset(events: list[Event]) -> dict[str, list[Event]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.target_asset:
            grouped[e.target_asset].append(e)
    return grouped


def _has(events: list[Event], action: str) -> bool:
    return any(e.action == action for e in events)


def _count(events: list[Event], action: str) -> int:
    return sum(1 for e in events if e.action == action)


def _flag(events: list[Event], action: str, key: str) -> bool:
    return any(e.action == action and e.raw.get(key) for e in events)


def _severity_int(points: int) -> int:
    if points >= 86:
        return 5
    if points >= 61:
        return 4
    if points >= 31:
        return 3
    if points >= 15:
        return 2
    return 1


def make_signal(det_id: str, factor_keys: set[str], *, actor: str | None, asset: str | None,
                events: list[Event], confidence: float, detail: str) -> Signal | None:
    """Build a Signal from matched catalog scoring_factors."""
    definition = get_definition(det_id)
    if not definition:
        return None
    factors: dict[str, int] = definition["scoring_factors"]
    matched = {k: factors[k] for k in factor_keys if k in factors}
    if not matched:
        return None
    points = min(sum(matched.values()), 100)
    name = definition["name_en"]
    return Signal(
        detector=det_id.lower().replace("-", "_"),
        det_id=det_id,
        threat_type=name.lower().replace(" ", "_"),
        actor_username=actor,
        target_asset=asset,
        severity=_severity_int(points),
        confidence=round(confidence, 2),
        description=f"{name}: {detail}",
        matched_factors=matched,
        event_ids=[e.id for e in events if e.id is not None],
    )


# --- DET-001 Suspicious Login --------------------------------------------

def det_suspicious_login(events: list[Event], baselines: Baselines) -> list[Signal]:
    out: list[Signal] = []
    for user, evs in _by_user(events).items():
        logins = [e for e in evs if e.action == "login_success" and e.country]
        if not logins:
            continue
        bl = baselines.for_user(user)
        keys: set[str] = set()
        # New country: judged against the user's LEARNED home countries (works for
        # any org, any country) — no hardcoded assumption.
        if any(bl.is_new_country(e.country) for e in logins):
            keys.add("new_country")
        # New device / unusual time: from the source's own hint OR the baseline.
        if _flag(evs, "login_success", "new_device") or any(bl.is_new_device(e.raw.get("device_id")) for e in logins):
            keys.add("new_device")
        if _flag(evs, "login_success", "off_hours") or any(bl.is_unusual_time(e.timestamp) for e in logins):
            keys.add("unusual_time")
        if _flag(evs, "login_success", "risky_ip") or _flag(evs, "login_failed", "risky_ip"):
            keys.add("risky_ip")
        # Impossible travel — worldwide. An unknown country yields None and is
        # skipped rather than silently scoring as "no travel".
        for a, b in zip(logins, logins[1:]):
            if a.country != b.country:
                hrs = (b.timestamp - a.timestamp).total_seconds() / 3600
                speed = implied_speed_kmh(a.country, b.country, hrs)
                if speed is not None and speed > settings.impossible_travel_kmh:
                    keys.add("impossible_travel")
        if baselines.is_privileged(user):
            keys.add("privileged_user")
        if {"new_country", "impossible_travel", "risky_ip"} & keys:
            sig = make_signal("DET-001", keys, actor=user, asset=logins[-1].target_asset,
                              events=logins, confidence=0.6 + 0.08 * len(keys),
                              detail=f"anomalous login pattern for {user} ({', '.join(sorted(keys))}).")
            if sig:
                out.append(sig)
    return out


# --- DET-002 Account Compromise ------------------------------------------

def det_account_compromise(events: list[Event], baselines: Baselines) -> list[Signal]:
    out: list[Signal] = []
    for user, evs in _by_user(events).items():
        bl = baselines.for_user(user)
        keys: set[str] = set()
        foreign_login = any(e.action == "login_success" and bl.is_new_country(e.country) for e in evs)
        if foreign_login and (_has(evs, "password_changed") or _has(evs, "mfa_disabled")):
            keys.add("suspicious_login_before_change")
        if _has(evs, "mfa_disabled"):
            keys.add("mfa_disabled")
        if _has(evs, "password_changed"):
            keys.add("password_changed")
        if _count(evs, "file_download") >= settings.mass_download_count:
            keys.add("mass_file_download")
        if _count(evs, "email_send") >= settings.email_spam_count:
            keys.add("email_spam_behavior")
        if baselines.is_privileged(user):
            keys.add("privileged_user")
        if {"mfa_disabled", "mass_file_download", "suspicious_login_before_change"} & keys and len(keys) >= 2:
            related = [e for e in evs if e.action in
                       ("login_success", "mfa_disabled", "password_changed", "file_download", "email_send")]
            sig = make_signal("DET-002", keys, actor=user, asset=None, events=related,
                              confidence=0.7 + 0.06 * len(keys),
                              detail=f"{user} shows account-takeover behaviour ({', '.join(sorted(keys))}).")
            if sig:
                out.append(sig)
    return out


# --- DET-003 Phishing -----------------------------------------------------

def det_phishing(events: list[Event], baselines: Baselines) -> list[Signal]:
    out: list[Signal] = []
    mails = [e for e in events if e.action == "email_received"]
    by_campaign: dict[str, list[Event]] = defaultdict(list)
    for e in mails:
        by_campaign[e.raw.get("sender_domain", "unknown")].append(e)
    for domain, evs in by_campaign.items():
        keys: set[str] = set()
        if any(e.raw.get("lookalike_domain") for e in evs):
            keys.add("lookalike_domain")
        if any(e.raw.get("malicious_url") for e in evs):
            keys.add("malicious_url")
        if any(e.raw.get("attachment") for e in evs):
            keys.add("suspicious_attachment")
        if len(evs) >= settings.phishing_recipient_count:
            keys.add("mass_recipient_count")
        if any(e.raw.get("cred_keywords") for e in evs):
            keys.add("credential_harvesting_keywords")
        if any(e.raw.get("auth_fail") for e in evs):
            keys.add("failed_email_authentication")
        if {"malicious_url", "lookalike_domain", "suspicious_attachment"} & keys:
            sig = make_signal("DET-003", keys, actor=None, asset="exchange-online", events=evs,
                              confidence=0.65 + 0.05 * len(keys),
                              detail=f"phishing campaign from {domain} to {len(evs)} user(s).")
            if sig:
                out.append(sig)
    return out


# --- DET-004 Malware Execution -------------------------------------------

def det_malware_execution(events: list[Event], baselines: Baselines) -> list[Signal]:
    out: list[Signal] = []
    for asset, evs in _by_asset(events).items():
        keys: set[str] = set()
        if _flag(evs, "process_start", "unknown_hash"):
            keys.add("unknown_file_hash")
        if _flag(evs, "malware_detected", "hash_match") or _has(evs, "malware_detected"):
            keys.add("malicious_hash_match")
        if _flag(evs, "process_start", "powershell_suspicious"):
            keys.add("suspicious_powershell")
        if _flag(evs, "process_start", "bad_network"):
            keys.add("malicious_network_connection")
        if _flag(evs, "process_start", "tamper"):
            keys.add("security_tool_tampering")
        if _flag(evs, "process_start", "privileged"):
            keys.add("privileged_execution")
        # Avoid double-firing with ransomware (which owns file_rename storms).
        if keys and not _has(evs, "file_rename"):
            actor = next((e.actor_username for e in evs if e.actor_username), None)
            related = [e for e in evs if e.action in ("process_start", "malware_detected")]
            sig = make_signal("DET-004", keys, actor=actor, asset=asset, events=related,
                              confidence=0.7 + 0.05 * len(keys),
                              detail=f"malicious execution on {asset} ({', '.join(sorted(keys))}).")
            if sig:
                out.append(sig)
    return out


# --- DET-005 Ransomware ---------------------------------------------------

def det_ransomware(events: list[Event], baselines: Baselines) -> list[Signal]:
    out: list[Signal] = []
    for asset, evs in _by_asset(events).items():
        renames = _count(evs, "file_rename")
        keys: set[str] = set()
        if renames >= settings.ransomware_rename_count:
            keys.add("mass_file_modification")
            keys.add("rapid_encryption_pattern")
        if _has(evs, "shadow_copy_delete"):
            keys.add("shadow_copy_deletion")
        if any(e.action == "malware_detected" and "Ransom" in str(e.raw.get("signature", "")) for e in evs):
            keys.add("known_ransomware_tool")
        if _flag(evs, "file_rename", "network_share"):
            keys.add("multiple_network_shares")
        if _has(evs, "backup_tamper"):
            keys.add("backup_tampering")
        if {"mass_file_modification", "known_ransomware_tool", "shadow_copy_deletion"} & keys:
            actor = next((e.actor_username for e in evs if e.actor_username), None)
            related = [e for e in evs if e.action in
                       ("file_rename", "shadow_copy_delete", "malware_detected", "backup_tamper")]
            sig = make_signal("DET-005", keys, actor=actor, asset=asset, events=related,
                              confidence=0.85 + 0.03 * len(keys),
                              detail=f"{asset}: {renames} rapid file renames + ransomware indicators.")
            if sig:
                out.append(sig)
    return out


# --- DET-006 Data Exfiltration -------------------------------------------

def det_data_exfiltration(events: list[Event], baselines: Baselines) -> list[Signal]:
    out: list[Signal] = []
    for user, evs in _by_user(events).items():
        keys: set[str] = set()
        if _count(evs, "file_download") >= settings.exfil_download_count:
            keys.add("large_download_volume")
            keys.add("sensitive_data_access")
        uploads = [e for e in evs if e.action == "large_upload"]
        if uploads:
            keys.add("large_upload_volume")
            if any(e.raw.get("external") for e in uploads):
                keys.add("unknown_external_service")
        if _flag(evs, "large_upload", "off_hours") or _flag(evs, "file_download", "off_hours"):
            keys.add("after_hours_transfer")
        if _has(evs, "archive_create"):
            keys.add("compressed_archive_creation")
        if "large_upload_volume" in keys and "large_download_volume" in keys:
            related = [e for e in evs if e.action in ("file_download", "large_upload", "archive_create")]
            asset = next((e.target_asset for e in related if e.target_asset), None)
            sig = make_signal("DET-006", keys, actor=user, asset=asset, events=related,
                              confidence=0.78 + 0.04 * len(keys),
                              detail=f"{user} downloaded in bulk then uploaded externally.")
            if sig:
                out.append(sig)
    return out


# --- DET-007 Privilege Abuse ---------------------------------------------

def det_privilege_abuse(events: list[Event], baselines: Baselines) -> list[Signal]:
    out: list[Signal] = []
    for user, evs in _by_user(events).items():
        keys: set[str] = set()
        if _has(evs, "admin_create_user"):
            keys.add("new_admin_user_created")
        if _flag(evs, "permission_change", "sensitive"):
            keys.add("sensitive_permission_change")
        if _flag(evs, "admin_activity", "off_hours"):
            keys.add("after_hours_admin_activity")
        if _has(evs, "security_control_disabled"):
            keys.add("security_control_disabled")
        if _flag(evs, "admin_activity", "new_device"):
            keys.add("new_device_for_admin")
        if _count(evs, "permission_change") >= settings.admin_change_count:
            keys.add("multiple_admin_changes")
        if {"new_admin_user_created", "security_control_disabled", "sensitive_permission_change"} & keys:
            related = [e for e in evs if e.action in
                       ("admin_create_user", "permission_change", "security_control_disabled", "admin_activity")]
            asset = next((e.target_asset for e in related if e.target_asset), None)
            sig = make_signal("DET-007", keys, actor=user, asset=asset, events=related,
                              confidence=0.72 + 0.05 * len(keys),
                              detail=f"{user} abused administrative access ({', '.join(sorted(keys))}).")
            if sig:
                out.append(sig)
    return out


# --- DET-008 Security Configuration Changes ------------------------------

_CONFIG_FACTOR = {
    "mfa_disabled": "mfa_disabled",
    "firewall_rule_removed": "firewall_rule_removed",
    "port_opened": "sensitive_port_opened",
    "logging_disabled": "logging_disabled",
    "backup_weakened": "backup_policy_weakened",
    "public_exposure": "public_exposure_created",
}


def det_security_config_change(events: list[Event], baselines: Baselines) -> list[Signal]:
    out: list[Signal] = []
    for asset, evs in _by_asset(events).items():
        changes = [e for e in evs if e.action == "config_change"]
        keys: set[str] = set()
        for e in changes:
            factor = _CONFIG_FACTOR.get(str(e.raw.get("change")))
            if factor:
                keys.add(factor)
        if keys:
            actor = next((e.actor_username for e in changes if e.actor_username), None)
            sig = make_signal("DET-008", keys, actor=actor, asset=asset, events=changes,
                              confidence=0.68 + 0.05 * len(keys),
                              detail=f"security posture weakened on {asset} ({', '.join(sorted(keys))}).")
            if sig:
                out.append(sig)
    return out


# --- DET-009 Lateral Movement --------------------------------------------

def det_lateral_movement(events: list[Event], baselines: Baselines) -> list[Signal]:
    out: list[Signal] = []
    for user, evs in _by_user(events).items():
        remote_logins = [e for e in evs if e.action == "remote_login"]
        hosts = {e.target_asset for e in remote_logins if e.target_asset}
        keys: set[str] = set()
        if len(hosts) >= settings.lateral_host_count:
            keys.add("multiple_hosts_accessed")
            keys.add("new_internal_access_pattern")
        if _has(evs, "remote_exec"):
            keys.add("remote_execution_detected")
        if _flag(evs, "remote_login", "shared_creds"):
            keys.add("shared_credentials")
        if _flag(evs, "remote_login", "admin_protocol"):
            keys.add("admin_protocol_abuse")
        if _flag(evs, "remote_login", "sensitive_server"):
            keys.add("sensitive_server_access")
        if {"multiple_hosts_accessed", "remote_execution_detected"} & keys:
            related = [e for e in evs if e.action in ("remote_login", "remote_exec")]
            sig = make_signal("DET-009", keys, actor=user, asset=sorted(hosts)[0] if hosts else None,
                              events=related, confidence=0.75 + 0.04 * len(keys),
                              detail=f"{user} moved laterally across {len(hosts)} hosts.")
            if sig:
                out.append(sig)
    return out


# --- DET-010 Privilege Escalation ----------------------------------------

def det_privilege_escalation(events: list[Event], baselines: Baselines) -> list[Signal]:
    out: list[Signal] = []
    for user, evs in _by_user(events).items():
        keys: set[str] = set()
        if _has(evs, "group_add_admin"):
            keys.add("added_to_admin_group")
        if _flag(evs, "privilege_escalation", "tool"):
            keys.add("privilege_escalation_tool")
        if _has(evs, "role_change_admin"):
            keys.add("role_changed_to_admin")
        if _flag(evs, "privilege_escalation", "exploit"):
            keys.add("exploit_behavior")
        if _has(evs, "access_key_create"):
            keys.add("new_access_key_created")
        if _flag(evs, "permission_change", "sensitive_granted"):
            keys.add("sensitive_permission_granted")
        if {"added_to_admin_group", "privilege_escalation_tool", "role_changed_to_admin", "exploit_behavior"} & keys:
            related = [e for e in evs if e.action in
                       ("privilege_escalation", "group_add_admin", "role_change_admin", "access_key_create",
                        "permission_change")]
            asset = next((e.target_asset for e in related if e.target_asset), None)
            sig = make_signal("DET-010", keys, actor=user, asset=asset, events=related,
                              confidence=0.78 + 0.04 * len(keys),
                              detail=f"{user} escalated privileges ({', '.join(sorted(keys))}).")
            if sig:
                out.append(sig)
    return out


DETECTORS = [
    det_suspicious_login,        # DET-001
    det_account_compromise,      # DET-002
    det_phishing,                # DET-003
    det_malware_execution,       # DET-004
    det_ransomware,              # DET-005
    det_data_exfiltration,       # DET-006
    det_privilege_abuse,         # DET-007
    det_security_config_change,  # DET-008
    det_lateral_movement,        # DET-009
    det_privilege_escalation,    # DET-010
]


def _signal_fingerprint(s: Signal) -> str:
    return f"{s.det_id}:{s.actor_username}:{s.target_asset}:{min(s.event_ids or [0])}"


def run_detectors(session: Session, active_users: set[str] | None = None,
                  active_assets: set[str] | None = None) -> list[Signal]:
    """Run all detectors over recent events, skipping already-known signals.

    ``active_users``/``active_assets`` narrow the correlation window to subjects
    touched by the current cycle; omit them to scan the whole window.
    """
    events = _recent_events(session, active_users, active_assets)
    if not events:
        return []
    baselines = Baselines(session, runtime.current_mode())
    candidates: list[Signal] = []
    for det in DETECTORS:
        candidates.extend(det(events, baselines))

    existing = session.exec(select(Signal).where(
        Signal.created_at >= utcnow() - timedelta(minutes=WINDOW_MINUTES * 2)
    ))
    seen = {_signal_fingerprint(s) for s in existing}
    mode = runtime.current_mode()
    fresh: list[Signal] = []
    for s in candidates:
        fp = _signal_fingerprint(s)
        if fp in seen:
            continue
        seen.add(fp)
        s.origin = mode
        session.add(s)
        fresh.append(s)
    session.commit()
    for s in fresh:
        session.refresh(s)
    return fresh
