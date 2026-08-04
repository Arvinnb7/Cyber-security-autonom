"""Phase 8: Defender telemetry makes malware, ransomware, phishing and lateral
movement detectable on real data.

The mapping is a *contract* with ``app/detection/detectors.py``: an action name
or raw flag that is nearly right produces a detection that silently never fires —
exactly the bug this phase exists to fix. So these tests assert the canonical
names, and then prove end-to-end that the detections actually fire.
"""
from __future__ import annotations

from datetime import timedelta

from app.connectors.real.defender import MicrosoftDefenderConnector
from app.connectors.real.factory import is_implemented
from app.core.time import utcnow
from app.detection.catalog import seed_catalog
from app.detection.detectors import run_detectors
from app.ingestion.pipeline import ingest_raw_events
from app.models.tables import Asset, User


class _Resp:
    def __init__(self, status, payload=None, text=""):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        return self._payload


def _connector() -> MicrosoftDefenderConnector:
    return MicrosoftDefenderConnector({"tenant_id": "t", "client_id": "c"}, {"client_secret": "s"})


def _hunting(rows_by_table: dict[str, list[dict]]):
    """Fake Graph transport: token, alerts, and per-table hunting results."""
    def fake_post(url, **kw):
        if "oauth2" in url:
            return _Resp(200, {"access_token": "tok"})
        query = (kw.get("json") or {}).get("Query", "")
        for table, rows in rows_by_table.items():
            if query.startswith(table):
                return _Resp(200, {"results": rows})
        return _Resp(200, {"results": []})

    def fake_get(url, **kw):
        return _Resp(200, {"value": rows_by_table.get("__alerts__", [])})

    return fake_post, fake_get


# --- registration ---------------------------------------------------------

def test_defender_is_a_real_connector():
    assert is_implemented("microsoft_defender")


# --- alert mapping (DET-004 / DET-005) ------------------------------------

def test_alert_maps_to_malware_detected_with_signature(patch_graph_http):
    post, get = _hunting({"__alerts__": [{
        "id": "a1", "title": "Ransom:Win32/Conti.A!dha", "severity": "high",
        "createdDateTime": "2026-06-20T03:00:00Z", "category": "Ransomware",
        "evidence": [{"deviceDnsName": "ws-finance-01", "sha256": "abc123"},
                     {"userAccount": {"userPrincipalName": "bob@corp.com"}}],
    }]})
    patch_graph_http(post=post, get=get)
    events = _connector().fetch_events()
    malware = [e for e in events if e.action == "malware_detected"]
    assert malware, "Defender alert was not mapped to malware_detected"
    e = malware[0]
    assert e.target_asset == "ws-finance-01"
    assert e.actor_username == "bob@corp.com"
    assert e.raw["hash_match"] is True
    # DET-005 keys known_ransomware_tool off "Ransom" appearing in the signature.
    assert "Ransom" in e.raw["signature"]


# --- hunting mappings -----------------------------------------------------

def test_email_maps_to_phishing_flags(patch_graph_http):
    post, get = _hunting({"EmailEvents": [{
        "Timestamp": "2026-06-20T03:00:00Z", "SenderFromDomain": "c0rp-secure.com",
        "SenderFromAddress": "it@c0rp-secure.com", "RecipientEmailAddress": "alice@corp.com",
        "Subject": "Urgent: verify your password now", "ThreatTypes": "Phish,Spoof",
        "DetectionMethods": "Impersonation", "AttachmentCount": 1, "UrlCount": 2,
        "AuthenticationDetails": "SPF:fail;DMARC:fail", "SenderIPv4": "9.9.9.9",
    }]})
    patch_graph_http(post=post, get=get)
    mail = [e for e in _connector().fetch_events() if e.action == "email_received"]
    assert mail, "EmailEvents was not mapped to email_received"
    raw = mail[0].raw
    # Exactly the keys det_phishing reads.
    assert raw["sender_domain"] == "c0rp-secure.com"
    assert raw["malicious_url"] is True
    assert raw["attachment"] is True
    assert raw["lookalike_domain"] is True
    assert raw["auth_fail"] is True
    assert raw["cred_keywords"] is True


def test_benign_email_sets_no_phishing_flags(patch_graph_http):
    post, get = _hunting({"EmailEvents": [{
        "Timestamp": "2026-06-20T03:00:00Z", "SenderFromDomain": "partner.com",
        "RecipientEmailAddress": "alice@corp.com", "Subject": "Lunch tomorrow?",
        "ThreatTypes": "", "DetectionMethods": "", "AttachmentCount": 0,
        "UrlCount": 0, "AuthenticationDetails": "SPF:pass;DMARC:pass",
    }]})
    patch_graph_http(post=post, get=get)
    raw = [e for e in _connector().fetch_events() if e.action == "email_received"][0].raw
    assert not raw["malicious_url"] and not raw["attachment"]
    assert not raw["lookalike_domain"] and not raw["auth_fail"] and not raw["cred_keywords"]


def test_process_maps_to_process_start_with_malware_flags(patch_graph_http):
    post, get = _hunting({"DeviceProcessEvents": [{
        "Timestamp": "2026-06-20T03:00:00Z", "DeviceName": "ws-01",
        "AccountName": "SYSTEM", "FileName": "powershell.exe",
        "ProcessCommandLine": "powershell.exe -enc SQBFAFgA -w hidden", "SHA256": "",
    }]})
    patch_graph_http(post=post, get=get)
    procs = [e for e in _connector().fetch_events() if e.action == "process_start"]
    assert procs
    raw = procs[0].raw
    assert raw["powershell_suspicious"] is True
    assert raw["privileged"] is True
    assert raw["unknown_hash"] is True


def test_remote_exec_tooling_is_separated(patch_graph_http):
    post, get = _hunting({"DeviceProcessEvents": [{
        "Timestamp": "2026-06-20T03:00:00Z", "DeviceName": "srv-01",
        "AccountName": "svc", "FileName": "PsExec.exe",
        "ProcessCommandLine": "psexec \\\\srv-02 cmd", "SHA256": "d1",
    }]})
    patch_graph_http(post=post, get=get)
    assert any(e.action == "remote_exec" for e in _connector().fetch_events())


def test_shadow_copy_and_tamper_map_to_their_actions(patch_graph_http):
    post, get = _hunting({"DeviceEvents": [
        {"Timestamp": "2026-06-20T03:00:00Z", "DeviceName": "ws-01",
         "AccountName": "u", "ActionType": "ShadowCopyDeleted"},
        {"Timestamp": "2026-06-20T03:01:00Z", "DeviceName": "ws-01",
         "AccountName": "u", "ActionType": "AntivirusDisabled"},
    ]})
    patch_graph_http(post=post, get=get)
    actions = {e.action for e in _connector().fetch_events()}
    assert "shadow_copy_delete" in actions
    assert "security_control_disabled" in actions


def test_file_rename_flags_network_share(patch_graph_http):
    post, get = _hunting({"DeviceFileEvents": [{
        "Timestamp": "2026-06-20T03:00:00Z", "DeviceName": "ws-01", "AccountName": "u",
        "ActionType": "FileRenamed", "FileName": "report.xlsx.locked",
        "FolderPath": "\\\\fileserver\\finance",
    }]})
    patch_graph_http(post=post, get=get)
    renames = [e for e in _connector().fetch_events() if e.action == "file_rename"]
    assert renames and renames[0].raw["network_share"] is True


def test_remote_logon_flags_admin_protocol(patch_graph_http):
    post, get = _hunting({"DeviceLogonEvents": [{
        "Timestamp": "2026-06-20T03:00:00Z", "DeviceName": "srv-01", "AccountName": "svc",
        "LogonType": "RemoteInteractive", "RemoteDeviceName": "ws-01", "RemoteIP": "10.0.0.5",
    }]})
    patch_graph_http(post=post, get=get)
    logons = [e for e in _connector().fetch_events() if e.action == "remote_login"]
    assert logons and logons[0].raw["admin_protocol"] is True


def test_missing_permission_degrades_instead_of_failing(patch_graph_http):
    """A tenant without Advanced Hunting must still yield alerts."""
    def post(url, **kw):
        if "oauth2" in url:
            return _Resp(200, {"access_token": "tok"})
        return _Resp(403, text="forbidden")

    def get(url, **kw):
        return _Resp(200, {"value": [{
            "id": "a1", "title": "Trojan:Win32/Emotet", "severity": "high",
            "createdDateTime": "2026-06-20T03:00:00Z",
            "evidence": [{"deviceDnsName": "ws-01"}],
        }]})

    patch_graph_http(post=post, get=get)
    events = _connector().fetch_events()
    assert any(e.action == "malware_detected" for e in events), "alerts lost when hunting is denied"


# --- the proof: detections fire on Defender-shaped data -------------------

def _seed_subjects(session, device="ws-finance-01", user="mallory@corp.com"):
    seed_catalog(session)
    session.add(Asset(name=device, asset_type="endpoint", sensitivity=4, origin="demo"))
    session.add(User(username=user, display_name=user, origin="demo"))
    session.commit()


def test_det004_malware_fires_on_defender_data(session, patch_graph_http):
    """No simulator flags anywhere — this is Defender-shaped telemetry only."""
    _seed_subjects(session)
    post, get = _hunting({
        "__alerts__": [{
            "id": "a1", "title": "Trojan:Win32/Emotet.RA", "severity": "high",
            "createdDateTime": utcnow().isoformat() + "Z",
            "evidence": [{"deviceDnsName": "ws-finance-01", "sha256": "abc"}],
        }],
        "DeviceProcessEvents": [{
            "Timestamp": utcnow().isoformat() + "Z", "DeviceName": "ws-finance-01",
            "AccountName": "SYSTEM", "FileName": "powershell.exe",
            "ProcessCommandLine": "powershell -enc ZQBjAGgAbwA -w hidden", "SHA256": "",
        }],
    })
    patch_graph_http(post=post, get=get)
    ingest_raw_events(session, _connector().fetch_events())
    signals = run_detectors(session)
    assert any(s.det_id == "DET-004" for s in signals), \
        f"DET-004 did not fire on Defender data; got {[s.det_id for s in signals]}"


def test_det005_ransomware_fires_on_defender_data(session, patch_graph_http):
    _seed_subjects(session)
    now = utcnow()
    renames = [{
        "Timestamp": (now - timedelta(seconds=i)).isoformat() + "Z",
        "DeviceName": "ws-finance-01", "AccountName": "mallory@corp.com",
        "ActionType": "FileRenamed", "FileName": f"doc{i}.xlsx.locked",
        "FolderPath": "\\\\fileserver\\finance",
    } for i in range(40)]
    post, get = _hunting({
        "__alerts__": [{
            "id": "a2", "title": "Ransom:Win32/Conti", "severity": "high",
            "createdDateTime": now.isoformat() + "Z",
            "evidence": [{"deviceDnsName": "ws-finance-01"}],
        }],
        "DeviceFileEvents": renames,
        "DeviceEvents": [{"Timestamp": now.isoformat() + "Z", "DeviceName": "ws-finance-01",
                          "AccountName": "mallory@corp.com", "ActionType": "ShadowCopyDeleted"}],
    })
    patch_graph_http(post=post, get=get)
    ingest_raw_events(session, _connector().fetch_events())
    signals = run_detectors(session)
    det5 = [s for s in signals if s.det_id == "DET-005"]
    assert det5, f"DET-005 did not fire; got {[s.det_id for s in signals]}"
    factors = det5[0].matched_factors
    assert "mass_file_modification" in factors
    assert "shadow_copy_deletion" in factors
    assert "known_ransomware_tool" in factors


def test_det003_phishing_fires_on_defender_data(session, patch_graph_http):
    seed_catalog(session)
    now = utcnow()
    campaign = [{
        "Timestamp": now.isoformat() + "Z", "SenderFromDomain": "c0rp-secure.com",
        "SenderFromAddress": "it@c0rp-secure.com",
        "RecipientEmailAddress": f"victim{i}@corp.com",
        "Subject": "Urgent: verify your account password", "ThreatTypes": "Phish,Spoof",
        "DetectionMethods": "Impersonation", "AttachmentCount": 1, "UrlCount": 3,
        "AuthenticationDetails": "SPF:fail", "SenderIPv4": "9.9.9.9",
    } for i in range(8)]
    post, get = _hunting({"EmailEvents": campaign})
    patch_graph_http(post=post, get=get)
    ingest_raw_events(session, _connector().fetch_events())
    signals = run_detectors(session)
    det3 = [s for s in signals if s.det_id == "DET-003"]
    assert det3, f"DET-003 did not fire; got {[s.det_id for s in signals]}"
    factors = det3[0].matched_factors
    assert "malicious_url" in factors
    assert "mass_recipient_count" in factors


def test_det009_lateral_movement_fires_on_defender_data(session, patch_graph_http):
    seed_catalog(session)
    now = utcnow()
    logons = [{
        "Timestamp": now.isoformat() + "Z", "DeviceName": f"srv-{i:02d}",
        "AccountName": "svc-backup", "LogonType": "RemoteInteractive",
        "RemoteDeviceName": "ws-01", "RemoteIP": "10.0.0.5",
    } for i in range(4)]
    post, get = _hunting({
        "DeviceLogonEvents": logons,
        "DeviceProcessEvents": [{
            "Timestamp": now.isoformat() + "Z", "DeviceName": "srv-01",
            "AccountName": "svc-backup", "FileName": "PsExec.exe",
            "ProcessCommandLine": "psexec \\\\srv-02 cmd", "SHA256": "d1",
        }],
    })
    patch_graph_http(post=post, get=get)
    ingest_raw_events(session, _connector().fetch_events())
    signals = run_detectors(session)
    assert any(s.det_id == "DET-009" for s in signals), \
        f"DET-009 did not fire; got {[s.det_id for s in signals]}"


# --- host isolation -------------------------------------------------------

def test_isolate_host_calls_defender(patch_graph_http):
    calls = {}

    def post(url, **kw):
        return _Resp(200, {"access_token": "tok"})

    def request(method, url, **kw):
        calls["method"], calls["url"], calls["json"] = method, url, kw.get("json")
        return _Resp(201)

    patch_graph_http(post=post, request=request)
    result = _connector().execute_action("isolate_host", "ws-finance-01")
    assert result.success, result.detail
    assert calls["method"] == "POST"
    assert calls["url"].endswith("security/machines/ws-finance-01/isolate")


def test_isolate_host_reports_missing_permission(patch_graph_http):
    patch_graph_http(post=lambda url, **kw: _Resp(200, {"access_token": "tok"}),
                     request=lambda method, url, **kw: _Resp(403, text="denied"))
    result = _connector().execute_action("isolate_host", "ws-01")
    assert not result.success and "Machine.Isolate" in result.detail


def test_defender_rejects_unsupported_action():
    assert not _connector().execute_action("block_user", "x").success


def test_isolate_host_blocked_without_allow_actions(session, monkeypatch):
    """The Phase-2 safety guard must cover the new action too."""
    monkeypatch.setattr("app.core.runtime.current_mode", lambda: "live")
    monkeypatch.setattr("app.core.runtime.is_live", lambda: True)
    from app.models.tables import Connection
    from app.response.actions import approve_action, request_action

    session.add(Connection(provider="microsoft_defender", enabled=True, allow_actions=False))
    session.commit()
    action = request_action(session, "isolate_host", "ws-01", requested_by="analyst")
    resolved = approve_action(session, action.id, approved_by="admin")
    assert resolved.status == "blocked"
    assert "automated response" in resolved.result.lower()
