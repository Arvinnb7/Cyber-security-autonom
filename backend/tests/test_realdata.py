"""Phase 3: detection works on REAL-shaped data (learned baselines, not hardcoded
demo assumptions) and live-mode auto-provisions users/assets for scoring."""
from __future__ import annotations

import types
from datetime import timedelta

from sqlmodel import select

from app.connectors.base import RawEvent
from app.core.time import utcnow
from app.detection.baseline import Baselines
from app.detection.detectors import run_detectors
from app.ingestion.pipeline import ingest_raw_events
from app.models.tables import Asset, User


def _login(user: str, country: str, ts, device: str = "known-laptop") -> RawEvent:
    # Real-shaped M365 sign-in: NO demo hints (no "home"/"off_hours"/"risky_ip").
    return RawEvent(source="microsoft_365", timestamp=ts, category="authentication",
                    action="login_success", actor_username=user, country=country, city=country,
                    src_ip="203.0.113.10", raw={"device_id": device})


def test_baseline_learns_home_country_per_org(session):
    user = "carol@corp.de"
    now = utcnow()
    # A German org: 9 historical logins from DE — nothing Iranian anywhere.
    ingest_raw_events(session, [_login(user, "DE", now - timedelta(days=d)) for d in range(1, 10)])
    bl = Baselines(session, "demo").for_user(user)
    assert bl.established
    assert "DE" in bl.home_countries
    assert bl.is_new_country("RU")        # deviation from learned normal
    assert not bl.is_new_country("DE")     # normal — not flagged


def test_det001_fires_on_real_shaped_data(session):
    """The core proof: impossible-travel + new-country detected on realistic M365
    events with a learned baseline — no `IR` hardcode, no simulator raw flags."""
    user = "alice@corp.com"
    now = utcnow()
    # Establish baseline: 10 logins from the US.
    ingest_raw_events(session, [_login(user, "US", now - timedelta(days=d)) for d in range(1, 11)])
    # Then a US login immediately followed by a Moscow login (impossible travel).
    base = now - timedelta(minutes=25)
    ingest_raw_events(session, [_login(user, "US", base),
                                _login(user, "RU", base + timedelta(minutes=10))])
    signals = run_detectors(session)
    det1 = [s for s in signals if s.det_id == "DET-001"]
    assert det1, f"DET-001 did not fire on real-shaped data; got {[s.det_id for s in signals]}"
    factors = det1[0].matched_factors
    assert "new_country" in factors
    assert "impossible_travel" in factors


def test_no_false_positive_before_baseline_established(session):
    """With too little history, a single foreign login is NOT flagged as new-country
    (avoids false positives on day one)."""
    user = "dan@corp.com"
    now = utcnow()
    ingest_raw_events(session, [_login(user, "US", now - timedelta(minutes=30)),
                                _login(user, "GB", now - timedelta(minutes=10))])
    bl = Baselines(session, "demo").for_user(user)
    assert not bl.established
    assert not bl.is_new_country("GB")     # not enough history to judge


def test_live_ingest_provisions_users_and_assets(session, monkeypatch):
    monkeypatch.setattr("app.core.runtime.current_mode", lambda: "live")
    ev = RawEvent(source="microsoft_365", category="authentication", action="login_success",
                  actor_username="bob@corp.com", country="US", target_asset="sharepoint-hr")
    ingest_raw_events(session, [ev])
    user = session.exec(select(User).where(User.username == "bob@corp.com")).first()
    asset = session.exec(select(Asset).where(Asset.name == "sharepoint-hr")).first()
    assert user is not None and user.origin == "live"
    assert asset is not None and asset.origin == "live"


class _Resp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


def test_m365_management_activity_maps_file_download(patch_graph_http):
    """Real M365 SharePoint file activity is mapped to the canonical `file_download`
    action the detectors understand (mocked; needs real-tenant validation)."""
    import app.connectors.real.microsoft365 as m

    def fake_post(url, **kw):
        return _Resp(200, {"access_token": "tok"})

    def fake_request(method, url, **kw):
        if "subscriptions/start" in url:
            return _Resp(202, {})
        if "subscriptions/content" in url:
            return _Resp(200, [{"contentUri": "https://blob/1"}])
        return _Resp(200, [{
            "Operation": "FileDownloaded", "UserId": "alice@corp.com",
            "CreationTime": "2026-06-20T03:00:00Z", "Workload": "SharePoint",
            "ClientIP": "9.9.9.9", "SourceFileName": "customers.xlsx",
        }])

    patch_graph_http(post=fake_post, request=fake_request)
    conn = m.Microsoft365Connector({"tenant_id": "t", "client_id": "c"}, {"client_secret": "s"})
    events = conn._management_activity()
    downloads = [e for e in events if e.action == "file_download"]
    assert downloads, "SharePoint FileDownloaded was not mapped to file_download"
    assert downloads[0].actor_username == "alice@corp.com"
    assert downloads[0].raw["file"] == "customers.xlsx"


# --- Phase 8: mappings that were nearly right, and so never fired ---------
# Each of these emitted a semantically adjacent action under the wrong name,
# which meant the corresponding detection could never trigger on real M365 data.

def _mgmt(records, table="sharepoint"):
    """Fake Graph + Management API transport returning one activity blob."""
    def fake_post(url, **kw):
        return _Resp(200, {"access_token": "tok"})

    def fake_request(method, url, **kw):
        if "subscriptions/start" in url:
            return _Resp(202, {})
        if "subscriptions/content" in url:
            wanted = "SharePoint" if table == "sharepoint" else "Exchange"
            return _Resp(200, [{"contentUri": "https://blob/1"}] if wanted in url else [])
        return _Resp(200, records)

    return fake_post, fake_request


def test_bulk_upload_maps_to_large_upload(patch_graph_http):
    """DET-006 reads `large_upload`; the connector used to emit only `file_upload`."""
    import app.connectors.real.microsoft365 as m

    post, request = _mgmt([{
        "Operation": "FileUploaded", "UserId": "mallory@corp.com",
        "CreationTime": "2026-06-20T03:00:00Z", "Workload": "SharePoint",
        "SourceFileName": "customer-db.zip", "SourceFileSize": 80 * 1024 * 1024,
    }])
    patch_graph_http(post=post, request=request)
    conn = m.Microsoft365Connector({"tenant_id": "t", "client_id": "c"}, {"client_secret": "s"})
    events = conn._management_activity()
    assert any(e.action == "large_upload" for e in events), \
        f"bulk upload not mapped to large_upload; got {[e.action for e in events]}"


def test_upload_to_guest_is_flagged_external(patch_graph_http):
    import app.connectors.real.microsoft365 as m

    post, request = _mgmt([{
        "Operation": "FileUploaded", "UserId": "mallory@corp.com",
        "CreationTime": "2026-06-20T03:00:00Z", "Workload": "SharePoint",
        "SourceFileName": "notes.docx", "SourceFileSize": 1024,
        "TargetUserOrGroupType": "Guest",
    }])
    patch_graph_http(post=post, request=request)
    conn = m.Microsoft365Connector({"tenant_id": "t", "client_id": "c"}, {"client_secret": "s"})
    uploads = [e for e in conn._management_activity() if e.action == "large_upload"]
    assert uploads and uploads[0].raw["external"] is True


def test_ordinary_upload_stays_file_upload(patch_graph_http):
    """Regression guard: a normal save must not look like exfiltration."""
    import app.connectors.real.microsoft365 as m

    post, request = _mgmt([{
        "Operation": "FileUploaded", "UserId": "alice@corp.com",
        "CreationTime": "2026-06-20T03:00:00Z", "Workload": "SharePoint",
        "SourceFileName": "memo.docx", "SourceFileSize": 40 * 1024,
    }])
    patch_graph_http(post=post, request=request)
    conn = m.Microsoft365Connector({"tenant_id": "t", "client_id": "c"}, {"client_secret": "s"})
    assert [e.action for e in conn._management_activity()] == ["file_upload"]


def _audit(activity: str, patch):
    import app.connectors.real.microsoft365 as m

    def fake_post(url, **kw):
        return _Resp(200, {"access_token": "tok"})

    def fake_get(url, **kw):
        if "directoryAudits" in url:
            return _Resp(200, {"value": [{
                "activityDisplayName": activity, "activityDateTime": "2026-06-20T03:00:00Z",
                "category": "RoleManagement",
                "initiatedBy": {"user": {"userPrincipalName": "mallory@corp.com"}},
            }]})
        return _Resp(200, {"value": []})

    patch(post=fake_post, get=fake_get)
    conn = m.Microsoft365Connector({"tenant_id": "t", "client_id": "c",
                                    "pull_activity": False}, {"client_secret": "s"})
    return conn.fetch_events()


def test_role_addition_maps_to_group_add_admin(patch_graph_http):
    """DET-010 reads `group_add_admin`; this used to arrive as admin_create_user."""
    actions = {e.action for e in _audit("Add member to role", patch_graph_http)}
    assert "group_add_admin" in actions, actions


def test_role_update_maps_to_role_change_admin(patch_graph_http):
    actions = {e.action for e in _audit("Update role assignment", patch_graph_http)}
    assert "role_change_admin" in actions, actions


def test_mfa_policy_change_emits_both_actions(patch_graph_http):
    """DET-002 tests the `mfa_disabled` action; DET-008 reads config_change."""
    actions = {e.action for e in _audit("Update authentication methods policy", patch_graph_http)}
    assert "mfa_disabled" in actions, actions
    assert "config_change" in actions, actions
