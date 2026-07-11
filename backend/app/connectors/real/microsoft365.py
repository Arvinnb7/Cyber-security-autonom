"""Live Microsoft 365 / Azure AD connector via Microsoft Graph.

Requires an Azure AD app registration (client credentials) with the application
permission ``AuditLog.Read.All`` (admin-consented). Pulls recent sign-in logs and
directory audit events and maps them to the canonical RawEvent schema so the
detection engine works on real tenant data.
"""
from __future__ import annotations

import logging
import secrets as _secrets
from datetime import datetime, timezone

import httpx

from app.connectors.base import ActionResult, RawEvent
from app.connectors.real.base import ConnectorError, RealConnector

logger = logging.getLogger("sentinel.connectors.m365")

GRAPH = "https://graph.microsoft.com/v1.0"
MANAGE = "https://manage.office.com/api/v1.0"
LOGIN = "https://login.microsoftonline.com"
TIMEOUT = 20.0

# Office 365 audit "Operation" -> canonical action the detectors understand.
_SP_OPS = {
    "FileDownloaded": "file_download",
    "FileUploaded": "file_upload",
    "FileRenamed": "file_rename",
    "FileModified": "file_rename",
    "FileAccessed": "file_open",
    "FileDeleted": "file_rename",
}
_EXO_OPS = {
    "Send": "email_send",
    "SendAs": "email_send",
    "SendOnBehalf": "email_send",
    "MailItemsAccessed": "email_received",
}


def _graph_time(cursor: str | None) -> str | None:
    """Format an ISO cursor for a Graph $filter (must end with Z)."""
    if not cursor:
        return None
    return cursor if cursor.endswith("Z") else cursor.split("+")[0] + "Z"


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        return datetime.now(timezone.utc).replace(tzinfo=None)


class Microsoft365Connector(RealConnector):
    provider = "microsoft_365"
    supported_actions = ("block_user", "kill_session", "reset_password")

    def _token(self, scope: str = "https://graph.microsoft.com/.default") -> str:
        tenant = self.config.get("tenant_id")
        client_id = self.config.get("client_id")
        secret = self.secrets.get("client_secret")
        if not (tenant and client_id and secret):
            raise ConnectorError("Missing tenant_id, client_id or client_secret")
        try:
            resp = httpx.post(
                f"{LOGIN}/{tenant}/oauth2/v2.0/token",
                data={
                    "client_id": client_id,
                    "client_secret": secret,
                    "scope": scope,
                    "grant_type": "client_credentials",
                },
                timeout=TIMEOUT,
            )
        except httpx.HTTPError as exc:
            raise ConnectorError(f"Cannot reach Microsoft login endpoint: {exc}") from exc
        if resp.status_code != 200:
            raise ConnectorError(f"Auth failed ({resp.status_code}): {resp.text[:200]}")
        token = resp.json().get("access_token")
        if not token:
            raise ConnectorError("No access_token in Microsoft response")
        return token

    def _get(self, token: str, path: str) -> list[dict]:
        try:
            resp = httpx.get(f"{GRAPH}/{path}", headers={"Authorization": f"Bearer {token}"}, timeout=TIMEOUT)
        except httpx.HTTPError as exc:
            raise ConnectorError(f"Graph request failed: {exc}") from exc
        if resp.status_code == 403:
            raise ConnectorError("Access denied — grant AuditLog.Read.All (application) and admin-consent it.")
        if resp.status_code != 200:
            raise ConnectorError(f"Graph error ({resp.status_code}): {resp.text[:200]}")
        return resp.json().get("value", [])

    def _write(self, token: str, method: str, path: str, json: dict | None = None) -> tuple[int, str]:
        try:
            resp = httpx.request(method, f"{GRAPH}/{path}",
                                 headers={"Authorization": f"Bearer {token}"}, json=json, timeout=TIMEOUT)
        except httpx.HTTPError as exc:
            raise ConnectorError(f"Graph request failed: {exc}") from exc
        return resp.status_code, resp.text

    def fetch_events(self, cursor: str | None = None) -> list[RawEvent]:
        token = self._token()
        since = _graph_time(cursor)
        events: list[RawEvent] = []
        events.extend(self._signins(token, since))
        events.extend(self._directory_audits(token, since))
        # File/email activity (Office 365 Management Activity API). Resilient: if the
        # app lacks ActivityFeed.Read or audit isn't enabled, sign-in detection still
        # works — we just skip activity this cycle.
        if self.config.get("pull_activity", True):
            try:
                events.extend(self._management_activity())
            except ConnectorError as exc:
                logger.info("m365 activity feed unavailable: %s", exc)
        return events

    def _signins(self, token: str, since: str | None = None) -> list[RawEvent]:
        out: list[RawEvent] = []
        query = "auditLogs/signIns?$top=100&$orderby=createdDateTime desc"
        if since:
            query += f"&$filter=createdDateTime gt {since}"
        for s in self._get(token, query):
            status = s.get("status", {}) or {}
            failed = status.get("errorCode", 0) not in (0, None)
            loc = s.get("location", {}) or {}
            device = s.get("deviceDetail", {}) or {}
            risk = (s.get("riskLevelDuringSignIn") or s.get("riskState") or "none")
            out.append(RawEvent(
                source=self.provider,
                timestamp=_parse_ts(s.get("createdDateTime")),
                category="authentication",
                action="login_failed" if failed else "login_success",
                actor_username=s.get("userPrincipalName"),
                src_ip=s.get("ipAddress"),
                country=loc.get("countryOrRegion"),
                city=loc.get("city"),
                target_asset=s.get("resourceDisplayName"),
                severity=3 if failed else 2,
                raw={
                    "app": s.get("appDisplayName"),
                    "client_app": s.get("clientAppUsed"),
                    "device_id": device.get("deviceId"),
                    "new_device": not device.get("isManaged", True),
                    "risky_ip": str(risk).lower() in ("high", "medium"),
                    "risk_level": risk,
                    "error_code": status.get("errorCode"),
                },
            ))
        return out

    def _directory_audits(self, token: str, since: str | None = None) -> list[RawEvent]:
        out: list[RawEvent] = []
        query = "auditLogs/directoryAudits?$top=100&$orderby=activityDateTime desc"
        if since:
            query += f"&$filter=activityDateTime gt {since}"
        for a in self._get(token, query):
            initiated = (a.get("initiatedBy", {}) or {}).get("user", {}) or {}
            activity = (a.get("activityDisplayName") or "").lower()
            action = "config_change"
            raw_extra: dict = {"activity": a.get("activityDisplayName"), "category": a.get("category")}
            if "add member to role" in activity or "add user" in activity:
                action = "admin_create_user"
            elif "update" in activity and "policy" in activity:
                action = "config_change"
                raw_extra["change"] = "mfa_disabled" if "authentication" in activity else "logging_disabled"
            elif "reset" in activity and "password" in activity:
                action = "password_changed"
            out.append(RawEvent(
                source=self.provider,
                timestamp=_parse_ts(a.get("activityDateTime")),
                category="process",
                action=action,
                actor_username=initiated.get("userPrincipalName"),
                target_asset="azure-ad",
                severity=3,
                raw=raw_extra,
            ))
        return out

    # --- file/email activity (Office 365 Management Activity API) ----------
    # Needs application permission ActivityFeed.Read and unified audit logging
    # enabled in the tenant. Validated end-to-end against a real tenant.

    def _mgmt_request(self, token: str, method: str, url: str) -> httpx.Response:
        try:
            return httpx.request(method, url, headers={"Authorization": f"Bearer {token}"}, timeout=TIMEOUT)
        except httpx.HTTPError as exc:
            raise ConnectorError(f"Management API request failed: {exc}") from exc

    def _management_activity(self, max_blobs: int = 5) -> list[RawEvent]:
        tenant = self.config.get("tenant_id")
        token = self._token("https://manage.office.com/.default")
        out: list[RawEvent] = []
        for content_type, mapper in (("Audit.SharePoint", self._map_sharepoint),
                                     ("Audit.Exchange", self._map_exchange)):
            base = f"{MANAGE}/{tenant}/activity/feed"
            # Idempotently ensure the subscription is started (ignore "already enabled").
            self._mgmt_request(token, "POST", f"{base}/subscriptions/start?contentType={content_type}")
            listing = self._mgmt_request(token, "GET", f"{base}/subscriptions/content?contentType={content_type}")
            if listing.status_code == 403:
                raise ConnectorError("Access denied — grant ActivityFeed.Read (application) for file/email activity.")
            if listing.status_code != 200:
                continue
            for blob in (listing.json() or [])[:max_blobs]:
                uri = blob.get("contentUri")
                if not uri:
                    continue
                content = self._mgmt_request(token, "GET", uri)
                if content.status_code != 200:
                    continue
                for record in content.json() or []:
                    ev = mapper(record)
                    if ev:
                        out.append(ev)
        return out

    def _map_sharepoint(self, r: dict) -> RawEvent | None:
        action = _SP_OPS.get(r.get("Operation"))
        if not action:
            return None
        return RawEvent(
            source=self.provider, timestamp=_parse_ts(r.get("CreationTime")), category="file",
            action=action, actor_username=r.get("UserId"), src_ip=r.get("ClientIP"),
            target_asset=r.get("Workload") or "sharepoint", severity=2,
            raw={"file": r.get("SourceFileName"), "object": r.get("ObjectId"), "op": r.get("Operation")},
        )

    def _map_exchange(self, r: dict) -> RawEvent | None:
        action = _EXO_OPS.get(r.get("Operation"))
        if not action:
            return None
        return RawEvent(
            source=self.provider, timestamp=_parse_ts(r.get("CreationTime")), category="email",
            action=action, actor_username=r.get("UserId"), src_ip=r.get("ClientIP"),
            target_asset="exchange-online", severity=2,
            raw={"op": r.get("Operation")},
        )

    # --- real response actions (Microsoft Graph) --------------------------

    def execute_action(self, action_type: str, target: str) -> ActionResult:
        if action_type not in self.supported_actions:
            return ActionResult(success=False, detail=f"microsoft_365 cannot perform '{action_type}'")
        if not target:
            return ActionResult(success=False, detail="no target user specified")
        token = self._token()

        if action_type == "block_user":
            code, text = self._write(token, "PATCH", f"users/{target}", {"accountEnabled": False})
            perm = "User.ReadWrite.All"
            ok_detail = f"disabled Azure AD account {target}"
        elif action_type == "kill_session":
            code, text = self._write(token, "POST", f"users/{target}/revokeSignInSessions")
            perm = "User.ReadWrite.All"
            ok_detail = f"revoked all sign-in sessions for {target}"
        else:  # reset_password
            new_pw = _secrets.token_urlsafe(16) + "Aa1!"
            code, text = self._write(token, "PATCH", f"users/{target}",
                                     {"passwordProfile": {"forceChangePasswordNextSignIn": True,
                                                          "password": new_pw}})
            perm = "User-PasswordProfile.ReadWrite.All"
            ok_detail = f"forced password reset for {target}"

        if code in (200, 204):
            return ActionResult(success=True, detail=ok_detail)
        if code == 403:
            return ActionResult(success=False,
                                detail=f"access denied — grant application permission '{perm}' and admin-consent it")
        return ActionResult(success=False, detail=f"Graph error ({code}): {text[:200]}")
