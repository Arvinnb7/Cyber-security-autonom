"""Live Microsoft 365 / Azure AD connector via Microsoft Graph.

Requires an Azure AD app registration (client credentials) with the application
permission ``AuditLog.Read.All`` (admin-consented). Pulls recent sign-in logs and
directory audit events and maps them to the canonical RawEvent schema so the
detection engine works on real tenant data.
"""
from __future__ import annotations

import secrets as _secrets
from datetime import datetime, timezone

import httpx

from app.connectors.base import ActionResult, RawEvent
from app.connectors.real.base import ConnectorError, RealConnector

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
TIMEOUT = 20.0


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

    def _token(self) -> str:
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
                    "scope": "https://graph.microsoft.com/.default",
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
