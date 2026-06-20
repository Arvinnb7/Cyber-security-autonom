"""Live Microsoft 365 / Azure AD connector via Microsoft Graph.

Requires an Azure AD app registration (client credentials) with the application
permission ``AuditLog.Read.All`` (admin-consented). Pulls recent sign-in logs and
directory audit events and maps them to the canonical RawEvent schema so the
detection engine works on real tenant data.
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx

from app.connectors.base import RawEvent
from app.connectors.real.base import ConnectorError, RealConnector

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
TIMEOUT = 20.0


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        return datetime.now(timezone.utc).replace(tzinfo=None)


class Microsoft365Connector(RealConnector):
    provider = "microsoft_365"

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

    def fetch_events(self) -> list[RawEvent]:
        token = self._token()
        events: list[RawEvent] = []
        events.extend(self._signins(token))
        events.extend(self._directory_audits(token))
        return events

    def _signins(self, token: str) -> list[RawEvent]:
        out: list[RawEvent] = []
        for s in self._get(token, "auditLogs/signIns?$top=100&$orderby=createdDateTime desc"):
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

    def _directory_audits(self, token: str) -> list[RawEvent]:
        out: list[RawEvent] = []
        for a in self._get(token, "auditLogs/directoryAudits?$top=100&$orderby=activityDateTime desc"):
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
