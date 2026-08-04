"""Shared Microsoft Graph plumbing for Azure-backed connectors.

Microsoft 365, Entra ID and Defender all authenticate the same way (Azure AD app
registration, client-credentials flow) and speak the same REST dialect, so the
token handling and request helpers live here once rather than being copied into
each connector.

Sub-classes supply only the mapping from their vendor payloads to canonical
``RawEvent``s — which is where the real work (and the real risk of getting the
action names wrong) lives.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from app.connectors.real.base import ConnectorError, RealConnector

logger = logging.getLogger("sentinel.connectors.graph")

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
TIMEOUT = 20.0
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


def graph_time(cursor: str | None) -> str | None:
    """Format an ISO cursor for a Graph ``$filter`` (must end with Z)."""
    if not cursor:
        return None
    return cursor if cursor.endswith("Z") else cursor.split("+")[0] + "Z"


def parse_ts(value: str | None) -> datetime:
    """Parse a Graph timestamp into the naive-UTC convention used everywhere."""
    if not value:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        return datetime.now(timezone.utc).replace(tzinfo=None)


class AzureGraphConnector(RealConnector):
    """Base for connectors that talk to an Azure AD tenant via Graph."""

    #: Permission to name in the error message when Graph answers 403.
    required_permission = "the required application permission"

    def _token(self, scope: str = GRAPH_SCOPE) -> str:
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
            resp = httpx.get(f"{GRAPH}/{path}", headers={"Authorization": f"Bearer {token}"},
                             timeout=TIMEOUT)
        except httpx.HTTPError as exc:
            raise ConnectorError(f"Graph request failed: {exc}") from exc
        if resp.status_code == 403:
            raise ConnectorError(
                f"Access denied — grant {self.required_permission} (application) and admin-consent it.")
        if resp.status_code != 200:
            raise ConnectorError(f"Graph error ({resp.status_code}): {resp.text[:200]}")
        return resp.json().get("value", [])

    def _post(self, token: str, path: str, json: dict) -> dict:
        """POST to Graph and return the decoded body (used by hunting queries)."""
        try:
            resp = httpx.post(f"{GRAPH}/{path}", headers={"Authorization": f"Bearer {token}"},
                              json=json, timeout=TIMEOUT)
        except httpx.HTTPError as exc:
            raise ConnectorError(f"Graph request failed: {exc}") from exc
        if resp.status_code == 403:
            raise ConnectorError(
                f"Access denied — grant {self.required_permission} (application) and admin-consent it.")
        if resp.status_code not in (200, 201, 202):
            raise ConnectorError(f"Graph error ({resp.status_code}): {resp.text[:200]}")
        return resp.json() or {}

    def _write(self, token: str, method: str, path: str, json: dict | None = None) -> tuple[int, str]:
        try:
            resp = httpx.request(method, f"{GRAPH}/{path}",
                                 headers={"Authorization": f"Bearer {token}"}, json=json,
                                 timeout=TIMEOUT)
        except httpx.HTTPError as exc:
            raise ConnectorError(f"Graph request failed: {exc}") from exc
        return resp.status_code, resp.text
