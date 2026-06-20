"""Provider registry for org integrations.

Describes each connectable security source and the credential fields its
connection form needs. The frontend renders the "Add connection" form from this,
and the backend validates/stores credentials against it.

``implemented`` marks providers that have a real, live connector today. Others
can still be configured; their connector is a drop-in (see app/connectors/real/).
"""
from __future__ import annotations

from typing import Any

# field: {key, label, secret, placeholder?}
PROVIDERS: dict[str, dict[str, Any]] = {
    "microsoft_365": {
        "label": "Microsoft 365 / Azure AD",
        "doc": "Azure AD app registration with AuditLog.Read.All (application) permission.",
        "implemented": True,
        "fields": [
            {"key": "tenant_id", "label": "Tenant ID", "secret": False},
            {"key": "client_id", "label": "Client ID", "secret": False},
            {"key": "client_secret", "label": "Client Secret", "secret": True},
        ],
    },
    "azure": {
        "label": "Azure (Entra ID)",
        "doc": "Same Azure AD app registration as Microsoft 365 (Graph sign-in logs).",
        "implemented": True,
        "fields": [
            {"key": "tenant_id", "label": "Tenant ID", "secret": False},
            {"key": "client_id", "label": "Client ID", "secret": False},
            {"key": "client_secret", "label": "Client Secret", "secret": True},
        ],
    },
    "google_workspace": {
        "label": "Google Workspace",
        "doc": "Service account with domain-wide delegation (Reports API).",
        "implemented": False,
        "fields": [
            {"key": "customer_id", "label": "Customer ID", "secret": False},
            {"key": "delegated_admin", "label": "Delegated Admin Email", "secret": False},
            {"key": "service_account_json", "label": "Service Account JSON", "secret": True},
        ],
    },
    "microsoft_defender": {
        "label": "Microsoft Defender",
        "doc": "Azure AD app with SecurityEvents.Read.All (Graph Security API).",
        "implemented": False,
        "fields": [
            {"key": "tenant_id", "label": "Tenant ID", "secret": False},
            {"key": "client_id", "label": "Client ID", "secret": False},
            {"key": "client_secret", "label": "Client Secret", "secret": True},
        ],
    },
    "crowdstrike": {
        "label": "CrowdStrike Falcon",
        "doc": "API client with Detections:read, Hosts:read scopes.",
        "implemented": False,
        "fields": [
            {"key": "base_url", "label": "Base URL", "secret": False, "placeholder": "https://api.crowdstrike.com"},
            {"key": "client_id", "label": "Client ID", "secret": False},
            {"key": "client_secret", "label": "Client Secret", "secret": True},
        ],
    },
    "sentinelone": {
        "label": "SentinelOne",
        "doc": "Service-user API token with threat read access.",
        "implemented": False,
        "fields": [
            {"key": "base_url", "label": "Console URL", "secret": False, "placeholder": "https://xxx.sentinelone.net"},
            {"key": "api_token", "label": "API Token", "secret": True},
        ],
    },
    "cloudflare": {
        "label": "Cloudflare",
        "doc": "API token with Account Audit Logs read.",
        "implemented": False,
        "fields": [
            {"key": "account_id", "label": "Account ID", "secret": False},
            {"key": "api_token", "label": "API Token", "secret": True},
        ],
    },
    "aws": {
        "label": "AWS (CloudTrail)",
        "doc": "IAM access key with cloudtrail:LookupEvents.",
        "implemented": False,
        "fields": [
            {"key": "region", "label": "Region", "secret": False, "placeholder": "us-east-1"},
            {"key": "access_key_id", "label": "Access Key ID", "secret": False},
            {"key": "secret_access_key", "label": "Secret Access Key", "secret": True},
        ],
    },
}


def provider_meta(provider: str) -> dict | None:
    return PROVIDERS.get(provider)


def secret_keys(provider: str) -> set[str]:
    meta = PROVIDERS.get(provider, {})
    return {f["key"] for f in meta.get("fields", []) if f.get("secret")}


def split_credentials(provider: str, credentials: dict) -> tuple[dict, dict]:
    """Split a submitted credentials dict into (public_config, secrets)."""
    secrets_set = secret_keys(provider)
    public = {k: v for k, v in credentials.items() if k not in secrets_set}
    secrets = {k: v for k, v in credentials.items() if k in secrets_set and v}
    return public, secrets


def public_providers() -> list[dict]:
    return [
        {"provider": key, "label": m["label"], "doc": m["doc"],
         "implemented": m["implemented"], "fields": m["fields"]}
        for key, m in PROVIDERS.items()
    ]
