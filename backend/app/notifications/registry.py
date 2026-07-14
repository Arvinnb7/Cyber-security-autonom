"""Catalog of notification channel kinds and the fields each one needs.

The frontend renders the "Add channel" form from this, and the backend
validates/stores credentials against it — the same pattern used for connector
providers in ``app/connectors/registry.py``. Secret fields (SMTP password,
webhook URL) are stored encrypted and never returned by the API.
"""
from __future__ import annotations

from typing import Any

# field: {key, label, secret, placeholder?}
CHANNELS: dict[str, dict[str, Any]] = {
    "email": {
        "label": "Email (SMTP)",
        "doc": "Send alerts by email through your SMTP server (works everywhere).",
        "fields": [
            {"key": "host", "label": "SMTP Host", "secret": False, "placeholder": "smtp.example.com"},
            {"key": "port", "label": "Port", "secret": False, "placeholder": "587"},
            {"key": "from_addr", "label": "From address", "secret": False, "placeholder": "sentinel@example.com"},
            {"key": "to_addrs", "label": "Recipients (comma-separated)", "secret": False,
             "placeholder": "soc@example.com, ciso@example.com"},
            {"key": "use_tls", "label": "Use STARTTLS", "secret": False, "placeholder": "true"},
            {"key": "username", "label": "SMTP Username", "secret": True},
            {"key": "password", "label": "SMTP Password", "secret": True},
        ],
    },
    "teams": {
        "label": "Microsoft Teams",
        "doc": "Post alerts to a Teams channel via an Incoming Webhook.",
        "fields": [
            {"key": "webhook_url", "label": "Incoming Webhook URL", "secret": True,
             "placeholder": "https://outlook.office.com/webhook/..."},
        ],
    },
    "slack": {
        "label": "Slack",
        "doc": "Post alerts to a Slack channel via an Incoming Webhook.",
        "fields": [
            {"key": "webhook_url", "label": "Incoming Webhook URL", "secret": True,
             "placeholder": "https://hooks.slack.com/services/..."},
        ],
    },
}


def channel_meta(kind: str) -> dict | None:
    return CHANNELS.get(kind)


def secret_keys(kind: str) -> set[str]:
    meta = CHANNELS.get(kind, {})
    return {f["key"] for f in meta.get("fields", []) if f.get("secret")}


def split_credentials(kind: str, credentials: dict) -> tuple[dict, dict]:
    """Split a submitted dict into (public_config, secrets)."""
    secrets_set = secret_keys(kind)
    public = {k: v for k, v in credentials.items() if k not in secrets_set}
    secrets = {k: v for k, v in credentials.items() if k in secrets_set and v}
    return public, secrets


def public_channels() -> list[dict]:
    return [
        {"kind": key, "label": m["label"], "doc": m["doc"], "fields": m["fields"]}
        for key, m in CHANNELS.items()
    ]
