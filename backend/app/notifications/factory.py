"""Build a channel sender from a stored NotificationChannel (mirrors the connector factory)."""
from __future__ import annotations

from app.core.crypto import decrypt_dict
from app.models.tables import NotificationChannel
from app.notifications.channels import (
    EmailSender,
    NotificationSender,
    SlackSender,
    TeamsSender,
)

_SENDERS: dict[str, type[NotificationSender]] = {
    "email": EmailSender,
    "teams": TeamsSender,
    "slack": SlackSender,
}


def is_supported(kind: str) -> bool:
    return kind in _SENDERS


def build_sender(channel: NotificationChannel) -> NotificationSender | None:
    cls = _SENDERS.get(channel.kind)
    if cls is None:
        return None
    return cls(channel.config or {}, decrypt_dict(channel.secrets_enc))
