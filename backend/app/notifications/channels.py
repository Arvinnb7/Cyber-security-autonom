"""Channel senders — turn an alert (subject, body, meta) into an actual delivery.

Each sender is built from a channel's decrypted config + secrets and exposes a
single ``send()`` that returns ``(ok, detail)`` and never raises. ``httpx`` is
imported at module level so tests can monkeypatch it (same pattern as the M365
connector).
"""
from __future__ import annotations

import abc
import smtplib
from email.message import EmailMessage

import httpx

TIMEOUT = 15.0

# incident severity -> a hex colour (no leading '#') used for card accents.
_THEME = {
    "critical": "b91c1c",
    "high": "ea580c",
    "medium": "ca8a04",
    "low": "2563eb",
}


def _colour(severity: str | None) -> str:
    return _THEME.get((severity or "").lower(), "6b7280")


def _post_webhook(url: str, payload: dict) -> tuple[bool, str]:
    try:
        resp = httpx.post(url, json=payload, timeout=TIMEOUT)
    except httpx.HTTPError as exc:
        return False, f"request failed: {exc}"
    if resp.status_code in (200, 201, 202, 204):
        return True, f"delivered ({resp.status_code})"
    return False, f"webhook error ({resp.status_code}): {resp.text[:150]}"


class NotificationSender(abc.ABC):
    kind: str = "base"

    def __init__(self, config: dict, secrets: dict):
        self.config = config or {}
        self.secrets = secrets or {}

    @abc.abstractmethod
    def send(self, subject: str, body: str, meta: dict) -> tuple[bool, str]:
        """Deliver the alert. Returns (ok, human-readable detail). Never raises."""


class EmailSender(NotificationSender):
    kind = "email"

    def send(self, subject: str, body: str, meta: dict) -> tuple[bool, str]:
        host = self.config.get("host")
        if not host:
            return False, "missing SMTP host"
        raw_to = self.config.get("to_addrs") or ""
        if isinstance(raw_to, (list, tuple)):
            raw_to = ",".join(raw_to)
        recipients = [a.strip() for a in str(raw_to).split(",") if a.strip()]
        if not recipients:
            return False, "no recipients configured"
        from_addr = self.config.get("from_addr") or self.secrets.get("username") or "sentinel@localhost"
        try:
            port = int(self.config.get("port") or 587)
        except (TypeError, ValueError):
            port = 587
        use_tls = str(self.config.get("use_tls", True)).strip().lower() not in ("false", "0", "no", "")

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(recipients)
        msg.set_content(body)
        try:
            with smtplib.SMTP(host, port, timeout=TIMEOUT) as smtp:
                if use_tls:
                    smtp.starttls()
                user = self.secrets.get("username")
                pw = self.secrets.get("password")
                if user and pw:
                    smtp.login(user, pw)
                smtp.send_message(msg)
        except Exception as exc:  # noqa: BLE001 - report any SMTP failure as a failed send
            return False, f"{type(exc).__name__}: {exc}"
        return True, f"sent to {len(recipients)} recipient(s)"


class TeamsSender(NotificationSender):
    kind = "teams"

    def send(self, subject: str, body: str, meta: dict) -> tuple[bool, str]:
        url = self.secrets.get("webhook_url")
        if not url:
            return False, "missing webhook URL"
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": _colour(meta.get("severity")),
            "summary": subject[:200],
            "title": subject,
            "text": body.replace("\n", "  \n"),
        }
        return _post_webhook(url, payload)


class SlackSender(NotificationSender):
    kind = "slack"

    def send(self, subject: str, body: str, meta: dict) -> tuple[bool, str]:
        url = self.secrets.get("webhook_url")
        if not url:
            return False, "missing webhook URL"
        payload = {
            "text": subject,
            "attachments": [{"color": "#" + _colour(meta.get("severity")), "text": body}],
        }
        return _post_webhook(url, payload)
