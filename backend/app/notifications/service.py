"""Alert dispatch — the operational loop that turns incidents and pending
approvals into notifications on the org's channels.

Design:
- **Resilient:** the public entry points (``notify_incident``,
  ``notify_pending_approval``) never raise — a broken channel must never break
  the ingestion pipeline or the approval flow.
- **Severity gating:** a channel only fires for incidents at/above its
  ``min_severity``.
- **Dedup / escalation:** each delivery is recorded as a ``Notification`` row.
  An incident re-touched every ingest cycle is not re-alerted unless its severity
  *increases* (that's an escalation and warrants a fresh alert). A pending
  approval is alerted once, then re-alerted by the scheduler if still unactioned.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from sqlmodel import Session, select

from app.core import runtime
from app.core.config import settings
from app.core.time import utcnow
from app.models.tables import (
    AuditAction,
    Incident,
    Notification,
    NotificationChannel,
)
from app.notifications.factory import build_sender

logger = logging.getLogger("sentinel.notifications")

_SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_ACTION_LABELS = {
    "block_user": "Block user",
    "reset_password": "Reset password",
    "kill_session": "Kill session",
    "block_ip": "Block IP",
}


def _sev_rank(severity: str | None) -> int:
    return _SEV_ORDER.get((severity or "").lower(), 0)


def _base_url() -> str:
    return settings.app_base_url.rstrip("/")


def _enabled_channels(session: Session) -> list[NotificationChannel]:
    return list(session.exec(
        select(NotificationChannel).where(NotificationChannel.enabled == True)  # noqa: E712
    ))


# --- rendering ------------------------------------------------------------

def _render_incident(incident: Incident) -> tuple[str, str]:
    sev = (incident.severity or "medium").upper()
    title = incident.title or incident.det_id or "Security incident"
    subject = f"[Sentinel] {sev}: {title}"
    lines = [
        f"Severity: {sev} · risk {round(incident.final_score)}/100 · "
        f"confidence {round(incident.confidence * 100)}%",
        f"Type: {incident.threat_type or 'n/a'}",
    ]
    if incident.actor_username:
        lines.append(f"User: {incident.actor_username}")
    if incident.target_asset:
        lines.append(f"Asset: {incident.target_asset}")
    summary = incident.ai_summary or {}
    what = summary.get("what_happened")
    if what:
        lines += ["", str(what)]
    action = summary.get("recommended_action")
    if action:
        lines.append(f"Recommended: {action}")
    lines += ["", f"View incident: {_base_url()}/incidents/{incident.id}"]
    return subject, "\n".join(lines)


def _render_approval(action: AuditAction, incident: Incident | None, *, escalation: bool = False) -> tuple[str, str]:
    label = _ACTION_LABELS.get(action.action_type, action.action_type)
    prefix = "[Sentinel] ESCALATION — approval still pending" if escalation else "[Sentinel] Approval needed"
    subject = f"{prefix}: {label} on {action.target}"
    lines = [
        f"Action awaiting manager approval: {label}",
        f"Target: {action.target}",
        f"Requested by: {action.requested_by}",
    ]
    if incident:
        lines.append(f"Incident: {incident.title or incident.det_id} ({(incident.severity or '').upper()})")
        lines.append(f"Review & approve: {_base_url()}/incidents/{incident.id}")
    else:
        lines.append(f"Review pending actions: {_base_url()}/incidents")
    return subject, "\n".join(lines)


# --- delivery + logging ---------------------------------------------------

def _send_and_log(session: Session, channel: NotificationChannel, subject: str, body: str,
                  meta: dict, *, kind: str, incident_id: int | None = None,
                  action_id: int | None = None, severity: str = "medium") -> Notification:
    sender = build_sender(channel)
    if sender is None:
        status, detail = "failed", f"no sender for kind '{channel.kind}'"
    else:
        ok, detail = sender.send(subject, body, meta)
        status = "sent" if ok else "failed"

    note = Notification(
        channel_id=channel.id, incident_id=incident_id, action_id=action_id,
        kind=kind, severity=severity, subject=subject, body=body,
        status=status, detail=detail, origin=runtime.current_mode(),
    )
    session.add(note)
    channel.status = "connected" if status == "sent" else "error"
    channel.last_error = "" if status == "sent" else detail
    if status == "sent":
        channel.last_sent = utcnow()
    channel.updated_at = utcnow()
    session.add(channel)
    session.commit()
    session.refresh(note)
    return note


# --- incident alerts ------------------------------------------------------

def _already_alerted_at_severity(session: Session, channel_id: int, incident_id: int, rank: int) -> bool:
    prior = session.exec(
        select(Notification).where(
            Notification.channel_id == channel_id,
            Notification.incident_id == incident_id,
            Notification.kind == "incident",
            Notification.status == "sent",
        )
    ).all()
    return any(_sev_rank(n.severity) >= rank for n in prior)


def notify_incident(session: Session, incident: Incident, *, created: bool = False) -> None:
    """Alert enabled channels about an incident. Never raises."""
    if not settings.notifications_enabled or incident is None or incident.id is None:
        return
    try:
        rank = _sev_rank(incident.severity)
        channels = [c for c in _enabled_channels(session) if c.notify_on_incident]
        if not channels:
            return
        subject, body = _render_incident(incident)
        meta = {"severity": incident.severity, "incident_id": incident.id}
        for ch in channels:
            if rank < _sev_rank(ch.min_severity):
                continue
            if _already_alerted_at_severity(session, ch.id, incident.id, rank):
                continue
            _send_and_log(session, ch, subject, body, meta, kind="incident",
                          incident_id=incident.id, severity=incident.severity)
    except Exception:  # noqa: BLE001 - alerting must never break the pipeline
        logger.exception("notify_incident failed for incident %s", getattr(incident, "id", "?"))


# --- approval escalation --------------------------------------------------

def _approval_already_sent(session: Session, channel_id: int, action_id: int) -> bool:
    return session.exec(
        select(Notification).where(
            Notification.channel_id == channel_id,
            Notification.action_id == action_id,
            Notification.kind == "approval",
            Notification.status == "sent",
        )
    ).first() is not None


def _last_approval_note(session: Session, action_id: int) -> Notification | None:
    return session.exec(
        select(Notification).where(
            Notification.action_id == action_id,
            Notification.kind == "approval",
            Notification.status == "sent",
        ).order_by(Notification.created_at.desc())
    ).first()


def _dispatch_approval(session: Session, action: AuditAction, incident: Incident | None,
                       *, force: bool = False, escalation: bool = False) -> None:
    channels = [c for c in _enabled_channels(session) if c.notify_on_approval]
    if not channels:
        return
    subject, body = _render_approval(action, incident, escalation=escalation)
    sev = incident.severity if incident else "high"
    meta = {"severity": sev, "incident_id": action.incident_id}
    for ch in channels:
        if incident and _sev_rank(sev) < _sev_rank(ch.min_severity):
            continue
        if not force and _approval_already_sent(session, ch.id, action.id):
            continue
        _send_and_log(session, ch, subject, body, meta, kind="approval",
                      incident_id=action.incident_id, action_id=action.id, severity=sev)


def notify_pending_approval(session: Session, action: AuditAction, incident: Incident | None = None) -> None:
    """Alert that a response action is waiting on manager approval. Never raises."""
    if not settings.notifications_enabled or action is None or action.id is None:
        return
    try:
        if incident is None and action.incident_id:
            incident = session.get(Incident, action.incident_id)
        _dispatch_approval(session, action, incident)
    except Exception:  # noqa: BLE001
        logger.exception("notify_pending_approval failed for action %s", getattr(action, "id", "?"))


def escalate_pending_approvals(session: Session) -> int:
    """Re-alert approvals still pending past the escalation window. Returns count."""
    if not settings.notifications_enabled:
        return 0
    cutoff = utcnow() - timedelta(minutes=settings.approval_escalation_minutes)
    pending = session.exec(
        select(AuditAction).where(
            AuditAction.status == "pending",
            AuditAction.requested_at <= cutoff,
        )
    ).all()
    escalated = 0
    for action in pending:
        last = _last_approval_note(session, action.id)
        if last and last.created_at > cutoff:
            continue  # already re-alerted within the window
        incident = session.get(Incident, action.incident_id) if action.incident_id else None
        try:
            _dispatch_approval(session, action, incident, force=True, escalation=True)
            escalated += 1
        except Exception:  # noqa: BLE001
            logger.exception("escalation failed for action %s", action.id)
    return escalated


# --- platform health alerts (self-monitoring) -----------------------------
# These intentionally bypass ``min_severity``: if the platform has gone blind,
# that is always critical regardless of how a channel is tuned for incidents.

def _render_health(issues: list, *, recovered: bool) -> tuple[str, str]:
    if recovered:
        return ("[Sentinel] RECOVERED — monitoring is healthy again",
                "All previously reported platform health issues are resolved. "
                "Event collection and detection are running normally.")
    subject = f"[Sentinel] PLATFORM ALERT — monitoring degraded ({len(issues)} issue(s))"
    lines = ["Sentinel is not fully monitoring your environment right now:", ""]
    lines += [f"• {i.line()}" for i in issues]
    lines += ["", "Until this is fixed, an empty incident list does NOT mean you are safe.",
              f"Open Sentinel: {_base_url()}"]
    return subject, "\n".join(lines)


def _health_channels(session: Session) -> list[NotificationChannel]:
    return [c for c in _enabled_channels(session) if c.notify_on_health]


def notify_health(session: Session, issues: list, *, recovered: bool = False) -> int:
    """Alert channels about the platform's own health. Never raises."""
    if not settings.notifications_enabled:
        return 0
    try:
        channels = _health_channels(session)
        if not channels:
            return 0
        subject, body = _render_health(issues, recovered=recovered)
        meta = {"severity": "low" if recovered else "critical"}
        for ch in channels:
            _send_and_log(session, ch, subject, body, meta, kind="health",
                          severity=meta["severity"])
        return len(channels)
    except Exception:  # noqa: BLE001 - alerting must never break the watchdog
        logger.exception("notify_health failed")
        return 0


# --- test delivery (used by the "Send test" endpoint) ---------------------

def send_test(session: Session, channel: NotificationChannel) -> tuple[bool, str]:
    note = _send_and_log(
        session, channel, "[Sentinel] Test alert",
        "This is a test alert from Sentinel. If you can read this, the channel works.",
        {"severity": "medium"}, kind="test",
    )
    return note.status == "sent", note.detail
