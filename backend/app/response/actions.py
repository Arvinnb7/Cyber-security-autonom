"""Semi-automatic response (F8).

Every action is created as ``pending`` and only takes effect after a manager
approves it. Execution is routed to the relevant connector (simulated here) and
recorded in the audit trail. Real connectors plug in without changing this code.
"""
from __future__ import annotations

from sqlmodel import Session, select

from app.connectors.real.factory import build_connector
from app.connectors.simulators import get_connector
from app.core import runtime
from app.core.time import utcnow
from app.models.tables import AuditAction, Connection, Incident, User
from app.notifications.service import notify_pending_approval

# action -> (label, which connector executes it)
AVAILABLE_ACTIONS = {
    "block_user": {"label": "Block User", "connector": "azure"},
    "reset_password": {"label": "Reset Password", "connector": "azure"},
    "kill_session": {"label": "Kill Session", "connector": "microsoft_365"},
    "block_ip": {"label": "Block IP", "connector": "cloudflare"},
    "isolate_host": {"label": "Isolate Host", "connector": "microsoft_defender"},
}

# Which live provider(s) can execute each action (Azure AD shares M365's connector).
_ACTION_PROVIDERS = {
    "block_user": ["microsoft_365", "azure"],
    "reset_password": ["microsoft_365", "azure"],
    "kill_session": ["microsoft_365", "azure"],
    "block_ip": ["cloudflare"],
    "isolate_host": ["microsoft_defender"],
}


def _execute_live(session: Session, action_type: str, target: str) -> tuple[str, str]:
    """Run a real response action against a live integration. Returns (status, detail).

    Guardrail: only executes when an enabled connection exists AND it has
    ``allow_actions`` turned on; otherwise it is blocked by policy.
    """
    providers = _ACTION_PROVIDERS.get(action_type, [])
    conn = session.exec(
        select(Connection).where(Connection.provider.in_(providers), Connection.enabled == True)  # noqa: E712
    ).first()
    if conn is None:
        return "failed", f"no enabled integration for '{action_type}' (providers: {', '.join(providers)})"
    if not conn.allow_actions:
        return "blocked", (f"blocked by policy — enable automated response on the "
                           f"'{conn.display_name or conn.provider}' integration first")
    connector = build_connector(conn)
    if connector is None:
        return "failed", f"no live connector for provider '{conn.provider}'"
    try:
        result = connector.execute_action(action_type, target)
    except Exception as exc:  # noqa: BLE001 - surface any vendor/auth error as a failed action
        return "failed", f"{type(exc).__name__}: {exc}"
    return ("executed" if result.success else "failed"), result.detail


def request_action(session: Session, action_type: str, target: str,
                   incident_id: int | None = None, requested_by: str = "system") -> AuditAction:
    if action_type not in AVAILABLE_ACTIONS:
        raise ValueError(f"unsupported action: {action_type}")
    action = AuditAction(
        incident_id=incident_id, action_type=action_type, target=target,
        status="pending", requested_by=requested_by, origin=runtime.current_mode(),
    )
    session.add(action)
    session.commit()
    session.refresh(action)
    # Escalate: alert managers that an action is waiting on their approval.
    notify_pending_approval(session, action)
    return action


def approve_action(session: Session, action_id: int, approved_by: str) -> AuditAction:
    action = session.get(AuditAction, action_id)
    if action is None:
        raise ValueError("action not found")
    if action.status != "pending":
        return action

    if runtime.is_live():
        # Real execution against the customer's live integration (guardrailed).
        status, detail = _execute_live(session, action.action_type, action.target)
    else:
        # Demo mode: safe simulated execution.
        spec = AVAILABLE_ACTIONS[action.action_type]
        connector = get_connector(spec["connector"])
        detail = connector.execute_action(action.action_type, action.target).detail \
            if connector is not None else "executed (simulated)"
        status = "executed"

    # Reflect side effects in the demo model where meaningful.
    if status == "executed" and action.action_type == "block_user":
        user = session.exec(select(User).where(User.username == action.target)).first()
        if user:
            user.is_blocked = True
            session.add(user)

    action.status = status
    action.approved_by = approved_by
    action.result = detail
    action.resolved_at = utcnow()
    session.add(action)

    # Mark the incident as being handled (only if the action actually ran).
    if status == "executed" and action.incident_id:
        incident = session.get(Incident, action.incident_id)
        if incident and incident.status == "open":
            incident.status = "investigating"
            session.add(incident)

    session.commit()
    session.refresh(action)
    return action


def reject_action(session: Session, action_id: int, rejected_by: str) -> AuditAction:
    action = session.get(AuditAction, action_id)
    if action is None:
        raise ValueError("action not found")
    if action.status == "pending":
        action.status = "rejected"
        action.approved_by = rejected_by
        action.resolved_at = utcnow()
        session.add(action)
        session.commit()
        session.refresh(action)
    return action


def list_actions(session: Session, status: str | None = None) -> list[AuditAction]:
    q = select(AuditAction).where(AuditAction.origin == runtime.current_mode())
    if status:
        q = q.where(AuditAction.status == status)
    return list(session.exec(q.order_by(AuditAction.requested_at.desc())))
