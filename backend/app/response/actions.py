"""Semi-automatic response (F8).

Every action is created as ``pending`` and only takes effect after a manager
approves it. Execution is routed to the relevant connector (simulated here) and
recorded in the audit trail. Real connectors plug in without changing this code.
"""
from __future__ import annotations

from sqlmodel import Session, select

from app.connectors.simulators import get_connector
from app.core.time import utcnow
from app.models.tables import AuditAction, Incident, User

# action -> (label, which connector executes it)
AVAILABLE_ACTIONS = {
    "block_user": {"label": "Block User", "connector": "azure"},
    "reset_password": {"label": "Reset Password", "connector": "azure"},
    "kill_session": {"label": "Kill Session", "connector": "microsoft_365"},
    "block_ip": {"label": "Block IP", "connector": "cloudflare"},
}


def request_action(session: Session, action_type: str, target: str,
                   incident_id: int | None = None, requested_by: str = "system") -> AuditAction:
    if action_type not in AVAILABLE_ACTIONS:
        raise ValueError(f"unsupported action: {action_type}")
    action = AuditAction(
        incident_id=incident_id, action_type=action_type, target=target,
        status="pending", requested_by=requested_by,
    )
    session.add(action)
    session.commit()
    session.refresh(action)
    return action


def approve_action(session: Session, action_id: int, approved_by: str) -> AuditAction:
    action = session.get(AuditAction, action_id)
    if action is None:
        raise ValueError("action not found")
    if action.status != "pending":
        return action

    spec = AVAILABLE_ACTIONS[action.action_type]
    connector = get_connector(spec["connector"])
    detail = "executed (simulated)"
    if connector is not None:
        result = connector.execute_action(action.action_type, action.target)
        detail = result.detail

    # Reflect side effects in the model where meaningful.
    if action.action_type == "block_user":
        user = session.exec(select(User).where(User.username == action.target)).first()
        if user:
            user.is_blocked = True
            session.add(user)

    action.status = "executed"
    action.approved_by = approved_by
    action.result = detail
    action.resolved_at = utcnow()
    session.add(action)

    # Mark the incident as being handled.
    if action.incident_id:
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
    q = select(AuditAction)
    if status:
        q = q.where(AuditAction.status == status)
    return list(session.exec(q.order_by(AuditAction.requested_at.desc())))
