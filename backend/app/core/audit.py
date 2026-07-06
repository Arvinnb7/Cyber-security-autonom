"""Audit logging — record who did what for security/compliance."""
from __future__ import annotations

from typing import Any

from fastapi import Request
from sqlmodel import Session

from app.models.tables import AuditLog


def record_audit(session: Session, actor: str, action: str, *, target: str = "",
                 detail: dict[str, Any] | None = None, request: Request | None = None,
                 org_id: int = 1) -> None:
    ip = ""
    if request is not None and request.client:
        ip = request.client.host
    session.add(AuditLog(
        org_id=org_id, actor=actor, action=action, target=target,
        detail=detail or {}, ip=ip,
    ))
    session.commit()
