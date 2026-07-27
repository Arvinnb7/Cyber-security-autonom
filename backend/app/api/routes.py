"""REST API surfacing all ten product features."""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select

from app.ai.chat import answer_question
from app.ai.client import ai_available
from app.connectors.real.factory import test_connection
from app.connectors.registry import provider_meta, public_providers, secret_keys, split_credentials
from app.connectors.simulators import get_connectors
from app.core import runtime
from app.core.audit import record_audit
from app.core.auth import get_current_account, get_current_user, require_role
from app.core.crypto import decrypt_dict, encrypt_dict
from app.core.db import get_session
from app.core.security import create_access_token, hash_password, verify_password
from app.core.time import utcnow
from app.models.schemas import (
    AccountCreate,
    AccountUpdate,
    ActionRequest,
    AssetUpdate,
    AssignRequest,
    ChannelCreate,
    ChannelUpdate,
    ChatRequest,
    ChatResponse,
    ConnectionCreate,
    ConnectionUpdate,
    InjectRequest,
    ModeUpdate,
    MonitoredUserUpdate,
    NoteCreate,
    StatusUpdate,
    Token,
)
from app.models.tables import (
    Account,
    Asset,
    AuditAction,
    AuditLog,
    Connection,
    DetectionDefinition,
    Incident,
    IncidentNote,
    Notification,
    NotificationChannel,
    Signal,
    User,
    WeeklyReport,
)
from app.notifications.registry import (
    channel_meta,
    public_channels,
    secret_keys as channel_secret_keys,
    split_credentials as channel_split_credentials,
)
from app.notifications.service import send_test as send_test_notification
from app.response import actions as response_actions
from app.services import analytics

api_router = APIRouter(prefix="/api")

# Authenticated dependency reused on protected routers.
Auth = Depends(get_current_user)
DB = Depends(get_session)
# RBAC helpers: any authenticated account, or a minimum role tier.
Account_ = Depends(get_current_account)
AdminOnly = Depends(require_role("admin"))
AnalystUp = Depends(require_role("analyst"))  # admin implicitly included


# --- Health & meta --------------------------------------------------------

@api_router.get("/health")
def health() -> dict:
    return {"status": "ok", "ai_enabled": ai_available(), "data_mode": runtime.current_mode()}


@api_router.get("/ready")
def ready(session: Session = DB):
    """Readiness probe: verifies the database is reachable (503 if not)."""
    from fastapi.responses import JSONResponse
    from sqlalchemy import text

    try:
        session.exec(text("SELECT 1"))
        return {"status": "ready"}
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=503, content={"status": "not_ready", "detail": str(exc)})


@api_router.get("/system/health")
def system_health(fresh: bool = False, _: str = Auth, session: Session = DB) -> dict:
    """Platform self-monitoring: is Sentinel actually watching right now?

    Serves the watchdog's last computed state by default (cheap enough to poll);
    ``?fresh=true`` re-runs every check on demand.
    """
    from app.monitoring.health import health_snapshot

    return health_snapshot(session, fresh=fresh)


@api_router.get("/connectors")
def connectors(_: str = Auth) -> dict:
    return {
        "ai_enabled": ai_available(),
        "data_mode": runtime.current_mode(),
        "connectors": [
            {"name": c.name, "label": c.label, "actions": list(c.supported_actions)}
            for c in get_connectors()
        ],
    }


# --- Data mode (switch demo <-> live live, in-app) — admin only -----------

@api_router.get("/mode")
def get_mode(_: str = Auth) -> dict:
    return {"data_mode": runtime.current_mode()}


@api_router.post("/mode")
def set_mode(body: ModeUpdate, request: Request, account: Account = AdminOnly, session: Session = DB) -> dict:
    try:
        mode = runtime.set_mode(session, body.data_mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    # Entering demo mode: ensure the demo dataset exists so the UI is populated.
    if mode == "demo":
        from app.simulation.seed import seed_all

        seed_all(session, demo=True)
    record_audit(session, account.username, "mode.switch", target=mode, request=request)
    return {"data_mode": mode}


# --- Auth -----------------------------------------------------------------

# Very small in-memory login throttle: max attempts per username per window.
_LOGIN_ATTEMPTS: dict[str, list[float]] = {}
_LOGIN_MAX = 8
_LOGIN_WINDOW = 300.0


def _rate_limited(username: str) -> bool:
    now = time.time()
    hits = [t for t in _LOGIN_ATTEMPTS.get(username, []) if now - t < _LOGIN_WINDOW]
    hits.append(now)
    _LOGIN_ATTEMPTS[username] = hits
    return len(hits) > _LOGIN_MAX


@api_router.post("/auth/login", response_model=Token)
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), session: Session = DB) -> Token:
    if _rate_limited(form.username):
        raise HTTPException(status_code=429, detail="Too many login attempts, try again later")
    account = session.exec(select(Account).where(Account.username == form.username)).first()
    if account is None or not account.is_active or not verify_password(form.password, account.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    account.last_login = utcnow()
    session.add(account)
    session.commit()
    record_audit(session, account.username, "auth.login", request=request, org_id=account.org_id)
    return Token(access_token=create_access_token(account.username, account.role, account.org_id))


@api_router.get("/me")
def me(account: Account = Account_) -> dict:
    return {"username": account.username, "email": account.email, "role": account.role,
            "org_id": account.org_id, "is_active": account.is_active}


# --- Account management (admin only) --------------------------------------

def _account_brief(a: Account) -> dict:
    return {"id": a.id, "username": a.username, "email": a.email, "role": a.role,
            "is_active": a.is_active, "last_login": a.last_login, "created_at": a.created_at}


@api_router.get("/accounts")
def list_accounts(account: Account = AdminOnly, session: Session = DB) -> list[dict]:
    rows = session.exec(select(Account).order_by(Account.created_at)).all()
    return [_account_brief(a) for a in rows]


@api_router.post("/accounts")
def create_account(body: AccountCreate, request: Request, account: Account = AdminOnly,
                   session: Session = DB) -> dict:
    if body.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=400, detail="invalid role")
    if session.exec(select(Account).where(Account.username == body.username)).first():
        raise HTTPException(status_code=409, detail="username already exists")
    acc = Account(org_id=account.org_id, username=body.username, email=body.email, role=body.role,
                  hashed_password=hash_password(body.password), is_active=True)
    session.add(acc)
    session.commit()
    session.refresh(acc)
    record_audit(session, account.username, "account.create", target=body.username,
                 detail={"role": body.role}, request=request)
    return _account_brief(acc)


@api_router.put("/accounts/{account_id}")
def update_account(account_id: int, body: AccountUpdate, request: Request,
                   account: Account = AdminOnly, session: Session = DB) -> dict:
    target = session.get(Account, account_id)
    if target is None:
        raise HTTPException(status_code=404, detail="account not found")
    if body.role is not None:
        if body.role not in ("admin", "analyst", "viewer"):
            raise HTTPException(status_code=400, detail="invalid role")
        target.role = body.role
    if body.email is not None:
        target.email = body.email
    if body.is_active is not None:
        # Don't let an admin lock themselves out / disable the last admin.
        if not body.is_active and target.id == account.id:
            raise HTTPException(status_code=400, detail="cannot deactivate yourself")
        target.is_active = body.is_active
    if body.password:
        target.hashed_password = hash_password(body.password)
    session.add(target)
    session.commit()
    record_audit(session, account.username, "account.update", target=target.username, request=request)
    return _account_brief(target)


@api_router.delete("/accounts/{account_id}")
def delete_account(account_id: int, request: Request, account: Account = AdminOnly,
                   session: Session = DB) -> dict:
    target = session.get(Account, account_id)
    if target is None:
        raise HTTPException(status_code=404, detail="account not found")
    if target.id == account.id:
        raise HTTPException(status_code=400, detail="cannot delete yourself")
    session.delete(target)
    session.commit()
    record_audit(session, account.username, "account.delete", target=target.username, request=request)
    return {"ok": True, "deleted": account_id}


# --- Audit log (admin only) -----------------------------------------------

@api_router.get("/audit")
def list_audit(limit: int = 100, account: Account = AdminOnly, session: Session = DB) -> list[dict]:
    rows = session.exec(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)).all()
    return [{"id": r.id, "actor": r.actor, "action": r.action, "target": r.target,
             "detail": r.detail, "ip": r.ip, "created_at": r.created_at} for r in rows]


# --- Dashboard (F9) -------------------------------------------------------

@api_router.get("/dashboard/overview")
def dashboard_overview(_: str = Auth, session: Session = DB) -> dict:
    return {
        "org_risk": analytics.org_risk(session),
        "stats": analytics.stats_overview(session),
        "active_threats": analytics.active_threats(session),
        "by_severity": analytics.detections_by_severity(session),
        "top_incidents": [_incident_brief(i) for i in analytics.top_incidents(session, 8)],
        "risky_users": [_user_brief(u) for u in analytics.riskiest_users(session, 6)],
        "risky_assets": [_asset_brief(a) for a in analytics.riskiest_assets(session, 6)],
    }


# --- Incidents (F3/F4/F5/F6) ----------------------------------------------

@api_router.get("/incidents")
def list_incidents(status: str | None = None, limit: int = 50,
                   _: str = Auth, session: Session = DB) -> list[dict]:
    items = analytics.top_incidents(session, limit=limit, status=status)
    return [_incident_brief(i) for i in items]


@api_router.get("/incidents/{incident_id}")
def get_incident(incident_id: int, _: str = Auth, session: Session = DB) -> dict:
    incident = session.get(Incident, incident_id)
    if incident is None or incident.origin != runtime.current_mode():
        raise HTTPException(status_code=404, detail="incident not found")
    signals = list(session.exec(select(Signal).where(Signal.incident_id == incident_id)))
    actions = list(session.exec(select(AuditAction).where(AuditAction.incident_id == incident_id)))
    notes = list(session.exec(
        select(IncidentNote).where(IncidentNote.incident_id == incident_id)
        .order_by(IncidentNote.created_at)
    ))
    return {
        **_incident_full(incident),
        "signals": [s.model_dump() for s in signals],
        "actions": [a.model_dump() for a in actions],
        "notes": [{"id": n.id, "author": n.author, "body": n.body, "created_at": n.created_at}
                  for n in notes],
    }


CLOSED_REASONS = ("true_positive", "false_positive", "benign")


@api_router.post("/incidents/{incident_id}/status")
def update_incident_status(incident_id: int, body: StatusUpdate, request: Request,
                           account: Account = AnalystUp, session: Session = DB) -> dict:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    if body.status not in ("open", "investigating", "resolved", "dismissed"):
        raise HTTPException(status_code=400, detail="invalid status")
    if body.closed_reason and body.closed_reason not in CLOSED_REASONS:
        raise HTTPException(status_code=400, detail=f"closed_reason must be one of {CLOSED_REASONS}")
    now = utcnow()
    incident.status = body.status
    if body.closed_reason:
        incident.closed_reason = body.closed_reason
    # Closing the case stops the response clock (feeds MTTR).
    if body.status in ("resolved", "dismissed"):
        incident.resolved_at = incident.resolved_at or now
    else:
        incident.resolved_at = None
    # Any human touch counts as acknowledgement (feeds MTTA).
    if incident.acknowledged_at is None:
        incident.acknowledged_at = now
        incident.acknowledged_by = account.username
    incident.updated_at = now
    session.add(incident)
    session.commit()
    # Recompute the actor's rolling risk after a state change.
    from app.scoring.engine import recompute_user_risk

    recompute_user_risk(session, incident.actor_username)
    analytics.invalidate_sla_cache()   # the numbers just changed
    record_audit(session, account.username, "incident.status", target=str(incident_id),
                 detail={"status": body.status, "closed_reason": body.closed_reason or ""},
                 request=request)
    return {"ok": True, "status": incident.status, "closed_reason": incident.closed_reason}


@api_router.post("/incidents/{incident_id}/acknowledge")
def acknowledge_incident(incident_id: int, request: Request,
                         account: Account = AnalystUp, session: Session = DB) -> dict:
    """Claim the case: 'a human has seen this'. Starts the MTTA clock stopping."""
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    if incident.acknowledged_at is None:
        incident.acknowledged_at = utcnow()
        incident.acknowledged_by = account.username
        incident.updated_at = utcnow()
        session.add(incident)
        session.commit()
        session.refresh(incident)
    analytics.invalidate_sla_cache()
    record_audit(session, account.username, "incident.acknowledge", target=str(incident_id),
                 request=request)
    return {"ok": True, "acknowledged_at": incident.acknowledged_at,
            "acknowledged_by": incident.acknowledged_by}


@api_router.post("/incidents/{incident_id}/assign")
def assign_incident(incident_id: int, body: AssignRequest, request: Request,
                    account: Account = AnalystUp, session: Session = DB) -> dict:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    if body.assignee:
        target = session.exec(select(Account).where(Account.username == body.assignee)).first()
        if target is None:
            raise HTTPException(status_code=400, detail=f"no such account: {body.assignee}")
    incident.assigned_to = body.assignee or None
    incident.updated_at = utcnow()
    session.add(incident)
    session.commit()
    record_audit(session, account.username, "incident.assign", target=str(incident_id),
                 detail={"assignee": body.assignee or ""}, request=request)
    return {"ok": True, "assigned_to": incident.assigned_to}


@api_router.post("/incidents/{incident_id}/notes")
def add_incident_note(incident_id: int, body: NoteCreate, request: Request,
                      account: Account = AnalystUp, session: Session = DB) -> dict:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    text = (body.body or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="note body is empty")
    note = IncidentNote(incident_id=incident_id, author=account.username, body=text)
    session.add(note)
    session.commit()
    session.refresh(note)
    record_audit(session, account.username, "incident.note", target=str(incident_id), request=request)
    return {"id": note.id, "author": note.author, "body": note.body, "created_at": note.created_at}


@api_router.get("/metrics/sla")
def sla_metrics(days: int = 30, _: str = Auth, session: Session = DB) -> dict:
    """Response-time and accuracy metrics — the ROI evidence for the business."""
    return analytics.sla_metrics(session, days=days)


# --- Users & Assets -------------------------------------------------------

@api_router.get("/users")
def list_users(_: str = Auth, session: Session = DB) -> list[dict]:
    return [_user_brief(u) for u in analytics.riskiest_users(session, 100)]


@api_router.get("/assets")
def list_assets(_: str = Auth, session: Session = DB) -> list[dict]:
    return [_asset_brief(a) for a in analytics.riskiest_assets(session, 100)]


@api_router.put("/assets/{asset_id}")
def update_asset(asset_id: int, body: AssetUpdate, request: Request,
                 account: Account = AdminOnly, session: Session = DB) -> dict:
    """Correct the auto-classified business criticality (drives asset_risk)."""
    from app.scoring.engine import recompute_asset_risk

    asset = session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset not found")
    if body.sensitivity is not None:
        if not 1 <= body.sensitivity <= 5:
            raise HTTPException(status_code=400, detail="sensitivity must be 1..5")
        asset.sensitivity = body.sensitivity
    if body.owner_department is not None:
        asset.owner_department = body.owner_department
    if body.asset_type is not None:
        asset.asset_type = body.asset_type
    session.add(asset)
    session.commit()
    recompute_asset_risk(session, asset.name)
    session.refresh(asset)
    record_audit(session, account.username, "asset.update", target=asset.name, request=request)
    return _asset_brief(asset)


@api_router.put("/users/{user_id}")
def update_monitored_user(user_id: int, body: MonitoredUserUpdate, request: Request,
                          account: Account = AdminOnly, session: Session = DB) -> dict:
    """Mark a monitored identity as privileged (raises user_risk & scoring)."""
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    if body.is_privileged is not None:
        user.is_privileged = body.is_privileged
    if body.department is not None:
        user.department = body.department
    if body.title is not None:
        user.title = body.title
    session.add(user)
    session.commit()
    session.refresh(user)
    record_audit(session, account.username, "monitored_user.update",
                 target=user.username, request=request)
    return _user_brief(user)


# --- Semi-automatic response (F8) -----------------------------------------

@api_router.get("/actions/available")
def available_actions(_: str = Auth) -> dict:
    return {"actions": [{"type": k, **v} for k, v in response_actions.AVAILABLE_ACTIONS.items()]}


@api_router.get("/actions")
def list_actions(status: str | None = None, _: str = Auth, session: Session = DB) -> list[dict]:
    return [a.model_dump() for a in response_actions.list_actions(session, status)]


@api_router.post("/actions")
def request_action(body: ActionRequest, request: Request, account: Account = AnalystUp,
                   session: Session = DB) -> dict:
    try:
        action = response_actions.request_action(
            session, body.action_type, body.target, body.incident_id, requested_by=account.username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    record_audit(session, account.username, "action.request",
                 target=f"{body.action_type}:{body.target}", request=request)
    session.refresh(action)  # record_audit's commit expired it
    return action.model_dump()


@api_router.post("/actions/{action_id}/approve")
def approve_action(action_id: int, request: Request, account: Account = AdminOnly,
                   session: Session = DB) -> dict:
    try:
        action = response_actions.approve_action(session, action_id, approved_by=account.username)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    record_audit(session, account.username, "action.approve",
                 target=f"{action.action_type}:{action.target}", request=request)
    session.refresh(action)
    return action.model_dump()


@api_router.post("/actions/{action_id}/reject")
def reject_action(action_id: int, request: Request, account: Account = AdminOnly,
                  session: Session = DB) -> dict:
    try:
        action = response_actions.reject_action(session, action_id, rejected_by=account.username)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    record_audit(session, account.username, "action.reject", target=str(action_id), request=request)
    session.refresh(action)
    return action.model_dump()


# --- Chat assistant (F7) --------------------------------------------------

@api_router.post("/chat", response_model=ChatResponse)
def chat(body: ChatRequest, _: str = Auth, session: Session = DB) -> ChatResponse:
    result = answer_question(session, body.question, body.history)
    return ChatResponse(**result)


# --- Weekly reports (F10) -------------------------------------------------

@api_router.get("/reports")
def list_reports(_: str = Auth, session: Session = DB) -> list[dict]:
    reports = session.exec(
        select(WeeklyReport).where(WeeklyReport.origin == runtime.current_mode())
        .order_by(WeeklyReport.generated_at.desc())
    ).all()
    return [{"id": r.id, "period_start": r.period_start, "period_end": r.period_end,
             "generated_at": r.generated_at, "ai_generated": r.ai_generated, "stats": r.stats}
            for r in reports]


@api_router.get("/reports/{report_id}")
def get_report(report_id: int, _: str = Auth, session: Session = DB) -> dict:
    report = session.get(WeeklyReport, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="report not found")
    return report.model_dump()


@api_router.post("/reports/generate")
def generate_report(_: Account = AnalystUp, session: Session = DB) -> dict:
    from app.reporting.weekly import generate_weekly_report

    report = generate_weekly_report(session)
    return report.model_dump()


# --- Detection catalog CRUD (MVP source of truth) -------------------------

@api_router.get("/detections")
def list_detections(_: str = Auth, session: Session = DB) -> list[dict]:
    rows = session.exec(select(DetectionDefinition).order_by(DetectionDefinition.det_id)).all()
    return [d.model_dump() for d in rows]


@api_router.get("/detections/{det_id}")
def get_detection(det_id: str, _: str = Auth, session: Session = DB) -> dict:
    d = session.exec(select(DetectionDefinition).where(DetectionDefinition.det_id == det_id)).first()
    if d is None:
        raise HTTPException(status_code=404, detail="detection not found")
    return d.model_dump()


@api_router.post("/detections")
def create_detection(body: dict, _: Account = AdminOnly, session: Session = DB) -> dict:
    if not body.get("det_id"):
        raise HTTPException(status_code=400, detail="det_id is required")
    if session.exec(select(DetectionDefinition).where(DetectionDefinition.det_id == body["det_id"])).first():
        raise HTTPException(status_code=409, detail="det_id already exists")
    d = DetectionDefinition(**{k: v for k, v in body.items() if k in DetectionDefinition.model_fields})
    session.add(d)
    session.commit()
    session.refresh(d)
    return d.model_dump()


@api_router.put("/detections/{det_id}")
def update_detection(det_id: str, body: dict, _: Account = AdminOnly, session: Session = DB) -> dict:
    d = session.exec(select(DetectionDefinition).where(DetectionDefinition.det_id == det_id)).first()
    if d is None:
        raise HTTPException(status_code=404, detail="detection not found")
    for k, v in body.items():
        if k in DetectionDefinition.model_fields and k not in ("id", "det_id"):
            setattr(d, k, v)
    session.add(d)
    session.commit()
    session.refresh(d)
    return d.model_dump()


@api_router.delete("/detections/{det_id}")
def delete_detection(det_id: str, _: Account = AdminOnly, session: Session = DB) -> dict:
    d = session.exec(select(DetectionDefinition).where(DetectionDefinition.det_id == det_id)).first()
    if d is None:
        raise HTTPException(status_code=404, detail="detection not found")
    session.delete(d)
    session.commit()
    return {"ok": True, "deleted": det_id}


# --- Integrations / live connections (F1) ---------------------------------

@api_router.get("/providers")
def list_providers(_: str = Auth) -> list[dict]:
    return public_providers()


@api_router.get("/connections")
def list_connections(_: str = Auth, session: Session = DB) -> list[dict]:
    rows = session.exec(select(Connection).order_by(Connection.created_at.desc())).all()
    return [_connection_brief(c) for c in rows]


@api_router.post("/connections")
def create_connection(body: ConnectionCreate, request: Request, account: Account = AdminOnly,
                      session: Session = DB) -> dict:
    if provider_meta(body.provider) is None:
        raise HTTPException(status_code=400, detail=f"unknown provider: {body.provider}")
    public, secrets = split_credentials(body.provider, body.credentials or {})
    conn = Connection(
        provider=body.provider,
        display_name=body.display_name or body.provider,
        enabled=body.enabled,
        allow_actions=body.allow_actions,
        config=public,
        secrets_enc=encrypt_dict(secrets),
    )
    session.add(conn)
    session.commit()
    session.refresh(conn)
    record_audit(session, account.username, "connection.create",
                 target=f"{body.provider}#{conn.id}", request=request)
    return _connection_brief(conn)


@api_router.put("/connections/{conn_id}")
def update_connection(conn_id: int, body: ConnectionUpdate, request: Request,
                      account: Account = AdminOnly, session: Session = DB) -> dict:
    conn = session.get(Connection, conn_id)
    if conn is None:
        raise HTTPException(status_code=404, detail="connection not found")
    if body.display_name is not None:
        conn.display_name = body.display_name
    if body.enabled is not None:
        conn.enabled = body.enabled
    if body.allow_actions is not None:
        conn.allow_actions = body.allow_actions
    if body.credentials:
        public, secrets = split_credentials(conn.provider, body.credentials)
        conn.config = {**conn.config, **public}
        if secrets:  # only overwrite secrets that were actually provided
            current = decrypt_dict(conn.secrets_enc)
            current.update(secrets)
            conn.secrets_enc = encrypt_dict(current)
    conn.updated_at = utcnow()
    session.add(conn)
    session.commit()
    session.refresh(conn)
    record_audit(session, account.username, "connection.update", target=str(conn_id), request=request)
    return _connection_brief(conn)


@api_router.post("/connections/{conn_id}/test")
def test_conn(conn_id: int, request: Request, account: Account = AdminOnly, session: Session = DB) -> dict:
    conn = session.get(Connection, conn_id)
    if conn is None:
        raise HTTPException(status_code=404, detail="connection not found")
    ok, message = test_connection(conn)
    conn.status = "connected" if ok else "error"
    conn.last_error = "" if ok else message
    if ok:
        conn.last_sync = utcnow()
    session.add(conn)
    session.commit()
    record_audit(session, account.username, "connection.test",
                 target=f"{conn.provider}#{conn.id}", detail={"ok": ok}, request=request)
    return {"ok": ok, "message": message, "status": conn.status}


@api_router.delete("/connections/{conn_id}")
def delete_connection(conn_id: int, request: Request, account: Account = AdminOnly,
                      session: Session = DB) -> dict:
    conn = session.get(Connection, conn_id)
    if conn is None:
        raise HTTPException(status_code=404, detail="connection not found")
    session.delete(conn)
    session.commit()
    record_audit(session, account.username, "connection.delete", target=str(conn_id), request=request)
    return {"ok": True, "deleted": conn_id}


# --- Alerting / notification channels (operational alerting) --------------

_SEVERITIES = {"low", "medium", "high", "critical"}


@api_router.get("/notification-kinds")
def list_notification_kinds(_: str = Auth) -> list[dict]:
    return public_channels()


@api_router.get("/notification-channels")
def list_channels(_: Account = AdminOnly, session: Session = DB) -> list[dict]:
    rows = session.exec(select(NotificationChannel).order_by(NotificationChannel.created_at.desc())).all()
    return [_channel_brief(c) for c in rows]


@api_router.post("/notification-channels")
def create_channel(body: ChannelCreate, request: Request, account: Account = AdminOnly,
                   session: Session = DB) -> dict:
    meta = channel_meta(body.kind)
    if meta is None:
        raise HTTPException(status_code=400, detail=f"unknown channel kind: {body.kind}")
    if body.min_severity not in _SEVERITIES:
        raise HTTPException(status_code=400, detail=f"invalid min_severity: {body.min_severity}")
    public, secrets = channel_split_credentials(body.kind, body.credentials or {})
    channel = NotificationChannel(
        kind=body.kind,
        display_name=body.display_name or meta["label"],
        enabled=body.enabled,
        min_severity=body.min_severity,
        notify_on_incident=body.notify_on_incident,
        notify_on_approval=body.notify_on_approval,
        notify_on_health=body.notify_on_health,
        config=public,
        secrets_enc=encrypt_dict(secrets),
    )
    session.add(channel)
    session.commit()
    session.refresh(channel)
    record_audit(session, account.username, "notification_channel.create",
                 target=f"{body.kind}#{channel.id}", request=request)
    return _channel_brief(channel)


@api_router.put("/notification-channels/{channel_id}")
def update_channel(channel_id: int, body: ChannelUpdate, request: Request,
                   account: Account = AdminOnly, session: Session = DB) -> dict:
    channel = session.get(NotificationChannel, channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="channel not found")
    if body.display_name is not None:
        channel.display_name = body.display_name
    if body.enabled is not None:
        channel.enabled = body.enabled
    if body.min_severity is not None:
        if body.min_severity not in _SEVERITIES:
            raise HTTPException(status_code=400, detail=f"invalid min_severity: {body.min_severity}")
        channel.min_severity = body.min_severity
    if body.notify_on_incident is not None:
        channel.notify_on_incident = body.notify_on_incident
    if body.notify_on_approval is not None:
        channel.notify_on_approval = body.notify_on_approval
    if body.notify_on_health is not None:
        channel.notify_on_health = body.notify_on_health
    if body.credentials:
        public, secrets = channel_split_credentials(channel.kind, body.credentials)
        channel.config = {**channel.config, **public}
        if secrets:  # only overwrite secrets that were actually provided
            current = decrypt_dict(channel.secrets_enc)
            current.update(secrets)
            channel.secrets_enc = encrypt_dict(current)
    channel.updated_at = utcnow()
    session.add(channel)
    session.commit()
    session.refresh(channel)
    record_audit(session, account.username, "notification_channel.update",
                 target=str(channel_id), request=request)
    return _channel_brief(channel)


@api_router.post("/notification-channels/{channel_id}/test")
def test_channel(channel_id: int, request: Request, account: Account = AdminOnly,
                 session: Session = DB) -> dict:
    channel = session.get(NotificationChannel, channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="channel not found")
    ok, message = send_test_notification(session, channel)
    record_audit(session, account.username, "notification_channel.test",
                 target=f"{channel.kind}#{channel.id}", detail={"ok": ok}, request=request)
    return {"ok": ok, "message": message, "status": channel.status}


@api_router.delete("/notification-channels/{channel_id}")
def delete_channel(channel_id: int, request: Request, account: Account = AdminOnly,
                   session: Session = DB) -> dict:
    channel = session.get(NotificationChannel, channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="channel not found")
    session.delete(channel)
    session.commit()
    record_audit(session, account.username, "notification_channel.delete",
                 target=str(channel_id), request=request)
    return {"ok": True, "deleted": channel_id}


@api_router.get("/notifications")
def list_notifications(limit: int = 50, _: Account = AnalystUp, session: Session = DB) -> list[dict]:
    rows = session.exec(
        select(Notification)
        .where(Notification.origin == runtime.current_mode())
        .order_by(Notification.created_at.desc())
        .limit(limit)
    ).all()
    return [_notification_brief(n) for n in rows]


# --- Demo control (admin only) --------------------------------------------

@api_router.post("/control/inject")
def inject_scenario(body: InjectRequest, _: Account = AdminOnly, session: Session = DB) -> dict:
    from app.ingestion.pipeline import analyze, ingest_raw_events
    from app.simulation.scenarios import SCENARIOS, generate_scenario, random_scenario

    if runtime.is_live():
        raise HTTPException(status_code=403, detail="demo scenario injection is disabled in live mode")
    if body.scenario and body.scenario not in SCENARIOS:
        raise HTTPException(status_code=400, detail=f"unknown scenario; choose from {list(SCENARIOS)}")
    raw = generate_scenario(body.scenario) if body.scenario else random_scenario()
    ingest_raw_events(session, raw)
    touched = analyze(session)
    return {"injected": body.scenario or "random", "incidents_touched": touched}


@api_router.post("/control/cycle")
def run_cycle(_: Account = AdminOnly, session: Session = DB) -> dict:
    from app.ingestion.pipeline import run_full_cycle

    if runtime.is_live():
        raise HTTPException(status_code=403, detail="forced demo cycle is disabled in live mode")
    return run_full_cycle(session, inject_scenario_prob=1.0)


# --- Serializers ----------------------------------------------------------

def _incident_brief(i: Incident) -> dict:
    return {
        "id": i.id, "title": i.title, "threat_type": i.threat_type, "det_id": i.det_id,
        "severity": i.severity, "status": i.status, "actor_username": i.actor_username,
        "target_asset": i.target_asset, "human_approval_required": i.human_approval_required,
        "confidence": i.confidence, "final_score": i.final_score,
        "assigned_to": i.assigned_to, "acknowledged_at": i.acknowledged_at,
        "acknowledged_by": i.acknowledged_by, "resolved_at": i.resolved_at,
        "closed_reason": i.closed_reason,
        "created_at": i.created_at, "updated_at": i.updated_at,
    }


def _incident_full(i: Incident) -> dict:
    return {
        **_incident_brief(i),
        "scores": {
            "threat_score": i.threat_score, "user_risk": i.user_risk,
            "asset_risk": i.asset_risk, "business_impact": i.business_impact,
            "final_score": i.final_score,
        },
        "matched_factors": i.matched_factors, "evidence": i.evidence,
        "ai_analysis": i.ai_analysis, "ai_summary": i.ai_summary,
        "ai_generated": i.ai_generated, "timeline": i.timeline,
    }


def _user_brief(u: User) -> dict:
    return {"id": u.id, "username": u.username, "display_name": u.display_name,
            "department": u.department, "title": u.title, "risk_score": u.risk_score,
            "is_privileged": u.is_privileged, "is_blocked": u.is_blocked,
            "origin": u.origin}


def _asset_brief(a: Asset) -> dict:
    return {"id": a.id, "name": a.name, "asset_type": a.asset_type,
            "sensitivity": a.sensitivity, "owner_department": a.owner_department,
            "risk_score": a.risk_score}


def _connection_brief(c: Connection) -> dict:
    # Never return raw secrets — only which secret fields are set.
    set_secrets = sorted(decrypt_dict(c.secrets_enc).keys())
    meta = provider_meta(c.provider) or {}
    return {
        "id": c.id, "provider": c.provider, "display_name": c.display_name,
        "enabled": c.enabled, "allow_actions": c.allow_actions,
        "status": c.status, "last_error": c.last_error, "last_sync": c.last_sync,
        "config": c.config, "secrets_set": set_secrets,
        "required_secrets": sorted(secret_keys(c.provider)),
        "supported_actions": meta.get("actions", []),
    }


def _channel_brief(c: NotificationChannel) -> dict:
    # Never return raw secrets — only which secret fields are set.
    set_secrets = sorted(decrypt_dict(c.secrets_enc).keys())
    meta = channel_meta(c.kind) or {}
    return {
        "id": c.id, "kind": c.kind, "display_name": c.display_name, "enabled": c.enabled,
        "min_severity": c.min_severity, "notify_on_incident": c.notify_on_incident,
        "notify_on_approval": c.notify_on_approval, "notify_on_health": c.notify_on_health,
        "status": c.status,
        "last_error": c.last_error, "last_sent": c.last_sent,
        "config": c.config, "secrets_set": set_secrets,
        "required_secrets": sorted(channel_secret_keys(c.kind)),
        "fields": meta.get("fields", []),
    }


def _notification_brief(n: Notification) -> dict:
    return {
        "id": n.id, "kind": n.kind, "severity": n.severity, "subject": n.subject,
        "status": n.status, "detail": n.detail, "channel_id": n.channel_id,
        "incident_id": n.incident_id, "created_at": n.created_at,
    }
