"""REST API surfacing all ten product features."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select

from app.ai.chat import answer_question
from app.ai.client import ai_available
from app.connectors.real.factory import test_connection
from app.connectors.registry import provider_meta, public_providers, secret_keys, split_credentials
from app.connectors.simulators import get_connectors
from app.core.auth import authenticate, create_access_token, get_current_user
from app.core.config import settings
from app.core.crypto import decrypt_dict, encrypt_dict
from app.core.db import get_session
from app.core.time import utcnow
from app.models.schemas import (
    ActionRequest,
    ChatRequest,
    ChatResponse,
    ConnectionCreate,
    ConnectionUpdate,
    InjectRequest,
    StatusUpdate,
    Token,
)
from app.models.tables import (
    Asset,
    AuditAction,
    Connection,
    DetectionDefinition,
    Incident,
    Signal,
    User,
    WeeklyReport,
)
from app.response import actions as response_actions
from app.services import analytics

api_router = APIRouter(prefix="/api")

# Authenticated dependency reused on protected routers.
Auth = Depends(get_current_user)
DB = Depends(get_session)


# --- Health & meta --------------------------------------------------------

@api_router.get("/health")
def health() -> dict:
    return {"status": "ok", "ai_enabled": ai_available(), "data_mode": settings.data_mode}


@api_router.get("/connectors")
def connectors(_: str = Auth) -> dict:
    return {
        "ai_enabled": ai_available(),
        "data_mode": settings.data_mode,
        "connectors": [
            {"name": c.name, "label": c.label, "actions": list(c.supported_actions)}
            for c in get_connectors()
        ],
    }


# --- Auth -----------------------------------------------------------------

@api_router.post("/auth/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends()) -> Token:
    if not authenticate(form.username, form.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return Token(access_token=create_access_token(form.username))


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
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    signals = list(session.exec(select(Signal).where(Signal.incident_id == incident_id)))
    actions = list(session.exec(select(AuditAction).where(AuditAction.incident_id == incident_id)))
    return {
        **_incident_full(incident),
        "signals": [s.model_dump() for s in signals],
        "actions": [a.model_dump() for a in actions],
    }


@api_router.post("/incidents/{incident_id}/status")
def update_incident_status(incident_id: int, body: StatusUpdate,
                           user: str = Auth, session: Session = DB) -> dict:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    if body.status not in ("open", "investigating", "resolved", "dismissed"):
        raise HTTPException(status_code=400, detail="invalid status")
    incident.status = body.status
    incident.updated_at = utcnow()
    session.add(incident)
    session.commit()
    # Recompute the actor's rolling risk after a state change.
    from app.scoring.engine import recompute_user_risk

    recompute_user_risk(session, incident.actor_username)
    return {"ok": True, "status": incident.status}


# --- Users & Assets -------------------------------------------------------

@api_router.get("/users")
def list_users(_: str = Auth, session: Session = DB) -> list[dict]:
    return [_user_brief(u) for u in analytics.riskiest_users(session, 100)]


@api_router.get("/assets")
def list_assets(_: str = Auth, session: Session = DB) -> list[dict]:
    return [_asset_brief(a) for a in analytics.riskiest_assets(session, 100)]


# --- Semi-automatic response (F8) -----------------------------------------

@api_router.get("/actions/available")
def available_actions(_: str = Auth) -> dict:
    return {"actions": [{"type": k, **v} for k, v in response_actions.AVAILABLE_ACTIONS.items()]}


@api_router.get("/actions")
def list_actions(status: str | None = None, _: str = Auth, session: Session = DB) -> list[dict]:
    return [a.model_dump() for a in response_actions.list_actions(session, status)]


@api_router.post("/actions")
def request_action(body: ActionRequest, user: str = Auth, session: Session = DB) -> dict:
    try:
        action = response_actions.request_action(
            session, body.action_type, body.target, body.incident_id, requested_by=user)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return action.model_dump()


@api_router.post("/actions/{action_id}/approve")
def approve_action(action_id: int, user: str = Auth, session: Session = DB) -> dict:
    try:
        action = response_actions.approve_action(session, action_id, approved_by=user)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return action.model_dump()


@api_router.post("/actions/{action_id}/reject")
def reject_action(action_id: int, user: str = Auth, session: Session = DB) -> dict:
    try:
        action = response_actions.reject_action(session, action_id, rejected_by=user)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return action.model_dump()


# --- Chat assistant (F7) --------------------------------------------------

@api_router.post("/chat", response_model=ChatResponse)
def chat(body: ChatRequest, _: str = Auth, session: Session = DB) -> ChatResponse:
    result = answer_question(session, body.question, body.history)
    return ChatResponse(**result)


# --- Weekly reports (F10) -------------------------------------------------

@api_router.get("/reports")
def list_reports(_: str = Auth, session: Session = DB) -> list[dict]:
    reports = session.exec(select(WeeklyReport).order_by(WeeklyReport.generated_at.desc())).all()
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
def generate_report(_: str = Auth, session: Session = DB) -> dict:
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
def create_detection(body: dict, _: str = Auth, session: Session = DB) -> dict:
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
def update_detection(det_id: str, body: dict, _: str = Auth, session: Session = DB) -> dict:
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
def delete_detection(det_id: str, _: str = Auth, session: Session = DB) -> dict:
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
def create_connection(body: ConnectionCreate, _: str = Auth, session: Session = DB) -> dict:
    if provider_meta(body.provider) is None:
        raise HTTPException(status_code=400, detail=f"unknown provider: {body.provider}")
    public, secrets = split_credentials(body.provider, body.credentials or {})
    conn = Connection(
        provider=body.provider,
        display_name=body.display_name or body.provider,
        enabled=body.enabled,
        config=public,
        secrets_enc=encrypt_dict(secrets),
    )
    session.add(conn)
    session.commit()
    session.refresh(conn)
    return _connection_brief(conn)


@api_router.put("/connections/{conn_id}")
def update_connection(conn_id: int, body: ConnectionUpdate, _: str = Auth, session: Session = DB) -> dict:
    conn = session.get(Connection, conn_id)
    if conn is None:
        raise HTTPException(status_code=404, detail="connection not found")
    if body.display_name is not None:
        conn.display_name = body.display_name
    if body.enabled is not None:
        conn.enabled = body.enabled
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
    return _connection_brief(conn)


@api_router.post("/connections/{conn_id}/test")
def test_conn(conn_id: int, _: str = Auth, session: Session = DB) -> dict:
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
    return {"ok": ok, "message": message, "status": conn.status}


@api_router.delete("/connections/{conn_id}")
def delete_connection(conn_id: int, _: str = Auth, session: Session = DB) -> dict:
    conn = session.get(Connection, conn_id)
    if conn is None:
        raise HTTPException(status_code=404, detail="connection not found")
    session.delete(conn)
    session.commit()
    return {"ok": True, "deleted": conn_id}


# --- Demo control ---------------------------------------------------------

@api_router.post("/control/inject")
def inject_scenario(body: InjectRequest, _: str = Auth, session: Session = DB) -> dict:
    from app.ingestion.pipeline import analyze, ingest_raw_events
    from app.simulation.scenarios import SCENARIOS, generate_scenario, random_scenario

    if settings.is_live:
        raise HTTPException(status_code=403, detail="demo scenario injection is disabled in live mode")
    if body.scenario and body.scenario not in SCENARIOS:
        raise HTTPException(status_code=400, detail=f"unknown scenario; choose from {list(SCENARIOS)}")
    raw = generate_scenario(body.scenario) if body.scenario else random_scenario()
    ingest_raw_events(session, raw)
    touched = analyze(session)
    return {"injected": body.scenario or "random", "incidents_touched": touched}


@api_router.post("/control/cycle")
def run_cycle(_: str = Auth, session: Session = DB) -> dict:
    from app.ingestion.pipeline import run_full_cycle

    if settings.is_live:
        raise HTTPException(status_code=403, detail="forced demo cycle is disabled in live mode")
    return run_full_cycle(session, inject_scenario_prob=1.0)


# --- Serializers ----------------------------------------------------------

def _incident_brief(i: Incident) -> dict:
    return {
        "id": i.id, "title": i.title, "threat_type": i.threat_type, "det_id": i.det_id,
        "severity": i.severity, "status": i.status, "actor_username": i.actor_username,
        "target_asset": i.target_asset, "human_approval_required": i.human_approval_required,
        "confidence": i.confidence, "final_score": i.final_score,
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
            "is_privileged": u.is_privileged, "is_blocked": u.is_blocked}


def _asset_brief(a: Asset) -> dict:
    return {"id": a.id, "name": a.name, "asset_type": a.asset_type,
            "sensitivity": a.sensitivity, "owner_department": a.owner_department,
            "risk_score": a.risk_score}


def _connection_brief(c: Connection) -> dict:
    # Never return raw secrets — only which secret fields are set.
    set_secrets = sorted(decrypt_dict(c.secrets_enc).keys())
    return {
        "id": c.id, "provider": c.provider, "display_name": c.display_name,
        "enabled": c.enabled, "status": c.status, "last_error": c.last_error,
        "last_sync": c.last_sync, "config": c.config,
        "secrets_set": set_secrets,
        "required_secrets": sorted(secret_keys(c.provider)),
    }
