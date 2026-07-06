"""Sentinel backend entrypoint."""
from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session

from app.api import api_router
from app.core.config import settings
from app.core.db import engine, init_db
from app.core.logging import setup_logging
from app.core.scheduler import shutdown_scheduler, start_scheduler

setup_logging()
logger = logging.getLogger("sentinel")

# Error tracking (optional).
if settings.sentry_dsn:
    import sentry_sdk

    sentry_sdk.init(dsn=settings.sentry_dsn, environment=settings.environment, traces_sample_rate=0.1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail fast in production if secrets are still at insecure built-in defaults.
    insecure = settings.insecure_defaults()
    if insecure:
        msg = f"insecure default(s) in use: {', '.join(insecure)}"
        if settings.is_production:
            raise RuntimeError(f"Refusing to start in production — {msg}. Set them via env.")
        logger.warning("SECURITY: %s (fine for dev, MUST be set in production).", msg)
    init_db()
    from app.core import runtime
    from app.simulation.seed import seed_all

    # Runtime mode is persisted (DB) and switchable in-app; the DATA_MODE env var
    # only sets the initial value on first boot. Catalog always seeds; demo
    # org/scenarios only when the active mode is demo.
    with Session(engine) as session:
        mode = runtime.init_mode(session)
        seed_all(session, demo=(mode == "demo") and settings.seed_on_startup)
    start_scheduler()
    logger.info("Sentinel started (mode=%s, env=%s, ai=%s)",
                runtime.current_mode(), settings.environment, settings.ai_enabled)
    yield
    shutdown_scheduler()


app = FastAPI(title="Sentinel — Autonomous Network Security Monitoring", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,   # explicit allow-list, not "*"
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_and_request_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # Strict CSP on the JSON API only — leave /docs (Swagger UI) usable.
    if request.url.path.startswith("/api"):
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# Prometheus metrics at /metrics.
if settings.metrics_enabled:
    from prometheus_fastapi_instrumentator import Instrumentator

    Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

app.include_router(api_router)


@app.get("/")
def root() -> dict:
    return {"name": settings.app_name, "status": "running", "docs": "/docs"}
