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
from app.core.limits import SlidingWindowLimiter
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
    # SQLite serializes writers and locks under concurrency — fine for dev, a
    # latent outage under real analyst load.
    if settings.is_production and settings.database_url.startswith("sqlite"):
        logger.warning("SCALE: running production on SQLite. It single-writes and will "
                       "lock under concurrent load — use PostgreSQL "
                       "(SENTINEL_DATABASE_URL=postgresql+psycopg://...).")
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


# --- Load protection ------------------------------------------------------
# In-process quotas: enough to stop one client (or a buggy script) from taking
# the platform down with itself. Real abuse/DDoS protection belongs at the edge —
# with several API workers each holds its own counters, so the effective quota is
# per worker. Documented in the README rather than silently assumed.
_general_limiter = SlidingWindowLimiter(
    limit=settings.rate_limit_per_minute, window_seconds=60.0,
    max_keys=settings.rate_limit_max_keys)
_ai_limiter = SlidingWindowLimiter(
    limit=settings.rate_limit_ai_per_minute, window_seconds=60.0,
    max_keys=settings.rate_limit_max_keys)

# Endpoints that call out to Claude: slow and billable, so quota'd far harder.
_AI_PATHS = ("/api/chat", "/api/reports/generate")
# Liveness/readiness must never be throttled or the orchestrator will kill a
# healthy container during a traffic spike.
_EXEMPT_PATHS = ("/api/health", "/api/ready", "/metrics")


def _client_key(request: Request) -> str:
    client = request.client.host if request.client else "unknown"
    # Prefer the authenticated caller when present so one noisy tenant behind a
    # shared NAT doesn't throttle everyone else.
    auth = request.headers.get("authorization", "")
    return f"{client}|{auth[-24:]}" if auth else client


@app.middleware("http")
async def load_protection(request: Request, call_next):
    from fastapi.responses import JSONResponse

    path = request.url.path
    if path.startswith("/api") and not path.startswith(_EXEMPT_PATHS):
        # Reject oversized bodies before reading them into memory.
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > settings.max_request_bytes:
            return JSONResponse(
                status_code=413,
                content={"detail": f"request body exceeds {settings.max_request_bytes} bytes"})

        if settings.rate_limit_enabled:
            limiter = _ai_limiter if path.startswith(_AI_PATHS) else _general_limiter
            allowed, retry_after = limiter.check(_client_key(request))
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests, slow down"},
                    headers={"Retry-After": str(retry_after)})

    return await call_next(request)


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
