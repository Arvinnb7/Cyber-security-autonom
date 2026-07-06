"""Sentinel backend entrypoint."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session

from app.api import api_router
from app.core.config import settings
from app.core.db import engine, init_db
from app.core.scheduler import shutdown_scheduler, start_scheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("sentinel")


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
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # Strict CSP on the JSON API only — leave /docs (Swagger UI) usable.
    if request.url.path.startswith("/api"):
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


app.include_router(api_router)


@app.get("/")
def root() -> dict:
    return {"name": settings.app_name, "status": "running", "docs": "/docs"}
