"""Sentinel backend entrypoint."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
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
    allow_origins=["*"],  # MVP single-tenant; tighten for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/")
def root() -> dict:
    return {"name": settings.app_name, "status": "running", "docs": "/docs"}
