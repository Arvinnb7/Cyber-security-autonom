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
    if settings.seed_on_startup:
        from app.simulation.seed import seed_all

        with Session(engine) as session:
            seed_all(session)
    start_scheduler()
    logger.info("Sentinel started (env=%s, ai=%s)", settings.environment, settings.ai_enabled)
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
