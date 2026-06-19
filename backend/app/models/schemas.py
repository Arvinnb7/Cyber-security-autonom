"""API request/response schemas (Pydantic)."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ChatRequest(BaseModel):
    question: str
    history: list[dict[str, Any]] | None = None


class ChatResponse(BaseModel):
    answer: str
    ai_generated: bool


class ActionRequest(BaseModel):
    action_type: str
    target: str
    incident_id: int | None = None


class StatusUpdate(BaseModel):
    status: str  # open | investigating | resolved | dismissed


class InjectRequest(BaseModel):
    scenario: str | None = None  # None => random
