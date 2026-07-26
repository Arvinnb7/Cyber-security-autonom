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
    # Why the case was closed — drives the false-positive rate used for tuning.
    closed_reason: str | None = None  # true_positive | false_positive | benign


class AssignRequest(BaseModel):
    assignee: str | None = None  # account username; None/"" unassigns


class NoteCreate(BaseModel):
    body: str


class InjectRequest(BaseModel):
    scenario: str | None = None  # None => random


class ModeUpdate(BaseModel):
    data_mode: str  # "demo" | "live"


class AccountCreate(BaseModel):
    username: str
    password: str
    email: str = ""
    role: str = "viewer"  # admin | analyst | viewer


class AccountUpdate(BaseModel):
    email: str | None = None
    role: str | None = None
    is_active: bool | None = None
    password: str | None = None  # set to reset the password


class ConnectionCreate(BaseModel):
    provider: str
    display_name: str = ""
    enabled: bool = True
    allow_actions: bool = False
    credentials: dict[str, Any] = {}


class ConnectionUpdate(BaseModel):
    display_name: str | None = None
    enabled: bool | None = None
    allow_actions: bool | None = None
    credentials: dict[str, Any] | None = None


class AssetUpdate(BaseModel):
    """Let the customer correct what the auto-classifier guessed."""

    sensitivity: int | None = None      # 1..5 business criticality
    owner_department: str | None = None
    asset_type: str | None = None


class MonitoredUserUpdate(BaseModel):
    is_privileged: bool | None = None
    department: str | None = None
    title: str | None = None


class ChannelCreate(BaseModel):
    kind: str  # "email" | "teams" | "slack"
    display_name: str = ""
    enabled: bool = True
    min_severity: str = "high"  # low | medium | high | critical
    notify_on_incident: bool = True
    notify_on_approval: bool = True
    notify_on_health: bool = True
    credentials: dict[str, Any] = {}


class ChannelUpdate(BaseModel):
    display_name: str | None = None
    enabled: bool | None = None
    min_severity: str | None = None
    notify_on_incident: bool | None = None
    notify_on_approval: bool | None = None
    notify_on_health: bool | None = None
    credentials: dict[str, Any] | None = None
