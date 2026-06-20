"""Database tables (SQLModel).

Design notes
------------
- ``Event`` is the *canonical* event model — every connector normalizes into it
  (OCSF/ECS-inspired). ``raw`` keeps the original payload for forensics.
- ``Signal`` is a single detector firing; ``Incident`` correlates many signals
  into one human-meaningful story carrying the five risk scores (F4).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    # Naive UTC everywhere: SQLite stores datetimes without tzinfo, so keeping a
    # single naive-UTC convention avoids aware/naive comparison bugs in queries.
    return datetime.now(timezone.utc).replace(tzinfo=None)


class DetectionDefinition(SQLModel, table=True):
    """A detection from the MVP catalog (source of truth, DET-001..DET-010)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    det_id: str = Field(index=True, unique=True)      # e.g. "DET-005"
    name_en: str = ""
    name_fa: str = ""
    category: str = ""
    description_fa: str = ""
    default_severity: str = "medium"                  # low|medium|high|critical
    required_data_sources: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    detection_signals: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    scoring_factors: dict[str, int] = Field(default_factory=dict, sa_column=Column(JSON))
    required_evidence: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    recommended_response: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    human_approval_required: str = "high"             # low|medium|high|critical
    enabled: bool = True
    updated_at: datetime = Field(default_factory=utcnow)


class Connection(SQLModel, table=True):
    """An organization's live integration with a security source (F1).

    ``config`` holds non-secret settings (safe to return); secret credentials are
    encrypted in ``secrets_enc`` and never returned by the API.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    provider: str = Field(index=True)                 # e.g. "microsoft_365"
    display_name: str = ""
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    secrets_enc: str = ""                              # Fernet-encrypted JSON of secret fields
    status: str = "unknown"                            # unknown | connected | error
    last_error: str = ""
    last_sync: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class User(SQLModel, table=True):
    """A monitored identity in the protected organization."""

    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    display_name: str = ""
    email: str = ""
    department: str = "General"
    title: str = ""
    # Behavioural baseline used by detectors / scoring.
    home_country: str = "IR"
    is_privileged: bool = False
    risk_score: float = 0.0          # rolling user risk (F4), 0..100
    is_blocked: bool = False
    created_at: datetime = Field(default_factory=utcnow)


class Asset(SQLModel, table=True):
    """A protected resource (server, mailbox, SaaS app, data store)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    asset_type: str = "endpoint"     # endpoint | server | saas | identity | data_store
    # Business sensitivity 1..5 — feeds asset_risk + business_impact.
    sensitivity: int = 3
    owner_department: str = "General"
    risk_score: float = 0.0
    created_at: datetime = Field(default_factory=utcnow)


class Event(SQLModel, table=True):
    """Canonical, normalized security event (the unified schema, F2)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=utcnow, index=True)
    source: str = Field(index=True)              # connector name, e.g. "microsoft_365"
    category: str = "authentication"             # authentication|file|network|process|alert
    action: str = ""                             # e.g. "login_success", "file_download"
    actor_username: Optional[str] = Field(default=None, index=True)
    src_ip: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    target_asset: Optional[str] = None
    severity: int = 1                            # 1..5 base severity from the source
    fingerprint: str = Field(default="", index=True)  # dedup key (F2)
    raw: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))


class Signal(SQLModel, table=True):
    """A detector firing on one or more events (F3)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    detector: str = Field(index=True)            # e.g. "impossible_travel"
    det_id: str = Field(default="", index=True)  # catalog id, e.g. "DET-005"
    threat_type: str = ""                        # e.g. "account_takeover"
    actor_username: Optional[str] = Field(default=None, index=True)
    target_asset: Optional[str] = None
    severity: int = 3                            # 1..5
    confidence: float = 0.5                      # 0..1
    description: str = ""
    # Which catalog scoring_factors fired and their points (drives threat_score).
    matched_factors: dict[str, int] = Field(default_factory=dict, sa_column=Column(JSON))
    event_ids: list[int] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utcnow, index=True)
    incident_id: Optional[int] = Field(default=None, foreign_key="incident.id", index=True)


class Incident(SQLModel, table=True):
    """Correlated, scored, AI-analyzed security incident (F3/F4/F5/F6)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    title: str = ""
    threat_type: str = ""
    det_id: str = Field(default="", index=True)       # catalog detection id
    severity: str = Field(default="medium", index=True)  # low|medium|high|critical (from final_score)
    human_approval_required: str = "high"             # from catalog
    status: str = Field(default="open", index=True)   # open | investigating | resolved | dismissed
    actor_username: Optional[str] = Field(default=None, index=True)
    target_asset: Optional[str] = None
    confidence: float = 0.5                       # overall likelihood 0..1

    # --- The five scores (F4) ---
    threat_score: float = 0.0                     # severity of the technique
    user_risk: float = 0.0                        # how risky the user is
    asset_risk: float = 0.0                       # how critical the asset is
    business_impact: float = 0.0                  # potential damage
    final_score: float = Field(default=0.0, index=True)  # composite 0..100

    # --- AI outputs (F5/F6) ---
    ai_analysis: str = ""                                 # narrative (F5)
    ai_summary: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))  # F6
    ai_generated: bool = False                            # True if Claude, False if template fallback

    # Catalog-aligned investigation context.
    matched_factors: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    evidence: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))

    timeline: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utcnow, index=True)
    updated_at: datetime = Field(default_factory=utcnow)


class AuditAction(SQLModel, table=True):
    """Semi-automatic response action requiring manager approval (F8)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    incident_id: Optional[int] = Field(default=None, foreign_key="incident.id", index=True)
    action_type: str = ""                         # block_user | reset_password | kill_session | block_ip
    target: str = ""                              # username / ip / session id
    status: str = "pending"                       # pending | approved | executed | rejected
    requested_by: str = "system"
    approved_by: Optional[str] = None
    result: str = ""
    requested_at: datetime = Field(default_factory=utcnow, index=True)
    resolved_at: Optional[datetime] = None


class WeeklyReport(SQLModel, table=True):
    """Auto-generated weekly executive report (F10)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    period_start: datetime
    period_end: datetime
    content_md: str = ""                          # rendered markdown
    stats: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    ai_generated: bool = False
    generated_at: datetime = Field(default_factory=utcnow, index=True)
