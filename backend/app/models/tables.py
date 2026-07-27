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


class AppState(SQLModel, table=True):
    """Single-row runtime application state (e.g. the active data mode)."""

    id: Optional[int] = Field(default=1, primary_key=True)
    data_mode: str = "demo"                            # "demo" | "live"
    updated_at: datetime = Field(default_factory=utcnow)


class SystemHealth(SQLModel, table=True):
    """Single-row self-monitoring state — the watchdog's memory.

    A SOC that replaces human watchers must notice when it goes blind. The
    scheduler heartbeats here every ingest cycle; the health job compares those
    timestamps against the configured staleness window and alerts on a *state
    change* (healthy -> degraded and back), so operators get one alert and one
    recovery notice rather than a stream.
    """

    id: Optional[int] = Field(default=1, primary_key=True)
    # Heartbeats written by the scheduler's ingest job.
    last_cycle_at: Optional[datetime] = None      # last time a cycle ran at all
    last_ingest_at: Optional[datetime] = None     # last time a cycle ingested >0 events
    # Current evaluated state.
    state: str = "unknown"                        # unknown | healthy | degraded
    detail: str = ""                              # human-readable issue summary
    issue_key: str = ""                           # stable key of the active issues (dedup)
    # Full issue payload, so the API can serve the watchdog's findings without
    # re-running every check on each dashboard poll.
    issues: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    last_alert_at: Optional[datetime] = None      # when we last alerted (cooldown)
    updated_at: datetime = Field(default_factory=utcnow)


class Organization(SQLModel, table=True):
    """A tenant. On-prem deploys use a single default org; SaaS adds more (Phase 5)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = "Default Organization"
    slug: str = Field(default="default", index=True, unique=True)
    created_at: datetime = Field(default_factory=utcnow)


class Account(SQLModel, table=True):
    """A human user of the platform (distinct from a monitored ``User``)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(default=1, foreign_key="organization.id", index=True)
    username: str = Field(index=True, unique=True)
    email: str = ""
    hashed_password: str = ""
    role: str = Field(default="viewer", index=True)   # admin | analyst | viewer
    is_active: bool = True
    last_login: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utcnow)


class AuditLog(SQLModel, table=True):
    """Tamper-evident trail of who did what (security/compliance)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(default=1, index=True)
    actor: str = Field(default="system", index=True)  # account username
    action: str = Field(index=True)                   # e.g. "mode.switch", "action.approve"
    target: str = ""                                  # affected entity
    detail: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    ip: str = ""
    created_at: datetime = Field(default_factory=utcnow, index=True)


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
    # Safety guardrail: real response actions only fire when explicitly enabled.
    allow_actions: bool = False
    config: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    secrets_enc: str = ""                              # Fernet-encrypted JSON of secret fields
    status: str = "unknown"                            # unknown | connected | error
    last_error: str = ""
    last_sync: Optional[datetime] = None
    # Incremental-sync state so live connectors only pull new events.
    sync_cursor: str = ""
    consecutive_failures: int = 0
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
    origin: str = Field(default="demo", index=True)   # data mode this row belongs to
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
    origin: str = Field(default="demo", index=True)   # data mode this row belongs to
    created_at: datetime = Field(default_factory=utcnow)


class UserBaselineState(SQLModel, table=True):
    """Learned "normal" for one identity, kept as running counters.

    Rebuilding every user's baseline from 30 days of raw events on every ingest
    cycle does not scale (millions of rows, every 20 seconds), so the learned
    state lives here instead: cheap to read, updated incrementally as events
    arrive, and fully recomputed by a nightly job to correct the drift that
    accumulates as old events age out of the window.

    Counters — not sets — are stored so the "seen often enough to be normal"
    thresholds behave exactly as they did when computed in memory.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True)
    origin: str = Field(default="demo", index=True)   # data mode this row belongs to
    login_count: int = 0
    country_counts: dict[str, int] = Field(default_factory=dict, sa_column=Column(JSON))
    hour_counts: dict[str, int] = Field(default_factory=dict, sa_column=Column(JSON))
    known_devices: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    window_start: Optional[datetime] = None           # start of the learning window
    updated_at: datetime = Field(default_factory=utcnow)


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
    origin: str = Field(default="demo", index=True)   # data mode this row belongs to
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
    origin: str = Field(default="demo", index=True)   # data mode this row belongs to
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
    origin: str = Field(default="demo", index=True)   # data mode this row belongs to
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

    # --- Casework (who owns it, how fast we responded, was it real?) ---
    # These turn the platform from "it detected something" into an auditable case
    # record, and are the raw material for the MTTA/MTTR/false-positive metrics
    # that prove how much analyst time the automation actually replaces.
    assigned_to: Optional[str] = Field(default=None, index=True)   # account username
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    closed_reason: str = ""            # true_positive | false_positive | benign

    created_at: datetime = Field(default_factory=utcnow, index=True)
    updated_at: datetime = Field(default_factory=utcnow)


class IncidentNote(SQLModel, table=True):
    """An analyst's note on an incident — the case's written record."""

    id: Optional[int] = Field(default=None, primary_key=True)
    incident_id: int = Field(foreign_key="incident.id", index=True)
    author: str = Field(default="system", index=True)
    body: str = ""
    created_at: datetime = Field(default_factory=utcnow, index=True)


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
    origin: str = Field(default="demo", index=True)   # data mode this row belongs to
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
    origin: str = Field(default="demo", index=True)   # data mode this row belongs to
    generated_at: datetime = Field(default_factory=utcnow, index=True)


class NotificationChannel(SQLModel, table=True):
    """A delivery channel for security alerts — email, Microsoft Teams or Slack.

    Mirrors ``Connection``: non-secret settings live in ``config`` (safe to
    return); secret credentials (SMTP password, webhook URL) are Fernet-encrypted
    in ``secrets_enc`` and never returned by the API. Opt-in — no channels exist
    until an admin adds one, so demo mode is never spammed.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    kind: str = Field(index=True)                     # "email" | "teams" | "slack"
    display_name: str = ""
    enabled: bool = True
    # Only incidents at/above this severity notify this channel.
    min_severity: str = "high"                        # low|medium|high|critical
    notify_on_incident: bool = True
    notify_on_approval: bool = True                   # escalate pending manager approvals
    # Platform self-monitoring alerts (connector down, ingestion stopped). These
    # deliberately IGNORE min_severity — a blind SOC is always critical.
    notify_on_health: bool = True
    config: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    secrets_enc: str = ""                             # Fernet-encrypted JSON of secret fields
    status: str = "unknown"                           # unknown | connected | error
    last_error: str = ""
    last_sent: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class Notification(SQLModel, table=True):
    """A single alert delivery — audit trail, in-app feed, and dedup key.

    Before sending we check whether a ``sent`` notification already exists for the
    same (incident_id, channel_id, kind) at the same severity, so an incident that
    is re-touched every ingest cycle is not re-alerted; a severity *increase* is a
    new record (escalation).
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    channel_id: Optional[int] = Field(default=None, foreign_key="notificationchannel.id", index=True)
    incident_id: Optional[int] = Field(default=None, foreign_key="incident.id", index=True)
    action_id: Optional[int] = Field(default=None, foreign_key="auditaction.id", index=True)
    kind: str = "incident"                            # incident | approval | digest | test
    severity: str = "medium"                          # incident severity at send time
    subject: str = ""
    body: str = ""
    status: str = "sent"                              # sent | failed | skipped
    detail: str = ""                                  # error / skip reason
    origin: str = Field(default="demo", index=True)   # data mode this row belongs to
    created_at: datetime = Field(default_factory=utcnow, index=True)
