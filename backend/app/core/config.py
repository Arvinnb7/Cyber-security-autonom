"""Central configuration. All tunables live here so the platform stays config-driven."""
from __future__ import annotations

from functools import lru_cache

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SENTINEL_", extra="ignore")

    # --- App ---
    app_name: str = "Sentinel"
    environment: str = "dev"
    database_url: str = "sqlite:///./sentinel.db"
    # Public base URL of the frontend, used to build deep links to incidents in
    # outbound alerts (email/Teams/Slack).
    app_base_url: str = "http://localhost:3000"

    # --- Alerting (F: operational notifications) ---
    # Master switch. Channels are opt-in (configured in the DB) — nothing is sent
    # until an admin adds a channel, so demo mode is never spammed.
    notifications_enabled: bool = True
    # Re-notify a still-pending manager approval after this many minutes (escalation).
    approval_escalation_minutes: int = 30

    # --- Self-monitoring (watchdog) ------------------------------------------
    # A SOC that replaces human watchers must notice when it goes blind. If no
    # events have been ingested for this long (live mode, with an enabled
    # connection), the platform alerts instead of silently showing "0 threats".
    health_stale_minutes: int = 30
    # Consider the scheduler dead if it hasn't run a cycle for this long.
    health_cycle_stale_minutes: int = 15
    # Re-alert an unchanged, still-degraded state at most this often.
    health_alert_cooldown_minutes: int = 60
    # A connection is "down" after this many consecutive poll failures.
    health_connector_failures: int = 3

    # --- Data mode -----------------------------------------------------------
    # "demo" => seed demo org + attack scenarios and run the simulators.
    # "live" => no demo data, no simulators; only real connectors feed the DB.
    # Accepts either DATA_MODE or SENTINEL_DATA_MODE.
    data_mode: str = Field(default="demo", validation_alias=AliasChoices("DATA_MODE", "SENTINEL_DATA_MODE"))

    # --- Auth ---
    jwt_secret: str = "change-me-in-production-please"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 12
    # Bootstrap admin: seeded (hashed) into the Account table on first boot only.
    admin_username: str = "admin"
    admin_password: str = "admin"

    # Dedicated key for encrypting connector credentials at rest. Falls back to a
    # value derived from jwt_secret if unset (with a warning) — set this in prod.
    encryption_key: str | None = None

    # --- Transport / hardening ---
    # Comma-separated list of allowed browser origins for CORS.
    cors_origins: str = "http://localhost:3000"

    # --- AI (Claude) ---
    anthropic_api_key: str | None = None
    ai_model_deep: str = "claude-opus-4-8"      # F5/F6 deep incident analysis
    ai_model_fast: str = "claude-sonnet-4-6"    # F7 chat + light summaries
    ai_max_tokens: int = 1500

    # --- Simulation / scheduler ---
    sim_enabled: bool = True
    ingest_interval_seconds: int = 20            # how often connectors are polled
    seed_on_startup: bool = True                 # generate demo scenarios at boot
    # Run the background scheduler in this process. Disable on API workers and run
    # it in a single dedicated worker container in production.
    run_scheduler: bool = True
    retention_days: int = 90                     # purge events/signals older than this

    # --- Observability ---
    sentry_dsn: str | None = None                # enable error tracking when set
    metrics_enabled: bool = True                 # expose Prometheus /metrics
    json_logs: bool = False                      # structured JSON logging (prod)
    # Where user-provided attack-model files live (the plug-in point). Empty =>
    # default to <repo>/data/attack_models resolved relative to this package.
    attack_models_dir: str = ""
    # Detection catalog (the MVP source of truth). Empty => backend/data/detection_catalog.json
    detection_catalog_path: str = ""

    # --- Detection thresholds (calibrate per deployment) ---------------------
    # Every organization is different: a media team downloads far more files than
    # a law firm. These are the tuning knobs an operator adjusts to cut false
    # positives without touching code.
    impossible_travel_kmh: float = 900.0   # implied speed that can't be real travel
    mass_download_count: int = 15          # DET-002 bulk download
    exfil_download_count: int = 20         # DET-006 exfiltration volume
    email_spam_count: int = 10             # DET-002 outbound spam burst
    ransomware_rename_count: int = 20      # DET-005 rapid file renames
    phishing_recipient_count: int = 5      # DET-003 campaign breadth
    admin_change_count: int = 3            # DET-007 repeated permission changes
    lateral_host_count: int = 3            # DET-009 hosts touched

    # --- Risk scoring weights (F4) — the heart of the product ---
    # final_score = weighted blend of the four sub-scores, then 0..100
    weight_threat: float = 0.40
    weight_user: float = 0.20
    weight_asset: float = 0.20
    weight_business: float = 0.20

    @property
    def ai_enabled(self) -> bool:
        return bool(self.anthropic_api_key)

    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() in ("prod", "production")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def insecure_defaults(self) -> list[str]:
        """Names of secrets still at their insecure built-in default."""
        problems = []
        if self.jwt_secret == "change-me-in-production-please":
            problems.append("SENTINEL_JWT_SECRET")
        if self.admin_password == "admin":
            problems.append("SENTINEL_ADMIN_PASSWORD")
        if not self.encryption_key:
            problems.append("SENTINEL_ENCRYPTION_KEY")
        return problems

    @property
    def is_demo(self) -> bool:
        return self.data_mode.strip().lower() != "live"

    @property
    def is_live(self) -> bool:
        return not self.is_demo


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
