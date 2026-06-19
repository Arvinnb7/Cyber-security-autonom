"""Central configuration. All tunables live here so the platform stays config-driven."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SENTINEL_", extra="ignore")

    # --- App ---
    app_name: str = "Sentinel"
    environment: str = "dev"
    database_url: str = "sqlite:///./sentinel.db"

    # --- Auth (single-org MVP) ---
    jwt_secret: str = "change-me-in-production-please"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 12
    admin_username: str = "admin"
    admin_password: str = "admin"

    # --- AI (Claude) ---
    anthropic_api_key: str | None = None
    ai_model_deep: str = "claude-opus-4-8"      # F5/F6 deep incident analysis
    ai_model_fast: str = "claude-sonnet-4-6"    # F7 chat + light summaries
    ai_max_tokens: int = 1500

    # --- Simulation / scheduler ---
    sim_enabled: bool = True
    ingest_interval_seconds: int = 20            # how often connectors are polled
    seed_on_startup: bool = True                 # generate demo scenarios at boot
    # Where user-provided attack-model files live (the plug-in point). Empty =>
    # default to <repo>/data/attack_models resolved relative to this package.
    attack_models_dir: str = ""

    # --- Risk scoring weights (F4) — the heart of the product ---
    # final_score = weighted blend of the four sub-scores, then 0..100
    weight_threat: float = 0.40
    weight_user: float = 0.20
    weight_asset: float = 0.20
    weight_business: float = 0.20

    @property
    def ai_enabled(self) -> bool:
        return bool(self.anthropic_api_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
