"""Base class for live (real) connectors that talk to vendor APIs."""
from __future__ import annotations

import abc

from app.connectors.base import ActionResult, RawEvent


class ConnectorError(Exception):
    """Raised when a live connector cannot reach or authenticate to its source."""


class RealConnector(abc.ABC):
    provider: str = "real"
    #: response actions this connector can actually execute against the vendor
    supported_actions: tuple[str, ...] = ()

    def __init__(self, config: dict, secrets: dict):
        self.config = config or {}
        self.secrets = secrets or {}

    @abc.abstractmethod
    def fetch_events(self, cursor: str | None = None) -> list[RawEvent]:
        """Pull events newer than ``cursor`` from the vendor API (incremental)."""

    def execute_action(self, action_type: str, target: str) -> ActionResult:
        """Actually perform a response action against the vendor. Override per provider."""
        return ActionResult(success=False,
                            detail=f"{self.provider} does not support action '{action_type}'")

    def cursor_from(self, events: list[RawEvent]) -> str | None:
        """Return the new sync cursor after a fetch (default: latest timestamp)."""
        if not events:
            return None
        return max(e.timestamp for e in events).isoformat()

    def test(self) -> tuple[bool, str]:
        """Validate credentials/connectivity. Returns (ok, message)."""
        try:
            self.fetch_events()
            return True, "Connection succeeded"
        except ConnectorError as exc:
            return False, str(exc)
        except Exception as exc:  # noqa: BLE001
            return False, f"Unexpected error: {exc}"
