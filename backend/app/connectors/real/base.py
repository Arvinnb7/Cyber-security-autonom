"""Base class for live (real) connectors that talk to vendor APIs."""
from __future__ import annotations

import abc

from app.connectors.base import RawEvent


class ConnectorError(Exception):
    """Raised when a live connector cannot reach or authenticate to its source."""


class RealConnector(abc.ABC):
    provider: str = "real"

    def __init__(self, config: dict, secrets: dict):
        self.config = config or {}
        self.secrets = secrets or {}

    @abc.abstractmethod
    def fetch_events(self) -> list[RawEvent]:
        """Pull recent events from the vendor API and map them to RawEvent."""

    def test(self) -> tuple[bool, str]:
        """Validate credentials/connectivity. Returns (ok, message)."""
        try:
            self.fetch_events()
            return True, "Connection succeeded"
        except ConnectorError as exc:
            return False, str(exc)
        except Exception as exc:  # noqa: BLE001
            return False, f"Unexpected error: {exc}"
