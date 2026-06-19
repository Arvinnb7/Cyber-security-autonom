"""Connector abstraction (F1).

Every security source — real (Microsoft 365, CrowdStrike, ...) or simulated —
implements ``BaseConnector``. Adding a *real* integration later is just a new
subclass that talks to the vendor API; the rest of the pipeline is unchanged.
"""
from __future__ import annotations

import abc
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.core.time import utcnow


class RawEvent(BaseModel):
    """A source-native event, before normalization."""

    source: str
    timestamp: datetime = Field(default_factory=utcnow)
    category: str = "authentication"
    action: str = ""
    actor_username: str | None = None
    src_ip: str | None = None
    country: str | None = None
    city: str | None = None
    target_asset: str | None = None
    severity: int = 1
    raw: dict[str, Any] = Field(default_factory=dict)


class ActionResult(BaseModel):
    success: bool
    detail: str = ""


class BaseConnector(abc.ABC):
    """Interface implemented by every data source."""

    #: stable machine name used as ``Event.source``
    name: str = "base"
    #: human label for the UI
    label: str = "Base Connector"
    #: response actions this connector can perform (F8)
    supported_actions: tuple[str, ...] = ()

    @abc.abstractmethod
    def fetch_events(self) -> list[RawEvent]:
        """Pull the latest events from the source."""

    def execute_action(self, action_type: str, target: str) -> ActionResult:
        """Perform a response action. Simulated connectors just acknowledge it."""
        if action_type not in self.supported_actions:
            return ActionResult(success=False, detail=f"{self.label} does not support {action_type}")
        return ActionResult(success=True, detail=f"{action_type} executed on {target} via {self.label}")
