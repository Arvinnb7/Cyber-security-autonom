"""Simulated connectors for the eight security sources (F1).

Each produces realistic *benign* background traffic on every poll. Attack
chains are injected separately by the ingestion pipeline via the scenario
generators, so detectors have a noisy-but-real haystack to work against.
"""
from __future__ import annotations

import random

from app.connectors.base import BaseConnector, RawEvent
from app.core.time import utcnow
from app.simulation.org import DEMO_ASSETS, DEMO_USERS, GEO, user_home

_BENIGN_AUTH = ("login_success", "login_success", "login_success", "logout", "mfa_success")
_BENIGN_FILE = ("file_open", "file_download", "file_upload", "file_share")


def _benign_for(source: str, categories: tuple[str, ...]) -> RawEvent:
    user = random.choice(DEMO_USERS)["username"]
    home = user_home(user)
    city, _, _ = GEO[home]
    category = random.choice(categories)
    if category == "authentication":
        action = random.choice(_BENIGN_AUTH)
    elif category == "file":
        action = random.choice(_BENIGN_FILE)
    else:
        action = random.choice(("allowed_request", "process_start", "scan_clean"))
    return RawEvent(
        source=source, timestamp=utcnow(), category=category, action=action,
        actor_username=user, src_ip=".".join(str(random.randint(1, 254)) for _ in range(4)),
        country=home, city=city,
        target_asset=random.choice(DEMO_ASSETS)["name"], severity=1,
        raw={"benign": True},
    )


class SimulatedConnector(BaseConnector):
    """A configurable benign-traffic generator standing in for a real source."""

    def __init__(self, name: str, label: str, categories: tuple[str, ...],
                 actions: tuple[str, ...], rate: tuple[int, int] = (1, 4)):
        self.name = name
        self.label = label
        self._categories = categories
        self.supported_actions = actions
        self._rate = rate

    def fetch_events(self) -> list[RawEvent]:
        count = random.randint(*self._rate)
        return [_benign_for(self.name, self._categories) for _ in range(count)]


# The eight sources requested in the spec (F1).
ALL_CONNECTORS: list[SimulatedConnector] = [
    SimulatedConnector("microsoft_365", "Microsoft 365", ("authentication", "file"),
                       ("reset_password", "kill_session", "block_user")),
    SimulatedConnector("google_workspace", "Google Workspace", ("authentication", "file"),
                       ("reset_password", "kill_session", "block_user")),
    SimulatedConnector("microsoft_defender", "Microsoft Defender", ("alert", "process", "file"),
                       ("isolate_host",)),
    SimulatedConnector("crowdstrike", "CrowdStrike", ("alert", "process"),
                       ("isolate_host", "kill_process")),
    SimulatedConnector("sentinelone", "SentinelOne", ("alert", "process"),
                       ("isolate_host", "kill_process")),
    SimulatedConnector("cloudflare", "Cloudflare", ("network",),
                       ("block_ip",)),
    SimulatedConnector("aws", "AWS", ("authentication", "network", "process"),
                       ("block_ip", "disable_key")),
    SimulatedConnector("azure", "Azure", ("authentication", "process"),
                       ("block_user", "reset_password", "kill_session")),
]

_BY_NAME = {c.name: c for c in ALL_CONNECTORS}


def get_connectors() -> list[SimulatedConnector]:
    return ALL_CONNECTORS


def get_connector(name: str) -> SimulatedConnector | None:
    return _BY_NAME.get(name)
