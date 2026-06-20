"""Build live connectors from a stored Connection and poll enabled ones."""
from __future__ import annotations

import logging

from sqlmodel import Session, select

from app.connectors.real.base import ConnectorError, RealConnector
from app.connectors.real.microsoft365 import Microsoft365Connector
from app.core.crypto import decrypt_dict
from app.core.time import utcnow
from app.models.tables import Connection

logger = logging.getLogger("sentinel.connectors")

# provider -> connector class (Azure AD shares the Graph connector).
_REGISTRY: dict[str, type[RealConnector]] = {
    "microsoft_365": Microsoft365Connector,
    "azure": Microsoft365Connector,
}


def is_implemented(provider: str) -> bool:
    return provider in _REGISTRY


def build_connector(connection: Connection) -> RealConnector | None:
    cls = _REGISTRY.get(connection.provider)
    if cls is None:
        return None
    return cls(connection.config or {}, decrypt_dict(connection.secrets_enc))


def test_connection(connection: Connection) -> tuple[bool, str]:
    connector = build_connector(connection)
    if connector is None:
        return False, f"No live connector implemented yet for '{connection.provider}'."
    return connector.test()


def poll_enabled_connections(session: Session):
    """Fetch events from all enabled, implemented connections.

    Yields RawEvent batches and updates each connection's status/last_sync. Never
    raises — a broken integration is recorded and skipped.
    """
    connections = session.exec(select(Connection).where(Connection.enabled == True)).all()  # noqa: E712
    raw_events = []
    for conn in connections:
        connector = build_connector(conn)
        if connector is None:
            continue
        try:
            events = connector.fetch_events()
            raw_events.extend(events)
            conn.status = "connected"
            conn.last_error = ""
            conn.last_sync = utcnow()
        except ConnectorError as exc:
            conn.status = "error"
            conn.last_error = str(exc)
            logger.warning("connection %s (%s) error: %s", conn.id, conn.provider, exc)
        except Exception as exc:  # noqa: BLE001
            conn.status = "error"
            conn.last_error = f"Unexpected: {exc}"
            logger.exception("connection %s poll failed", conn.id)
        conn.updated_at = utcnow()
        session.add(conn)
    session.commit()
    return raw_events
