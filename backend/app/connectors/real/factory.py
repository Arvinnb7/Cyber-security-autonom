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


def get_action_connector(session: Session, provider: str) -> RealConnector | None:
    """Return a built connector from the first enabled connection for a provider."""
    conn = session.exec(
        select(Connection).where(Connection.provider == provider, Connection.enabled == True)  # noqa: E712
    ).first()
    return build_connector(conn) if conn else None


# Skip a connection for a while after this many consecutive failures (backoff).
_MAX_FAILURES = 5


def poll_enabled_connections(session: Session):
    """Incrementally fetch events from all enabled, implemented connections.

    Uses each connection's ``sync_cursor`` so only new events are pulled, applies
    a simple consecutive-failure backoff, and records health. Never raises — a
    broken integration is recorded and skipped.
    """
    connections = session.exec(select(Connection).where(Connection.enabled == True)).all()  # noqa: E712
    raw_events = []
    for conn in connections:
        connector = build_connector(conn)
        if connector is None:
            continue
        # Backoff: after too many failures, only retry occasionally.
        if conn.consecutive_failures >= _MAX_FAILURES and conn.consecutive_failures % 5 != 0:
            conn.consecutive_failures += 1
            session.add(conn)
            continue
        try:
            events = connector.fetch_events(conn.sync_cursor or None)
            raw_events.extend(events)
            new_cursor = connector.cursor_from(events)
            if new_cursor:
                conn.sync_cursor = new_cursor
            conn.status = "connected"
            conn.last_error = ""
            conn.last_sync = utcnow()
            conn.consecutive_failures = 0
        except ConnectorError as exc:
            conn.status = "error"
            conn.last_error = str(exc)
            conn.consecutive_failures += 1
            logger.warning("connection %s (%s) error: %s", conn.id, conn.provider, exc)
        except Exception as exc:  # noqa: BLE001
            conn.status = "error"
            conn.last_error = f"Unexpected: {exc}"
            conn.consecutive_failures += 1
            logger.exception("connection %s poll failed", conn.id)
        conn.updated_at = utcnow()
        session.add(conn)
    session.commit()
    return raw_events
