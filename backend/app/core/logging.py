"""Logging setup: human-readable in dev, structured JSON in production."""
from __future__ import annotations

import logging

from app.core.config import settings


def setup_logging() -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler()
    if settings.json_logs:
        from pythonjsonlogger import jsonlogger

        handler.setFormatter(jsonlogger.JsonFormatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"))
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(name)s %(levelname)s %(message)s"))
    root.addHandler(handler)
