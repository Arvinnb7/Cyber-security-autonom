"""Encrypt credential secrets at rest (Fernet, key derived from JWT secret)."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

logger = logging.getLogger("sentinel.crypto")


@lru_cache
def _fernet() -> Fernet:
    # Prefer a dedicated encryption key; fall back to one derived from jwt_secret
    # (kept for backward compatibility, but warn since it couples the two).
    source = settings.encryption_key
    if not source:
        logger.warning("SENTINEL_ENCRYPTION_KEY not set — deriving credential key from jwt_secret. "
                       "Set a dedicated key in production.")
        source = settings.jwt_secret
    key = base64.urlsafe_b64encode(hashlib.sha256(source.encode()).digest())
    return Fernet(key)


def encrypt_dict(data: dict) -> str:
    if not data:
        return ""
    return _fernet().encrypt(json.dumps(data).encode()).decode()


def decrypt_dict(blob: str) -> dict:
    if not blob:
        return {}
    try:
        return json.loads(_fernet().decrypt(blob.encode()).decode())
    except (InvalidToken, ValueError):
        return {}
