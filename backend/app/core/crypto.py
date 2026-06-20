"""Encrypt credential secrets at rest (Fernet, key derived from JWT secret)."""
from __future__ import annotations

import base64
import hashlib
import json
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


@lru_cache
def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.jwt_secret.encode()).digest())
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
