"""Auth dependencies: current account + role-based access control (RBAC)."""
from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlmodel import Session, select

from app.core.config import settings
from app.core.db import get_session
from app.models.tables import Account

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

_credentials_exc = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def _decode(token: str | None) -> dict:
    if not token:
        raise _credentials_exc
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        raise _credentials_exc
    if not payload.get("sub"):
        raise _credentials_exc
    return payload


def get_current_user(token: str | None = Depends(oauth2_scheme)) -> str:
    """Lightweight identity: the account username from the token (no DB hit)."""
    return _decode(token)["sub"]


def get_current_account(token: str | None = Depends(oauth2_scheme),
                        session: Session = Depends(get_session)) -> Account:
    """Full account, verified against the DB and active flag."""
    payload = _decode(token)
    account = session.exec(select(Account).where(Account.username == payload["sub"])).first()
    if account is None or not account.is_active:
        raise _credentials_exc
    return account


def require_role(*roles: str):
    """Dependency factory: allow only the given roles (admin implicitly allowed)."""
    allowed = set(roles) | {"admin"}

    def _dep(account: Account = Depends(get_current_account)) -> Account:
        if account.role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=f"requires role: {', '.join(sorted(allowed))}")
        return account

    return _dep
