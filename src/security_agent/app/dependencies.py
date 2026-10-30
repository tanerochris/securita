"""Shared route dependencies: current user + role gates."""

import secrets

from fastapi import Cookie, Depends, Form, HTTPException, status
from itsdangerous import BadSignature, TimestampSigner

from security_agent.app import accounts as svc
from security_agent.db.keys import get_signing_key
from security_agent.db.models import Role, User

SESSION_COOKIE = "app_session"


def _signer() -> TimestampSigner:
    return TimestampSigner(get_signing_key(), salt="csrf")


def make_csrf() -> str:
    return _signer().sign(secrets.token_urlsafe(16)).decode()


def require_csrf(csrf: str = Form("")) -> None:
    """Synchronizer token check for every state-changing POST."""
    try:
        _signer().unsign(csrf, max_age=3600)
    except BadSignature as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Bad CSRF token.") from exc


def get_current_user(session: str | None = Cookie(default=None, alias=SESSION_COOKIE)) -> User:
    if not session:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Login required.")
    user = svc.validate_session(session)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired.")
    return user


def require_owner(user: User = Depends(get_current_user)) -> User:
    if user.role != Role.OWNER:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Owner only.")
    return user


def require_approver(user: User = Depends(get_current_user)) -> User:
    if user.role not in (Role.OWNER, Role.MAINTAINER):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Owner or Maintainer only.")
    return user


def require_developer(user: User = Depends(get_current_user)) -> User:
    if user.role not in (Role.OWNER, Role.MAINTAINER, Role.DEVELOPER):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Developer or above.")
    return user
