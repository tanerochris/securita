from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from security_agent.app import accounts as svc
from security_agent.db.models import Invite, Role, Session, User
from security_agent.db.session import session_scope


def _email(tag: str) -> str:
    return f"{tag}-{datetime.now(UTC).timestamp()}@example.com"


def test_first_signup_is_owner():
    assert svc.first_user_role(0) == Role.OWNER
    assert svc.first_user_role(3) == Role.REPORTER


def test_password_policy_and_roundtrip():
    with pytest.raises(ValueError, match="at least 12"):
        svc.hash_password("short")
    h = svc.hash_password("correct-horse-12")
    assert svc.verify_password(h, "correct-horse-12")
    assert not svc.verify_password(h, "wrong-password-1")
    assert not svc.verify_password(None, "x")


def test_invite_single_use_and_expiry():
    token = svc.issue_invite("inv@example.com", Role.DEVELOPER)
    first = svc.redeem_invite(token)
    assert first is not None and first.role == Role.DEVELOPER
    assert svc.redeem_invite(token) is None  # single-use
    assert svc.redeem_invite("bogus") is None

    token2 = svc.issue_invite("exp@example.com", Role.REPORTER)
    with session_scope() as db:
        row = db.scalar(select(Invite).where(Invite.email == "exp@example.com"))
        assert row is not None
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    assert svc.redeem_invite(token2) is None  # expired


def test_last_owner_guard():
    # Reduce to exactly one enabled Owner, whatever other tests created.
    with session_scope() as db:
        owners = db.scalars(
            select(User).where(User.role == Role.OWNER, User.disabled.is_(False))
        ).all()
        keeper = owners[0] if owners else None
        if keeper is None:
            keeper = User(email=_email("keeper"), role=Role.OWNER)
            db.add(keeper)
            db.flush()
        keeper_id = keeper.id
        for other in owners[1:]:
            other.disabled = True
    assert svc.can_remove_owner() is False
    with pytest.raises(ValueError, match="last Owner"):
        svc.disable_user(keeper_id)
    with pytest.raises(ValueError, match="last Owner"):
        svc.set_role(keeper_id, Role.DEVELOPER)


def test_session_lifecycle_and_revoke():
    email = _email("sess")
    user = svc.create_user(email, None, Role.DEVELOPER)
    sid = svc.create_session(user.id)
    assert svc.validate_session(sid) is not None
    svc.revoke_session(sid)
    assert svc.validate_session(sid) is None


def test_session_idle_expiry():
    email = _email("idle")
    user = svc.create_user(email, None, Role.DEVELOPER)
    sid = svc.create_session(user.id)
    with session_scope() as db:
        row = db.scalar(select(Session).where(Session.session_id == sid))
        assert row is not None
        row.last_seen_at = datetime.now(UTC) - timedelta(minutes=31)
    assert svc.validate_session(sid) is None


def test_guest_user_is_owner_without_password():
    guest = svc.ensure_guest_user()
    assert guest.email == svc.GUEST_EMAIL
    assert guest.role == Role.OWNER
    assert guest.password_hash is None
    assert guest.disabled is False


def test_guest_user_idempotent_and_self_healing():
    first = svc.ensure_guest_user()
    assert svc.ensure_guest_user().id == first.id
    with session_scope() as db:
        row = db.get(User, first.id)
        assert row is not None
        row.role = Role.REPORTER
        row.disabled = True
    healed = svc.ensure_guest_user()
    assert healed.id == first.id
    assert healed.role == Role.OWNER
    assert healed.disabled is False


def test_user_count_excludes_guest():
    before = svc.user_count()
    svc.ensure_guest_user()
    assert svc.user_count() == before
