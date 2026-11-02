"""Account + session service (FR-10). All persistence lives here; routers stay thin."""

import hashlib
import logging
import secrets
import threading
from collections import OrderedDict
from datetime import UTC, datetime, timedelta

import httpx
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import func, select

from security_agent.crypto import decrypt_field, encrypt_field
from security_agent.db.keys import ensure_master_key, get_encryption_key
from security_agent.db.models import Invite, PasswordReset, Role, Session, User
from security_agent.db.session import session_scope

hasher = PasswordHasher()

MIN_PASSWORD_LEN = 12
INVITE_TTL = timedelta(hours=72)
RESET_TTL = timedelta(hours=1)
SESSION_ABSOLUTE_TTL = timedelta(hours=24)
SESSION_IDLE_TTL = timedelta(minutes=30)
IDLE_TOUCH_INTERVAL = timedelta(seconds=60)

log = logging.getLogger(__name__)

# Bounded cache: digest -> breached (avoids repeated HIBP hits on hot paths).
_breach_cache: OrderedDict[str, bool] = OrderedDict()
_BREACH_CACHE_MAX = 512
# Fail-open backoff: prefix -> last failure time. Avoids a 2s stall per signup
# when HIBP is unreachable; entries expire after _BREACH_FAIL_TTL.
_breach_fail_at: dict[str, datetime] = {}
_BREACH_FAIL_TTL = timedelta(minutes=5)
_BREACH_TIMEOUT = 2.0
# Guards both maps: signup/login routes run in a threadpool.
_breach_lock = threading.Lock()


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
    if is_breached(password):
        raise ValueError("Password appears in a known breach; choose another.")
    return hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    if not password_hash:
        return False
    try:
        return hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def is_breached(password: str) -> bool:
    """HIBP k-anonymity check. Fail-open when offline (log, don't block)."""
    digest = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
    prefix = digest[:5]
    with _breach_lock:
        if digest in _breach_cache:
            return _breach_cache[digest]
        failed_at = _breach_fail_at.get(prefix)
        if failed_at and datetime.now(UTC) - failed_at < _BREACH_FAIL_TTL:
            return False
    try:
        r = httpx.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=_BREACH_TIMEOUT)
        r.raise_for_status()
        result = any(line.split(":")[0] == digest[5:] for line in r.text.splitlines())
    except Exception as exc:  # noqa: BLE001 - fail-open by design
        log.warning("breach-check unavailable, failing open: %s", exc)
        with _breach_lock:
            _breach_fail_at[prefix] = datetime.now(UTC)
            if len(_breach_fail_at) > _BREACH_CACHE_MAX:
                _breach_fail_at.pop(next(iter(_breach_fail_at)))
        return False
    with _breach_lock:
        _breach_fail_at.pop(prefix, None)
        _breach_cache[digest] = result
        if len(_breach_cache) > _BREACH_CACHE_MAX:
            _breach_cache.popitem(last=False)
    return result


def user_count() -> int:
    with session_scope() as db:
        return db.scalar(select(func.count()).select_from(User)) or 0


def first_user_role(existing_count: int) -> Role:
    """First signup is Owner; registration closes afterwards (FR-10 D5)."""
    return Role.OWNER if existing_count == 0 else Role.REPORTER


def create_user(email: str, password_hash: str | None, role: Role) -> User:
    with session_scope() as db:
        user = User(email=email, password_hash=password_hash, role=role)
        db.add(user)
        db.flush()
        db.refresh(user)
        db.expunge(user)
        return user


def get_user_by_email(email: str) -> User | None:
    with session_scope() as db:
        user = db.scalar(select(User).where(User.email == email))
        if user is not None:
            db.expunge(user)
        return user


def issue_invite(email: str, role: Role) -> str:
    """Create invite; returns the single-use token (shown once, stored as hash)."""
    token = secrets.token_urlsafe(32)
    with session_scope() as db:
        db.add(
            Invite(
                email=email,
                role=role,
                token_hash=hashlib.sha256(token.encode()).hexdigest(),
                expires_at=datetime.now(UTC) + INVITE_TTL,
            )
        )
    return token


def _aware(dt: datetime) -> datetime:
    """SQLite returns naive datetimes; Postgres returns aware. Normalize."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def redeem_invite(token: str) -> Invite | None:
    """Return a valid unused invite, or None (expired/used/unknown)."""
    digest = hashlib.sha256(token.encode()).hexdigest()
    with session_scope() as db:
        invite = db.scalar(select(Invite).where(Invite.token_hash == digest))
        if invite is None or invite.used_at is not None:
            return None
        if _aware(invite.expires_at) < datetime.now(UTC):
            return None
        invite.used_at = datetime.now(UTC)
        db.flush()
        db.expunge(invite)
        return invite


def _owner_count(db) -> int:
    return (
        db.scalar(
            select(func.count())
            .select_from(User)
            .where(User.role == Role.OWNER, User.disabled.is_(False))
        )
        or 0
    )


def owner_count() -> int:
    with session_scope() as db:
        return _owner_count(db)


def can_remove_owner() -> bool:
    """Last Owner cannot be disabled or demoted (FR-10 D5)."""
    return owner_count() > 1


def disable_user(user_id: int) -> None:
    """Disable-only v1: login blocked, sessions revoked, audit kept."""
    with session_scope() as db:
        user = db.get(User, user_id)
        if user is None:
            return
        if user.role == Role.OWNER and _owner_count(db) <= 1:
            raise ValueError("Cannot disable the last Owner.")
        user.disabled = True
        db.query(Session).filter(Session.user_id == user_id).delete()


def set_role(user_id: int, role: Role) -> None:
    with session_scope() as db:
        user = db.get(User, user_id)
        if user is None:
            return
        if user.role == Role.OWNER and role != Role.OWNER and _owner_count(db) <= 1:
            raise ValueError("Cannot demote the last Owner.")
        user.role = role
        db.query(Session).filter(Session.user_id == user_id).delete()


def list_users() -> list[User]:
    with session_scope() as db:
        users = list(db.scalars(select(User).order_by(User.id)))
        for u in users:
            db.expunge(u)
        return users


def create_session(user_id: int) -> str:
    session_id = secrets.token_urlsafe(32)
    with session_scope() as db:
        db.add(Session(session_id=session_id, user_id=user_id))
    return session_id


def validate_session(session_id: str) -> User | None:
    """Absolute 24h + idle 30min; touch last_seen on success. Revoked on disable."""
    now = datetime.now(UTC)
    with session_scope() as db:
        sess = db.scalar(select(Session).where(Session.session_id == session_id))
        if sess is None:
            return None
        if now - _aware(sess.created_at) > SESSION_ABSOLUTE_TTL:
            db.delete(sess)
            return None
        if now - _aware(sess.last_seen_at) > SESSION_IDLE_TTL:
            db.delete(sess)
            return None
        user = db.get(User, sess.user_id)
        if user is None or user.disabled:
            db.delete(sess)
            return None
        # Throttle writes: at most one touch per IDLE_TOUCH_INTERVAL.
        if now - _aware(sess.last_seen_at) >= IDLE_TOUCH_INTERVAL:
            sess.last_seen_at = now
        db.flush()
        db.expunge(user)
        return user


def revoke_session(session_id: str) -> None:
    with session_scope() as db:
        db.query(Session).filter(Session.session_id == session_id).delete()


def list_user_sessions(user_id: int) -> list[Session]:
    with session_scope() as db:
        rows = list(db.scalars(select(Session).where(Session.user_id == user_id)))
        for r in rows:
            db.expunge(r)
        return rows


def _decrypt_totp_secret(stored: str) -> str | None:
    """Decrypt with the encryption subkey; fall back to master for pre-subkey rows."""
    master, _ = ensure_master_key()
    for key in (get_encryption_key(), master):
        try:
            return decrypt_field(stored, key, purpose="account:totp")
        except Exception:  # noqa: BLE001, S112 - try next key, None if all fail
            continue
    return None


def setup_totp(user_id: int) -> tuple[str, list[str]]:
    """Opt-in TOTP (FR-10 D3a). Secret encrypted at rest (AES-256-GCM)."""
    secret = pyotp.random_base32()
    codes = [secrets.token_hex(4) for _ in range(8)]
    key = get_encryption_key()
    with session_scope() as db:
        user = db.get(User, user_id)
        if user is None:
            raise ValueError("Unknown user.")
        user.totp_secret = encrypt_field(secret, key)
        user.backup_code_hashes = [hasher.hash(c) for c in codes]
        email = user.email
    url = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="Scurita")
    return url, codes


def get_user_by_email_or_id(user_id: int) -> str:
    with session_scope() as db:
        user = db.get(User, user_id)
        return user.email if user else ""


def issue_reset(email: str) -> str | None:
    """Create a reset token (hash-stored). None if no such account (no enum)."""
    token = secrets.token_urlsafe(32)
    with session_scope() as db:
        user = db.scalar(select(User).where(User.email == email))
        if user is None or user.disabled:
            return None
        db.add(
            PasswordReset(
                user_id=user.id,
                token_hash=hashlib.sha256(token.encode()).hexdigest(),
                expires_at=datetime.now(UTC) + RESET_TTL,
            )
        )
    return token


def redeem_reset(token: str, new_password_hash: str) -> bool:
    """Consume a reset token; set password, revoke all sessions. False if bad."""
    digest = hashlib.sha256(token.encode()).hexdigest()
    with session_scope() as db:
        row = db.scalar(select(PasswordReset).where(PasswordReset.token_hash == digest))
        if row is None or row.used_at is not None:
            return False
        if _aware(row.expires_at) < datetime.now(UTC):
            return False
        user = db.get(User, row.user_id)
        if user is None or user.disabled:
            return False
        row.used_at = datetime.now(UTC)
        user.password_hash = new_password_hash
        db.query(Session).filter(Session.user_id == user.id).delete()
        return True


def link_sso(user_id: int, provider: str, subject: str) -> None:
    with session_scope() as db:
        user = db.get(User, user_id)
        if user is None:
            return
        user.sso_provider = provider
        user.sso_subject = subject


def resolve_sso_user(email: str, subject: str, provider: str, invite_token: str = "") -> User:
    """SSO sign-in decision (FR-11): linked (provider, sub) wins, else gated create."""
    existing = get_user_by_email(email)
    if existing is not None:
        if existing.disabled:
            raise PermissionError("Account disabled.")
        if existing.sso_subject:
            if existing.sso_subject != subject or (
                existing.sso_provider and existing.sso_provider != provider
            ):
                raise PermissionError("SSO identity mismatch for this account.")
        else:
            link_sso(existing.id, provider, subject)
        return existing
    if user_count() == 0:
        user = create_user(email, None, Role.OWNER)
    elif invite_token:
        invite = redeem_invite(invite_token)
        if invite is None or invite.email.lower() != email.lower():
            raise PermissionError("Valid invite required.")
        user = create_user(email, None, invite.role)
    else:
        raise PermissionError("Invite required; ask the Owner.")
    link_sso(user.id, provider, subject)
    return user


def verify_totp_or_backup(user: User, code: str) -> bool:
    with session_scope() as db:
        row = db.get(User, user.id)
        if row is None:
            return False
        if row.totp_secret:
            raw_secret = _decrypt_totp_secret(row.totp_secret)
            if raw_secret and pyotp.TOTP(raw_secret).verify(code, valid_window=1):
                return True
        for i, h in enumerate(row.backup_code_hashes or []):
            try:
                hasher.verify(h, code)
            except VerifyMismatchError:
                continue
            hashes = list(row.backup_code_hashes or [])
            hashes.pop(i)  # single-use
            row.backup_code_hashes = hashes
            return True
        return False
