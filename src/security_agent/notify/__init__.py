"""FR-13 notifications: severity-routed events over email/Slack/webhook.

Events declare their severity at the call site; routes map severities
to channels. Approval requests fan out to ALL channels (FR-9 D5).
Delivery failures audit-warn and never raise past `notify_event`, and
callers emit after commit (H5 G8 precedent). Channel secrets live
encrypted under `notify-channel:{id}` and are never re-viewed.
"""

import json
import logging
from urllib.parse import urlparse

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from security_agent.audit import get_shared_log
from security_agent.crypto import decrypt_field, encrypt_field
from security_agent.db.keys import get_encryption_key
from security_agent.db.models import ChannelKind, EncryptedToken, NotifyChannel, NotifyRoute
from security_agent.db.session import session_scope
from security_agent.notify.transports import (
    NotifyError,
    send_email,
    send_slack,
    send_webhook,
    validate_email_config,
    webhook_payload,
)

log = logging.getLogger(__name__)
audit = get_shared_log()

SEVERITIES = ("critical", "high", "medium", "low", "info")

_SECRET_OWNER = "notify-channel:{}"  # noqa: S105 - owner label, not a credential

_MAX_ATTACHMENTS = 5
_MAX_ATTACHMENT_BYTES = 10_000_000


def _check_severity(severity: str) -> str:
    if severity not in SEVERITIES:
        raise ValueError(f"Unknown severity {severity!r}; want one of {SEVERITIES}.")
    return severity


def _store_secret(channel_id: int, payload: dict) -> None:
    ciphertext = encrypt_field(json.dumps(payload), get_encryption_key())
    owner = _SECRET_OWNER.format(channel_id)
    with session_scope() as db:
        try:
            with db.begin_nested():
                db.add(EncryptedToken(owner=owner, ciphertext=ciphertext))
                db.flush()
        except IntegrityError:
            row = db.scalar(select(EncryptedToken).where(EncryptedToken.owner == owner))
            if row is None:
                raise
            row.ciphertext = ciphertext


def _load_secret(channel_id: int) -> dict:
    with session_scope() as db:
        row = db.scalar(
            select(EncryptedToken).where(EncryptedToken.owner == _SECRET_OWNER.format(channel_id))
        )
        if row is None:
            return {}
        raw = decrypt_field(row.ciphertext, get_encryption_key(), purpose="notify:channel")
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _display_host(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


def _validate_name(name: str) -> str:
    if not name or len(name) > 200:
        raise ValueError("Channel name is required (max 200 chars).")
    return name.strip()


def _validate_email(config: dict) -> dict:
    try:
        return validate_email_config(dict(config or {}))
    except NotifyError as exc:
        raise ValueError(str(exc)) from exc


def _validate_hook_secret(channel_kind: ChannelKind, secret: dict) -> tuple[dict, dict]:
    """Validated (config, secret) for Slack/webhook; same rules for create/update."""
    url = secret.get("url", "")
    if not isinstance(url, str) or not url.strip() or len(url) > 2000:
        raise ValueError("A webhook URL secret is required.")
    try:
        parts = urlparse(url.strip())
    except ValueError as exc:
        raise ValueError(f"Webhook URL is invalid: {exc}") from exc
    schemes = {"https"} if channel_kind == ChannelKind.SLACK else {"http", "https"}
    if parts.scheme not in schemes or not parts.hostname:
        want = "https" if channel_kind == ChannelKind.SLACK else "http(s)"
        raise ValueError(f"Webhook URL must be {want} with a host.")
    clean = {"url": url.strip(), "signing_key": str(secret.get("signing_key", ""))[:500]}
    return {"host": _display_host(url)[:500]}, clean


def _upsert_token(db, owner: str, ciphertext: str) -> None:
    """Insert-or-update one token row inside the caller's transaction."""
    try:
        with db.begin_nested():
            db.add(EncryptedToken(owner=owner, ciphertext=ciphertext))
            db.flush()
    except IntegrityError:
        row = db.scalar(select(EncryptedToken).where(EncryptedToken.owner == owner))
        if row is None:
            raise
        row.ciphertext = ciphertext


def create_channel(
    kind: str, name: str, *, config: dict | None = None, secret: dict | None = None
) -> NotifyChannel:
    """Create a channel, validating shape; secrets go encrypted, never to config.

    Email: config {host, port, username, from_addr, to, use_tls},
    secret {password}. Slack: secret {url}. Webhook: secret
    {url, signing_key?}. New channels route all severities until the
    operator narrows them. Channel, routes, and secret commit in ONE
    transaction so a crash never leaves a secret-less channel behind.
    """
    try:
        channel_kind = ChannelKind(kind)
    except ValueError as exc:
        raise ValueError(f"Unknown channel kind {kind!r}.") from exc
    clean_name = _validate_name(name)
    secret = dict(secret or {})
    if channel_kind == ChannelKind.EMAIL:
        config = _validate_email(config or {})
    else:
        config, secret = _validate_hook_secret(channel_kind, secret)
    ciphertext = encrypt_field(json.dumps(secret), get_encryption_key()) if secret else None
    with session_scope() as db:
        row = NotifyChannel(kind=channel_kind, name=clean_name, config=config)
        db.add(row)
        db.flush()
        channel_id = row.id
        for severity in SEVERITIES:  # default: everything routes here until narrowed
            db.add(NotifyRoute(severity=severity, channel_id=channel_id))
        if ciphertext is not None:
            _upsert_token(db, _SECRET_OWNER.format(channel_id), ciphertext)
        db.expunge(row)
    audit.append(action_class="notify", decision="channel-create", line=f"channel={channel_id}")
    return row


def update_channel(
    channel_id: int, name: str, *, config: dict | None = None, secret: dict | None = None
) -> NotifyChannel:
    """Update name/config; kind is immutable, an empty secret keeps the old one.

    Same shape validation as create. Raises KeyError for unknown ids.
    """
    with session_scope() as db:
        row = db.get(NotifyChannel, channel_id)
        if row is None:
            raise KeyError(channel_id)
        channel_kind = row.kind
    clean_name = _validate_name(name)
    secret = dict(secret or {})
    new_config: dict | None
    new_secret: dict | None
    if channel_kind == ChannelKind.EMAIL:
        new_config = _validate_email(config or {})
        password = str(secret.get("password", ""))
        new_secret = None if not password.strip() else {"password": password}
    elif not str(secret.get("url", "")).strip():
        new_config = None  # empty secret: keep the stored secret and host label
        new_secret = None
    else:
        new_config, new_secret = _validate_hook_secret(channel_kind, secret)
    ciphertext = encrypt_field(json.dumps(new_secret), get_encryption_key()) if new_secret else None
    with session_scope() as db:
        row = db.get(NotifyChannel, channel_id)
        if row is None:
            raise KeyError(channel_id)
        row.name = clean_name
        if new_config is not None:
            row.config = new_config
        if new_secret is not None and ciphertext is not None:
            _upsert_token(db, _SECRET_OWNER.format(channel_id), ciphertext)
        db.flush()  # expunge drops unflushed changes; the upsert flush is not guaranteed
        db.expunge(row)
    audit.append(action_class="notify", decision="channel-update", line=f"channel={channel_id}")
    return row


def delete_channel(channel_id: int) -> bool:
    with session_scope() as db:
        row = db.get(NotifyChannel, channel_id)
        if row is None:
            return False
        db.execute(delete(NotifyRoute).where(NotifyRoute.channel_id == channel_id))
        db.execute(
            delete(EncryptedToken).where(EncryptedToken.owner == _SECRET_OWNER.format(channel_id))
        )
        db.delete(row)
    audit.append(action_class="notify", decision="channel-delete", line=f"channel={channel_id}")
    return True


def list_channels() -> list[dict]:
    """Channels with non-secret config only, plus route + secret presence."""
    with session_scope() as db:
        rows = list(db.scalars(select(NotifyChannel).order_by(NotifyChannel.id)))
        routes = list(db.scalars(select(NotifyRoute)))
        owners = {
            o
            for (o,) in db.execute(
                select(EncryptedToken.owner).where(EncryptedToken.owner.like("notify-channel:%"))
            ).all()
        }
        out = []
        for row in rows:
            out.append(
                {
                    "id": row.id,
                    "kind": row.kind.value,
                    "name": row.name,
                    "config": dict(row.config or {}),
                    "enabled": row.enabled,
                    "severities": sorted(r.severity for r in routes if r.channel_id == row.id),
                    "has_secret": _SECRET_OWNER.format(row.id) in owners,
                }
            )
            db.expunge(row)
        return out


def set_channel_enabled(channel_id: int, enabled: bool) -> bool:
    with session_scope() as db:
        row = db.get(NotifyChannel, channel_id)
        if row is None:
            return False
        row.enabled = enabled
        return True


def set_routes(severity: str, channel_ids: list[int]) -> None:
    """Replace the channel set for one severity (unknown ids rejected)."""
    _check_severity(severity)
    with session_scope() as db:
        known = {c.id for c in db.scalars(select(NotifyChannel))}
        unknown = set(channel_ids) - known
        if unknown:
            raise ValueError(f"Unknown channels: {sorted(unknown)}")
        db.execute(delete(NotifyRoute).where(NotifyRoute.severity == severity))
        for channel_id in sorted(set(channel_ids)):
            db.add(NotifyRoute(severity=severity, channel_id=channel_id))
    audit.append(
        action_class="notify", decision="routes", line=f"{severity} -> {sorted(set(channel_ids))}"
    )


def channels_for(severity: str, *, fan_out_all: bool = False) -> list[NotifyChannel]:
    """Enabled channels for a severity (or every channel for approval fan-out)."""
    _check_severity(severity)
    with session_scope() as db:
        query = select(NotifyChannel).where(NotifyChannel.enabled.is_(True))
        if not fan_out_all:
            query = query.where(
                NotifyChannel.id.in_(
                    select(NotifyRoute.channel_id).where(NotifyRoute.severity == severity)
                )
            )
        rows = list(db.scalars(query.order_by(NotifyChannel.id)))
        for r in rows:
            db.expunge(r)
        return rows


def _cap_attachments(
    attachments: list[tuple[str, bytes, str]] | None,
) -> list[tuple[str, bytes, str]] | None:
    """Email attachment guard: max 5 files, 10 MB total, the rest truncated."""
    if not attachments:
        return attachments
    capped: list[tuple[str, bytes, str]] = []
    total = 0
    for filename, payload, mime in attachments[:_MAX_ATTACHMENTS]:
        room = _MAX_ATTACHMENT_BYTES - total
        if room <= 0:
            break
        chunk = payload[:room]
        capped.append((filename, chunk, mime))
        total += len(chunk)
    return capped


def _deliver(
    channel: NotifyChannel,
    severity: str,
    subject: str,
    body: str,
    link: str,
    attachments: list[tuple[str, bytes, str]] | None = None,
) -> None:
    secret = _load_secret(channel.id)
    if channel.kind == ChannelKind.EMAIL:
        send_email(
            dict(channel.config or {}),
            str(secret.get("password", "")),
            subject,
            body,
            attachments=_cap_attachments(attachments),
        )
    elif channel.kind == ChannelKind.SLACK:
        send_slack(str(secret.get("url", "")), subject, body, link=link)
    elif channel.kind == ChannelKind.WEBHOOK:
        send_webhook(
            str(secret.get("url", "")),
            webhook_payload(severity, subject, body, link=link),
            signing_key=str(secret.get("signing_key", "")),
        )
    else:  # pragma: no cover - enum guards at creation
        raise NotifyError(f"Unknown channel kind {channel.kind!r}")


def notify_event(
    severity: str,
    subject: str,
    body: str,
    *,
    link: str = "",
    fan_out_all: bool = False,
    kind: str = "",
    attachments: list[tuple[str, bytes, str]] | None = None,
) -> dict:
    """Deliver one event; failures per channel audit-warn, never raise.

    Returns {"sent": [ids], "failed": {id: reason}}. Callers emit after
    their transaction commits so a rollback never sends a phantom alert.
    Attachments ride email channels only (digests); others ignore them.
    """
    _check_severity(severity)
    sent: list[int] = []
    failed: dict[int, str] = {}
    for channel in channels_for(severity, fan_out_all=fan_out_all):
        try:
            _deliver(channel, severity, subject, body, link, attachments)
            sent.append(channel.id)
        except (NotifyError, ValueError, OSError) as exc:
            reason = str(exc)[:300]
            failed[channel.id] = reason
            log.warning("notify: channel %d failed: %s", channel.id, reason)
    audit.append(
        action_class="notify",
        decision="event",
        line=f"kind={kind or '?'} severity={severity} sent={sent} failed={sorted(failed)}",
    )
    return {"sent": sent, "failed": failed}


def test_send(channel_id: int) -> dict:
    """Test-send one channel; returns {"ok": bool, "detail": str}."""
    with session_scope() as db:
        channel = db.get(NotifyChannel, channel_id)
        if channel is None:
            return {"ok": False, "detail": f"Unknown channel {channel_id}."}
        db.expunge(channel)
    try:
        _deliver(
            channel,
            "info",
            "security-agent test notification",
            f"Channel {channel.name!r} ({channel.kind.value}) delivers correctly.",
            "",
        )
    except (NotifyError, ValueError, OSError) as exc:
        detail = str(exc)[:300]
        audit.append(action_class="notify", decision="test-failed", line=f"channel={channel_id}")
        return {"ok": False, "detail": detail}
    audit.append(action_class="notify", decision="test-ok", line=f"channel={channel_id}")
    return {"ok": True, "detail": f"Test message sent via {channel.name}."}
