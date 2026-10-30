"""GitHub/GitLab connect via personal access tokens (PAT-only).

This install is self-hosted by professionals, so there is no OAuth app
to register and no hosted redirect to operate: the user creates a PAT on
their provider (any github.com/GitHub Enterprise/GitLab instance),
pastes it once, and it is validated, encrypted, and reused for every
repo they pick. Tokens sit in `encrypted_tokens` and are never
re-viewed (NFR-4). Rotation is pasting a fresh PAT; revocation is
deleting it at the provider plus Disconnect here.
"""

from urllib.parse import urlparse

import httpx
from sqlalchemy import delete, select, update

from security_agent.audit import get_shared_log
from security_agent.config import get_settings
from security_agent.crypto import decrypt_field, encrypt_field
from security_agent.db.keys import get_encryption_key
from security_agent.db.models import (
    ConnectionAuth,
    EncryptedToken,
    GitProvider,
    ProviderConnection,
    Repo,
)
from security_agent.db.session import session_scope

audit = get_shared_log()

_TIMEOUT = 15

_ACCESS_OWNER = "provider-conn:{}:access"  # noqa: S105 - owner label

# PAT scopes the operator should grant (shown in the connect UI/docs):
# GitHub classic `repo`, or fine-grained Contents + Pull requests RW;
# GitLab `api` (MR create/merge needs it).
PAT_SCOPES: dict[GitProvider, str] = {
    GitProvider.GITHUB: "repo (classic) or Contents + Pull requests read/write (fine-grained)",
    GitProvider.GITLAB: "api",
}


class ProviderError(ValueError):
    """User-facing provider failure (bad token, bad host, …)."""


def normalize_base_url(raw: str) -> str:
    """Canonical web root: scheme + host (+ optional subpath), no trailing /."""
    text = (raw or "").strip().rstrip("/")
    parsed = urlparse(text)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise ProviderError("Provider URL must be an http(s) URL, e.g. https://gitlab.com.")
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1"}:
        raise ProviderError("Provider URL must use https (http is localhost-only).")
    return text


def default_base_url(provider: GitProvider) -> str:
    s = get_settings()
    return normalize_base_url(
        s.github_base_url if provider == GitProvider.GITHUB else s.gitlab_base_url
    )


def api_base(provider: GitProvider, base_url: str) -> str:
    if provider == GitProvider.GITHUB:
        host = urlparse(base_url).netloc.split("@")[-1]
        return "https://api.github.com" if host == "github.com" else f"{base_url}/api/v3"
    return f"{base_url}/api/v4"


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def _store_secret(owner: str, plaintext: str) -> None:
    from sqlalchemy.exc import IntegrityError

    ciphertext = encrypt_field(plaintext, get_encryption_key())
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


def _load_secret(owner: str) -> str | None:
    with session_scope() as db:
        row = db.scalar(select(EncryptedToken).where(EncryptedToken.owner == owner))
        if row is None:
            return None
        return decrypt_field(row.ciphertext, get_encryption_key(), purpose="provider-conn")


def _delete_secrets(connection_id: int) -> None:
    # Legacy OAuth rows may also hold a refresh token; clear both labels.
    owners = [_ACCESS_OWNER.format(connection_id), f"provider-conn:{connection_id}:refresh"]
    with session_scope() as db:
        db.execute(delete(EncryptedToken).where(EncryptedToken.owner.in_(owners)))


def fetch_user(provider: GitProvider, base_url: str, token: str) -> dict[str, str]:
    """{external_id, username} for a token; ProviderError when rejected."""
    try:
        r = httpx.get(
            f"{api_base(provider, base_url)}/user", headers=_headers(token), timeout=_TIMEOUT
        )
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        raise ProviderError("Provider rejected that credential.") from exc
    username = data.get("login") or data.get("username")
    if data.get("id") is None or not username:
        raise ProviderError("Provider returned an unexpected identity response.")
    return {"external_id": str(data["id"]), "username": str(username)}


def connect_pat(
    user_id: int, provider: GitProvider, base_url: str, token: str
) -> ProviderConnection:
    """Validate a personal access token against the provider, then store it.

    Reconnecting the same account replaces the stored token (rotation).
    """
    token = (token or "").strip()
    if not token:
        raise ProviderError("Paste a personal access token.")
    base = normalize_base_url(base_url or default_base_url(provider))
    identity = fetch_user(provider, base, token)
    with session_scope() as db:
        row = db.scalar(
            select(ProviderConnection).where(
                ProviderConnection.user_id == user_id,
                ProviderConnection.provider == provider,
                ProviderConnection.base_url == base,
                ProviderConnection.external_id == identity["external_id"],
            )
        )
        if row is None:
            row = ProviderConnection(
                user_id=user_id,
                provider=provider,
                base_url=base,
                auth_type=ConnectionAuth.PAT,
                external_id=identity["external_id"],
                username=identity["username"],
                scopes=[],
                token_expires_at=None,
            )
            db.add(row)
        else:
            row.auth_type = ConnectionAuth.PAT
            row.username = identity["username"]
            row.token_expires_at = None
        db.flush()
        connection_id = row.id
        db.expunge(row)
    _store_secret(_ACCESS_OWNER.format(connection_id), token)
    audit.append(
        action_class="credential",
        decision="allow",
        line=f"provider-conn={connection_id} {provider.value} pat connected",
    )
    return row


def list_connections(user_id: int) -> list[ProviderConnection]:
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(ProviderConnection)
                .where(ProviderConnection.user_id == user_id)
                .order_by(ProviderConnection.id)
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


def get_connection(connection_id: int) -> ProviderConnection | None:
    with session_scope() as db:
        row = db.get(ProviderConnection, connection_id)
        if row is not None:
            db.expunge(row)
        return row


def get_valid_token(connection_id: int) -> str | None:
    """Stored PAT for a connection (PATs do not refresh; rotate by reconnecting)."""
    if get_connection(connection_id) is None:
        return None
    return _load_secret(_ACCESS_OWNER.format(connection_id))


def disconnect(connection_id: int, user_id: int) -> bool:
    """Delete a connection locally. Repos keep working via any per-repo
    token; their connection link is cleared. Revoke the PAT at the
    provider too — Disconnect here cannot reach into the provider."""
    conn = get_connection(connection_id)
    if conn is None or conn.user_id != user_id:
        return False
    _delete_secrets(connection_id)
    with session_scope() as db:
        db.execute(
            update(Repo).where(Repo.connection_id == connection_id).values(connection_id=None)
        )
        row = db.get(ProviderConnection, connection_id)
        if row is not None:
            db.delete(row)
    audit.append(
        action_class="credential",
        decision="allow",
        line=f"provider-conn={connection_id} disconnected",
    )
    return True


def list_provider_repos(connection_id: int, user_id: int) -> list[dict]:
    """Repos the connection can see (first 100, most recently active first)."""
    conn = get_connection(connection_id)
    if conn is None or conn.user_id != user_id:
        raise ProviderError("Unknown connection.")
    token = get_valid_token(connection_id)
    if not token:
        raise ProviderError("Connection has no stored token; reconnect it.")
    api = api_base(conn.provider, conn.base_url)
    try:
        if conn.provider == GitProvider.GITHUB:
            r = httpx.get(
                f"{api}/user/repos",
                headers=_headers(token),
                params={"per_page": 100, "sort": "updated"},
                timeout=_TIMEOUT,
            )
            r.raise_for_status()
            return [
                {
                    "full_name": str(item.get("full_name") or ""),
                    "clone_url": str(item.get("clone_url") or ""),
                    "private": bool(item.get("private")),
                    "default_branch": str(item.get("default_branch") or ""),
                }
                for item in r.json()
                if item.get("clone_url")
            ]
        r = httpx.get(
            f"{api}/projects",
            headers=_headers(token),
            params={"membership": "true", "per_page": 100, "order_by": "last_activity_at"},
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        return [
            {
                "full_name": str(item.get("path_with_namespace") or ""),
                "clone_url": str(item.get("http_url_to_repo") or ""),
                "private": item.get("visibility") != "public",
                "default_branch": str(item.get("default_branch") or ""),
            }
            for item in r.json()
            if item.get("http_url_to_repo")
        ]
    except ProviderError:
        raise
    except Exception as exc:
        raise ProviderError("Could not list repositories from the provider.") from exc
