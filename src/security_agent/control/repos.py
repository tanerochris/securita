"""Repo intake + credentials (FR-1 closure, FR-2 D2/D3).

Git URL or absolute local path. Provider tokens and webhook secrets live
encrypted and are never re-viewed; every decrypt is audit-logged.
"""

import hashlib
import hmac
import os
import secrets
from datetime import UTC, datetime
from urllib.parse import urlparse

from sqlalchemy import delete, or_, select, update

from security_agent.audit import get_shared_log
from security_agent.crypto import decrypt_field, encrypt_field
from security_agent.db.keys import get_encryption_key
from security_agent.db.models import (
    Approval,
    EncryptedToken,
    Finding,
    ModelUsage,
    NewsBoost,
    NewsFindingLink,
    NewsRepoRelevance,
    Proposal,
    Repo,
    RepoKind,
    RunTrigger,
    ScanRun,
    SecretBaseline,
    SecretFinding,
    Verdict,
)
from security_agent.db.session import session_scope

audit = get_shared_log()

_TOKEN_OWNER = "repo-token:{}"  # noqa: S105 - owner label, not a credential
_WEBHOOK_OWNER = "repo-webhook:{}"
_MERGE_OWNER = "repo-merge-token:{}"


def _valid_git_url(url: str) -> bool:
    if "@" in url and ":" in url and "://" not in url:
        return True  # scp-like: user@host:path
    try:
        scheme = urlparse(url).scheme
    except ValueError:
        return False
    return scheme in {"http", "https", "ssh", "git"}


def _store_secret(owner: str, plaintext: str) -> None:
    """Insert-first upsert; concurrent stores serialize on the owner key."""
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
        kind = owner.split(":")[0] if ":" in owner else "repo"
        return decrypt_field(row.ciphertext, get_encryption_key(), purpose=f"repo:{kind}")


def connect_repo(
    name: str,
    kind: RepoKind,
    *,
    url: str = "",
    local_path: str = "",
    token: str = "",
    schedule_hours: int = 6,
    default_branch: str = "",
    connection_id: int | None = None,
) -> Repo:
    """Connect a repo; scan-on-connect enqueues the first run (FR-2 D3)."""
    kind = RepoKind(kind)
    if kind == RepoKind.GIT:
        if not url or not _valid_git_url(url):
            raise ValueError("Git repos need a valid git URL.")
        if local_path:
            raise ValueError("Git repos take url, not local_path.")
    elif not local_path or not os.path.isabs(local_path):
        raise ValueError("Local repos need an absolute local_path.")
    elif url:
        raise ValueError("Local repos take local_path, not url.")
    if schedule_hours < 1:
        raise ValueError("schedule_hours must be >= 1.")
    if connection_id is not None:
        if kind != RepoKind.GIT:
            raise ValueError("Only git repos link to a provider connection.")
        from security_agent.control.git_providers import get_connection

        if get_connection(connection_id) is None:
            raise ValueError("Unknown provider connection.")
    with session_scope() as db:
        repo = Repo(
            name=name,
            kind=kind,
            url=url or None,
            local_path=local_path or None,
            default_branch=default_branch or None,
            connection_id=connection_id,
            schedule_hours=schedule_hours,
            last_scan_at=datetime.now(UTC),
        )
        db.add(repo)
        db.flush()
        db.add(ScanRun(repo_id=repo.id, trigger=RunTrigger.CONNECT))
        if token:
            db.add(
                EncryptedToken(
                    owner=_TOKEN_OWNER.format(repo.id),
                    ciphertext=encrypt_field(token, get_encryption_key()),
                )
            )
        db.flush()
        db.expunge(repo)
        return repo


def disconnect_repo(repo_id: int) -> None:
    """Remove a repo and everything it owns; the provider repo is untouched.

    Dependents go first (Postgres enforces the FKs): boosts/verdicts hang
    off findings and runs, the cost ledger hangs off runs, proposals and
    secrets reference each other, and the encrypted credential rows are
    keyed by owner label, not FK.
    """
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        if repo is None:
            raise ValueError(f"Unknown repo {repo_id}.")
        finding_ids = select(Finding.id).where(Finding.repo_id == repo_id)
        run_ids = select(ScanRun.id).where(ScanRun.repo_id == repo_id)
        db.execute(delete(NewsBoost).where(NewsBoost.finding_id.in_(finding_ids)))
        db.execute(delete(NewsFindingLink).where(NewsFindingLink.finding_id.in_(finding_ids)))
        db.execute(delete(NewsRepoRelevance).where(NewsRepoRelevance.repo_id == repo_id))
        db.execute(
            delete(Verdict).where(
                or_(
                    Verdict.finding_id.in_(finding_ids),
                    Verdict.run_id.in_(run_ids),
                )
            )
        )
        db.execute(delete(Approval).where(Approval.repo_id == repo_id))
        db.execute(
            update(SecretFinding).where(SecretFinding.repo_id == repo_id).values(proposal_id=None)
        )
        db.execute(delete(Proposal).where(Proposal.repo_id == repo_id))
        db.execute(delete(SecretFinding).where(SecretFinding.repo_id == repo_id))
        db.execute(delete(SecretBaseline).where(SecretBaseline.repo_id == repo_id))
        db.execute(delete(Finding).where(Finding.repo_id == repo_id))
        # Cost ledger rows point at the runs; Postgres blocks the run
        # delete until they are gone (NFR-8: spend history dies with the repo).
        db.execute(delete(ModelUsage).where(ModelUsage.run_id.in_(run_ids)))
        db.execute(delete(ScanRun).where(ScanRun.repo_id == repo_id))
        db.execute(
            delete(EncryptedToken).where(
                EncryptedToken.owner.in_(
                    [
                        _TOKEN_OWNER.format(repo_id),
                        _WEBHOOK_OWNER.format(repo_id),
                        _MERGE_OWNER.format(repo_id),
                    ]
                )
            )
        )
        db.delete(repo)
        db.flush()
    audit.append(action_class="repo", decision="disconnect", line=f"repo={repo_id} removed")


def list_repos() -> list[Repo]:
    with session_scope() as db:
        rows = list(db.scalars(select(Repo).order_by(Repo.id)))
        for r in rows:
            db.expunge(r)
        return rows


def store_repo_token(repo_id: int, token: str) -> None:
    _store_secret(_TOKEN_OWNER.format(repo_id), token)


def get_repo_token(repo_id: int) -> str | None:
    """Decrypt the provider token; audited per read (NFR-4).

    A per-repo PAT wins; otherwise a linked provider connection supplies
    its stored PAT.
    """
    secret = _load_secret(_TOKEN_OWNER.format(repo_id))
    if secret is not None:
        audit.append(action_class="credential", decision="allow", line=f"repo={repo_id} token-used")
        return secret
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        connection_id = repo.connection_id if repo else None
    if connection_id is None:
        return None
    from security_agent.control.git_providers import get_valid_token

    token = get_valid_token(connection_id)
    if token is not None:
        audit.append(
            action_class="credential",
            decision="allow",
            line=f"repo={repo_id} connection={connection_id} token-used",
        )
    return token


def store_merge_token(repo_id: int, token: str) -> None:
    """Privileged merge credential, separate from the sandbox token (FR-9 D3)."""
    _store_secret(_MERGE_OWNER.format(repo_id), token)


def get_merge_token(repo_id: int) -> str | None:
    """Decrypt the merge credential; audited per read (NFR-4)."""
    secret = _load_secret(_MERGE_OWNER.format(repo_id))
    if secret is not None:
        audit.append(
            action_class="credential", decision="allow", line=f"repo={repo_id} merge-token-used"
        )
    return secret


def issue_webhook_secret(repo_id: int) -> str:
    """Create a webhook secret; shown once, stored encrypted."""
    secret = secrets.token_urlsafe(32)
    _store_secret(_WEBHOOK_OWNER.format(repo_id), secret)
    return secret


def verify_github_signature(repo_id: int, body: bytes, header: str) -> bool:
    secret = _load_secret(_WEBHOOK_OWNER.format(repo_id))
    if not secret or not header.startswith("sha256="):
        return False
    want = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header.removeprefix("sha256="))


def verify_gitlab_token(repo_id: int, candidate: str) -> bool:
    secret = _load_secret(_WEBHOOK_OWNER.format(repo_id))
    return bool(secret and candidate and hmac.compare_digest(secret, candidate))
