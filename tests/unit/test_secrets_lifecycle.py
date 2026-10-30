"""H5 Slice A: secret lifecycle transitions, rotation confirmation, ordering."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from security_agent.app import accounts as accounts_svc
from security_agent.control import lifecycle
from security_agent.control import repos as repo_svc
from security_agent.db.models import RepoKind, Role, SecretFinding, SecretStatus, User
from security_agent.db.session import session_scope


def _email(tag: str) -> str:
    return f"{tag}-{datetime.now(UTC).timestamp()}@example.com"


def _user(tag: str, role: Role) -> User:
    return accounts_svc.create_user(_email(tag), None, role)


_SEQ = 0


def _secret(repo_id: int, **fields) -> int:
    global _SEQ
    _SEQ += 1
    with session_scope() as db:
        row = SecretFinding(
            repo_id=repo_id,
            rule_id=fields.pop("rule_id", "github-pat"),
            path=fields.pop("path", ".env"),
            fingerprint=fields.pop("fingerprint", f"fp-{_SEQ}"),
            **fields,
        )
        db.add(row)
        db.flush()
        return row.id


def test_secret_lifecycle_happy_path():
    repo = repo_svc.connect_repo("sec-a", RepoKind.GIT, url="https://example.com/sec-a.git")
    sid = _secret(repo.id)
    assert lifecycle.transition_secret_finding(sid, SecretStatus.PROPOSED).status == (
        SecretStatus.PROPOSED
    )
    assert (
        lifecycle.transition_secret_finding(sid, SecretStatus.AWAITING_ROTATION).status
        == SecretStatus.AWAITING_ROTATION
    )
    owner = _user("sec-owner", Role.OWNER)
    closed = lifecycle.mark_secret_rotated(sid, owner)
    assert closed.status == SecretStatus.CLOSED
    assert closed.rotated_by == owner.id
    assert closed.rotated_at is not None


def test_secret_illegal_transitions_rejected():
    repo = repo_svc.connect_repo("sec-b", RepoKind.GIT, url="https://example.com/sec-b.git")
    sid = _secret(repo.id)
    with pytest.raises(ValueError, match="Illegal transition"):
        lifecycle.transition_secret_finding(sid, SecretStatus.CLOSED)
    with pytest.raises(ValueError, match="Unknown secret"):
        lifecycle.transition_secret_finding(999999999, SecretStatus.OPEN)


def test_mark_rotated_needs_head_clean_and_approver():
    repo = repo_svc.connect_repo("sec-c", RepoKind.GIT, url="https://example.com/sec-c.git")
    owner = _user("sec-owner2", Role.OWNER)
    dev = _user("sec-dev", Role.DEVELOPER)
    sid = _secret(repo.id)  # OPEN: HEAD not clean, rotation unproven
    with pytest.raises(ValueError, match="HEAD-clean"):
        lifecycle.mark_secret_rotated(sid, owner)
    lifecycle.transition_secret_finding(sid, SecretStatus.AWAITING_ROTATION)
    with pytest.raises(PermissionError):
        lifecycle.mark_secret_rotated(sid, dev)
    assert lifecycle.mark_secret_rotated(sid, owner).status == SecretStatus.CLOSED


def test_secret_reopen_and_dead_paths():
    repo = repo_svc.connect_repo("sec-d", RepoKind.GIT, url="https://example.com/sec-d.git")
    back = _secret(repo.id)
    lifecycle.transition_secret_finding(back, SecretStatus.AWAITING_ROTATION)
    assert lifecycle.transition_secret_finding(back, SecretStatus.OPEN).status == (
        SecretStatus.OPEN
    )
    dead = _secret(repo.id)
    assert (
        lifecycle.transition_secret_finding(dead, SecretStatus.INFORMATIONAL).status
        == SecretStatus.INFORMATIONAL
    )
    # Terminal states reopen on HEAD reappearance: a new incident (H5 G1).
    assert lifecycle.transition_secret_finding(dead, SecretStatus.OPEN).status == (
        SecretStatus.OPEN
    )


def test_list_open_secrets_needs_action_first():
    repo = repo_svc.connect_repo("sec-e", RepoKind.GIT, url="https://example.com/sec-e.git")
    info = _secret(repo.id)
    lifecycle.transition_secret_finding(info, SecretStatus.INFORMATIONAL)
    awaiting = _secret(repo.id)
    lifecycle.transition_secret_finding(awaiting, SecretStatus.AWAITING_ROTATION)
    opened = _secret(repo.id)
    proposed = _secret(repo.id)
    lifecycle.transition_secret_finding(proposed, SecretStatus.PROPOSED)
    rows = lifecycle.list_open_secrets(repo.id)
    assert [r.id for r in rows] == [opened, proposed, awaiting]
    assert {r.id for r in lifecycle.list_repo_secrets(repo.id)} == {
        opened,
        proposed,
        awaiting,
        info,
    }
    with session_scope() as db:
        assert db.scalar(select(SecretFinding).where(SecretFinding.id == opened)) is not None
