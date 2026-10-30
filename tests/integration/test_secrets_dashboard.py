"""H5 Slice E: secrets dashboard views + rotation confirmation endpoint."""

import re
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from security_agent.app import accounts as accounts_svc
from security_agent.app.main import app
from security_agent.control import repos as repo_svc
from security_agent.db.models import RepoKind, Role, SecretFinding, SecretStatus
from security_agent.db.session import session_scope

client = TestClient(app, raise_server_exceptions=False)


def _login_as(role: Role) -> None:
    client.cookies.clear()
    email = f"secdash-{role.value}-{datetime.now(UTC).timestamp()}@example.com"
    user = accounts_svc.create_user(email, None, role)
    sid = accounts_svc.create_session(user.id)
    client.cookies.set("app_session", sid)


def _csrf(path: str) -> str:
    resp = client.get(path)
    match = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert match, f"no csrf token on {path}"
    return match.group(1)


def _seed_secret(status: SecretStatus) -> tuple[int, int]:
    repo = repo_svc.connect_repo(
        f"secdash-{datetime.now(UTC).timestamp()}", RepoKind.GIT, url="https://example.com/s.git"
    )
    with session_scope() as db:
        row = SecretFinding(
            repo_id=repo.id,
            rule_id="github-pat",
            path=".env",
            start_line=3,
            fingerprint="ab" * 32 + str(repo.id),
            liveness="live",
            status=status,
            guidance="Revoke the token at GitHub, then mint a replacement.",
        )
        db.add(row)
        db.flush()
        return repo.id, row.id


def test_findings_view_lists_secrets_with_guidance():
    repo_id, _ = _seed_secret(SecretStatus.OPEN)
    _login_as(Role.REPORTER)
    resp = client.get(f"/repos/{repo_id}/findings")
    assert resp.status_code == 200
    assert "github-pat" in resp.text
    assert ".env" in resp.text
    assert "Revoke the token" in resp.text
    assert "Confirm rotated" not in resp.text  # reporter cannot rotate


def test_awaiting_secret_offers_rotation_to_approvers():
    repo_id, sid = _seed_secret(SecretStatus.AWAITING_ROTATION)
    _login_as(Role.MAINTAINER)
    resp = client.get(f"/repos/{repo_id}/findings")
    assert resp.status_code == 200
    assert "Confirm rotated" in resp.text
    csrf = _csrf(f"/repos/{repo_id}/findings")
    posted = client.post(
        f"/repos/{repo_id}/secrets/{sid}/rotated",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert posted.status_code == 303
    with session_scope() as db:
        row = db.get(SecretFinding, sid)
        assert row is not None and row.status == SecretStatus.CLOSED
        assert row.rotated_by is not None


def test_rotation_refuses_open_findings_and_reporters():
    repo_id, sid = _seed_secret(SecretStatus.OPEN)
    _login_as(Role.OWNER)
    csrf = _csrf(f"/repos/{repo_id}")  # tokens are page-independent
    bad = client.post(f"/repos/{repo_id}/secrets/{sid}/rotated", data={"csrf": csrf})
    assert bad.status_code == 400  # HEAD not clean: rotation unproven
    _login_as(Role.REPORTER)
    denied = client.post(f"/repos/{repo_id}/secrets/{sid}/rotated", data={"csrf": csrf})
    assert denied.status_code in (401, 403)
    with session_scope() as db:
        row = db.get(SecretFinding, sid)
        assert row is not None and row.status == SecretStatus.OPEN


def test_rotation_rejects_other_repo_secret():
    """A secret cannot be confirmed through another repo's URL (H5 G5)."""
    repo_id, sid = _seed_secret(SecretStatus.AWAITING_ROTATION)
    other = repo_svc.connect_repo(
        f"secdash-other-{datetime.now(UTC).timestamp()}",
        RepoKind.GIT,
        url="https://example.com/other.git",
    )
    _login_as(Role.OWNER)
    csrf = _csrf(f"/repos/{other.id}")
    resp = client.post(
        f"/repos/{other.id}/secrets/{sid}/rotated",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 404
    with session_scope() as db:
        row = db.get(SecretFinding, sid)
        assert row is not None and row.status == SecretStatus.AWAITING_ROTATION
        assert row.repo_id == repo_id


def test_repo_detail_shows_open_secrets():
    repo_id, _ = _seed_secret(SecretStatus.PROPOSED)
    _login_as(Role.OWNER)
    resp = client.get(f"/repos/{repo_id}")
    assert resp.status_code == 200
    assert "Open secrets (1)" in resp.text
    assert "github-pat" in resp.text
