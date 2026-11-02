"""Dependency check detail page: worker log, manifests, and 404 guards."""

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import select

from security_agent.app import accounts as accounts_svc
from security_agent.app.main import app
from security_agent.control import repos as repo_svc
from security_agent.db.models import DependencyCheck, RepoKind, Role, RunStatus
from security_agent.db.session import session_scope

client = TestClient(app, raise_server_exceptions=False)


def _login(role: Role = Role.DEVELOPER) -> None:
    client.cookies.clear()
    email = f"depcheck-{role.value}-{datetime.now(UTC).timestamp()}@example.com"
    user = accounts_svc.create_user(email, None, role)
    client.cookies.set("app_session", accounts_svc.create_session(user.id))


def _seed_failed_check() -> tuple[int, int]:
    repo = repo_svc.connect_repo(
        f"depcheck-r-{datetime.now(UTC).timestamp()}",
        RepoKind.GIT,
        url="https://example.com/r.git",
    )
    with session_scope() as db:
        check = db.scalar(select(DependencyCheck).where(DependencyCheck.repo_id == repo.id))
        assert check is not None
        check.status = RunStatus.FAILED
        check.notes = "package.json: check failed (npm timed out)\nall manifests failed"
        check.manifests = [
            {
                "manifest": "package.json",
                "status": "check_failed",
                "error": "npm timed out",
            }
        ]
        check.claimed_by = "worker-1"
        check.finished_at = datetime.now(UTC)
        return repo.id, check.id


def test_check_detail_shows_worker_log_and_manifests():
    _login()
    repo_id, check_id = _seed_failed_check()
    resp = client.get(f"/repos/{repo_id}/dependencies/checks/{check_id}")
    assert resp.status_code == 200
    assert "all manifests failed" in resp.text
    assert "worker-1" in resp.text
    assert "package.json" in resp.text
    assert "npm timed out" in resp.text
    assert 'id="copyLog"' in resp.text and 'id="workerLog"' in resp.text


def test_check_detail_404s():
    _login()
    repo_id, check_id = _seed_failed_check()
    assert client.get(f"/repos/{repo_id}/dependencies/checks/999999").status_code == 404
    other = repo_svc.connect_repo(
        f"depcheck-other-{datetime.now(UTC).timestamp()}",
        RepoKind.GIT,
        url="https://example.com/o.git",
    )
    # Check exists but belongs to another repo: still 404.
    assert client.get(f"/repos/{other.id}/dependencies/checks/{check_id}").status_code == 404
    assert client.get("/repos/999999/dependencies/checks/1").status_code == 404


def test_dependencies_checks_link_to_detail():
    _login()
    repo_id, check_id = _seed_failed_check()
    resp = client.get(f"/repos/{repo_id}/dependencies")
    assert resp.status_code == 200
    assert f"/repos/{repo_id}/dependencies/checks/{check_id}" in resp.text
