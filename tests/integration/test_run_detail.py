"""Run detail page: worker log, findings, cost, and 404 guards."""

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import select

from security_agent.app import accounts as accounts_svc
from security_agent.app.main import app
from security_agent.control import repos as repo_svc
from security_agent.db.models import (
    Finding,
    FindingStatus,
    ModelUsage,
    RepoKind,
    Role,
    RunStatus,
    ScanRun,
)
from security_agent.db.session import session_scope

client = TestClient(app, raise_server_exceptions=False)


def _login(role: Role = Role.DEVELOPER) -> None:
    client.cookies.clear()
    email = f"run-{role.value}-{datetime.now(UTC).timestamp()}@example.com"
    user = accounts_svc.create_user(email, None, role)
    client.cookies.set("app_session", accounts_svc.create_session(user.id))


def _seed_failed_run() -> tuple[int, int]:
    repo = repo_svc.connect_repo(
        f"run-r-{datetime.now(UTC).timestamp()}",
        RepoKind.GIT,
        url="https://example.com/r.git",
    )
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        assert run is not None
        run.status = RunStatus.FAILED
        run.notes = "cloning\nfailed: clone timed out after 300s"
        run.claimed_by = "worker-1"
        run.finished_at = datetime.now(UTC)
        db.add(
            Finding(
                repo_id=repo.id,
                package="left-pad",
                installed_version="1.0.0",
                advisory_id="CVE-RUN",
                status=FindingStatus.OPEN,
                first_run_id=run.id,
            )
        )
        db.add(ModelUsage(run_id=run.id, task="adapt", total_tokens=120, cost_usd=0.5))
        return repo.id, run.id


def test_run_detail_shows_worker_log_findings_and_cost():
    _login()
    repo_id, run_id = _seed_failed_run()
    resp = client.get(f"/repos/{repo_id}/runs/{run_id}")
    assert resp.status_code == 200
    assert "failed: clone timed out after 300s" in resp.text
    assert "worker-1" in resp.text
    assert "left-pad" in resp.text
    assert "adapt" in resp.text and "120" in resp.text
    assert "reachable of" in resp.text
    assert 'id="copyLog"' in resp.text and 'id="workerLog"' in resp.text


def test_run_detail_404s():
    _login()
    repo_id, run_id = _seed_failed_run()
    assert client.get(f"/repos/{repo_id}/runs/999999").status_code == 404
    other = repo_svc.connect_repo(
        f"run-other-{datetime.now(UTC).timestamp()}",
        RepoKind.GIT,
        url="https://example.com/o.git",
    )
    # Run exists but belongs to another repo: still 404.
    assert client.get(f"/repos/{other.id}/runs/{run_id}").status_code == 404
    assert client.get("/repos/999999/runs/1").status_code == 404


def test_repo_runs_link_to_detail():
    _login()
    repo_id, run_id = _seed_failed_run()
    resp = client.get(f"/repos/{repo_id}")
    assert resp.status_code == 200
    assert f"/repos/{repo_id}/runs/{run_id}" in resp.text
