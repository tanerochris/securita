"""Live log streams: SSE endpoints for runs and dependency checks."""

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import select

from security_agent.app import accounts as accounts_svc
from security_agent.app.main import app
from security_agent.control import repos as repo_svc
from security_agent.db.models import (
    DependencyCheck,
    RepoKind,
    Role,
    RunStatus,
    ScanRun,
)
from security_agent.db.session import session_scope

client = TestClient(app, raise_server_exceptions=False)


def _login(role: Role = Role.DEVELOPER) -> None:
    client.cookies.clear()
    email = f"live-{role.value}-{datetime.now(UTC).timestamp()}@example.com"
    user = accounts_svc.create_user(email, None, role)
    client.cookies.set("app_session", accounts_svc.create_session(user.id))


def _seed_run(status: RunStatus, notes: str) -> tuple[int, int]:
    repo = repo_svc.connect_repo(
        f"live-r-{datetime.now(UTC).timestamp()}",
        RepoKind.GIT,
        url="https://example.com/r.git",
    )
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        assert run is not None
        run.status = status
        run.notes = notes
        if status != RunStatus.RUNNING:
            run.finished_at = datetime.now(UTC)
        return repo.id, run.id


def _seed_check(status: RunStatus, notes: str) -> tuple[int, int]:
    repo = repo_svc.connect_repo(
        f"live-c-{datetime.now(UTC).timestamp()}",
        RepoKind.GIT,
        url="https://example.com/c.git",
    )
    with session_scope() as db:
        check = db.scalar(select(DependencyCheck).where(DependencyCheck.repo_id == repo.id))
        assert check is not None
        check.status = status
        check.notes = notes
        if status != RunStatus.RUNNING:
            check.finished_at = datetime.now(UTC)
        return repo.id, check.id


def test_run_events_terminal_snapshot_and_close(monkeypatch):
    monkeypatch.setattr("security_agent.app.live.POLL_SECONDS", 0)
    _login()
    repo_id, run_id = _seed_run(RunStatus.DONE, "cloning\npipeline complete")
    resp = client.get(f"/repos/{repo_id}/runs/{run_id}/events")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert "event: init" in resp.text
    assert "pipeline complete" in resp.text
    assert '"status": "done"' in resp.text
    assert "event: log" not in resp.text
    assert "event: complete" in resp.text


def test_run_events_streams_live_tail():
    _login()
    repo_id, run_id = _seed_run(RunStatus.RUNNING, "cloning\n")
    with client.stream("GET", f"/repos/{repo_id}/runs/{run_id}/events") as resp:
        assert resp.status_code == 200
        buf = ""
        for chunk in resp.iter_text():
            buf += chunk
            if "event: init" in buf:
                break
        assert '"status": "running"' in buf
        assert "cloning\\n" in buf


def test_run_events_guards():
    _login()
    repo_id, run_id = _seed_run(RunStatus.DONE, "done")
    assert client.get(f"/repos/{repo_id}/runs/999999/events").status_code == 404
    other = repo_svc.connect_repo(
        f"live-other-{datetime.now(UTC).timestamp()}",
        RepoKind.GIT,
        url="https://example.com/o.git",
    )
    assert client.get(f"/repos/{other.id}/runs/{run_id}/events").status_code == 404
    assert client.get("/repos/999999/runs/1/events").status_code == 404
    client.cookies.clear()
    assert client.get(f"/repos/{repo_id}/runs/{run_id}/events").status_code == 401


def test_check_events_terminal_snapshot_and_close(monkeypatch):
    monkeypatch.setattr("security_agent.app.live.POLL_SECONDS", 0)
    _login()
    repo_id, check_id = _seed_check(RunStatus.FAILED, "npm timed out\nall manifests failed")
    resp = client.get(f"/repos/{repo_id}/dependencies/checks/{check_id}/events")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert "event: init" in resp.text
    assert "all manifests failed" in resp.text
    assert '"status": "failed"' in resp.text
    assert "event: complete" in resp.text


def test_check_events_streams_live_tail():
    _login()
    repo_id, check_id = _seed_check(RunStatus.RUNNING, "package.json: ok\n")
    with client.stream("GET", f"/repos/{repo_id}/dependencies/checks/{check_id}/events") as resp:
        assert resp.status_code == 200
        buf = ""
        for chunk in resp.iter_text():
            buf += chunk
            if "event: init" in buf:
                break
        assert '"status": "running"' in buf
        assert "package.json: ok\\n" in buf


def test_detail_pages_embed_live_stream_wiring():
    _login()
    repo_id, run_id = _seed_run(RunStatus.RUNNING, "cloning\n")
    resp = client.get(f"/repos/{repo_id}/runs/{run_id}")
    assert resp.status_code == 200
    assert 'id="liveLog"' in resp.text
    assert f'data-events-url="/repos/{repo_id}/runs/{run_id}/events"' in resp.text
    assert 'data-status="running"' in resp.text
    assert "new EventSource" in resp.text

    repo_id, check_id = _seed_check(RunStatus.RUNNING, "")
    resp = client.get(f"/repos/{repo_id}/dependencies/checks/{check_id}")
    assert resp.status_code == 200
    assert f'data-events-url="/repos/{repo_id}/dependencies/checks/{check_id}/events"' in resp.text
    assert 'id="logEmpty"' in resp.text


def test_finished_pages_do_not_open_stream():
    _login()
    repo_id, run_id = _seed_run(RunStatus.DONE, "done")
    resp = client.get(f"/repos/{repo_id}/runs/{run_id}")
    assert resp.status_code == 200
    assert 'data-status="done"' in resp.text
    assert ">Live</span>" not in resp.text


def test_check_events_guards():
    _login()
    repo_id, check_id = _seed_check(RunStatus.DONE, "done")
    base = f"/repos/{repo_id}/dependencies/checks"
    assert client.get(f"{base}/999999/events").status_code == 404
    other = repo_svc.connect_repo(
        f"live-other-{datetime.now(UTC).timestamp()}",
        RepoKind.GIT,
        url="https://example.com/o.git",
    )
    assert client.get(f"/repos/{other.id}/dependencies/checks/{check_id}/events").status_code == 404
    assert client.get("/repos/999999/dependencies/checks/1/events").status_code == 404
    client.cookies.clear()
    assert client.get(f"{base}/{check_id}/events").status_code == 401
