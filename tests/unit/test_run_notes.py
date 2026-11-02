"""Progress-note helpers: atomic appends + mid-pipeline reopen."""

from datetime import UTC, datetime

from sqlalchemy import select

from security_agent.control import deps as deps_svc
from security_agent.control import repos as repo_svc
from security_agent.control.lifecycle import append_run_note, reopen_run
from security_agent.db.models import DependencyCheck, RepoKind, RunStatus, ScanRun
from security_agent.db.session import session_scope


def _seed_run() -> int:
    repo = repo_svc.connect_repo(
        f"notes-r-{datetime.now(UTC).timestamp()}",
        RepoKind.GIT,
        url="https://example.com/r.git",
    )
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        assert run is not None
        return run.id


def _seed_check() -> int:
    repo = repo_svc.connect_repo(
        f"notes-c-{datetime.now(UTC).timestamp()}",
        RepoKind.GIT,
        url="https://example.com/c.git",
    )
    with session_scope() as db:
        check = db.scalar(select(DependencyCheck).where(DependencyCheck.repo_id == repo.id))
        assert check is not None
        return check.id


def _run_notes(run_id: int) -> str | None:
    with session_scope() as db:
        row = db.get(ScanRun, run_id)
        assert row is not None
        return row.notes


def test_append_run_note_joins_lines():
    run_id = _seed_run()
    append_run_note(run_id, "line one")
    append_run_note(run_id, "line two")
    append_run_note(run_id, "")  # empty lines never touch the log
    assert _run_notes(run_id) == "line one\nline two"


def test_append_run_note_missing_row_is_noop():
    append_run_note(999999999, "x")  # must not raise


def test_append_check_note_joins_lines():
    check_id = _seed_check()
    deps_svc.append_check_note(check_id, "first")
    deps_svc.append_check_note(check_id, "second")
    with session_scope() as db:
        row = db.get(DependencyCheck, check_id)
        assert row is not None
        assert row.notes == "first\nsecond"


def test_reopen_run_flips_done_back_to_running():
    run_id = _seed_run()
    with session_scope() as db:
        row = db.get(ScanRun, run_id)
        assert row is not None
        row.status = RunStatus.DONE
        row.finished_at = datetime.now(UTC)
    assert reopen_run(run_id) is True
    with session_scope() as db:
        row = db.get(ScanRun, run_id)
        assert row is not None
        assert row.status == RunStatus.RUNNING
        assert row.finished_at is None
    assert reopen_run(run_id) is False  # already running: no-op


def test_reopen_run_leaves_failed_and_missing_alone():
    run_id = _seed_run()
    with session_scope() as db:
        row = db.get(ScanRun, run_id)
        assert row is not None
        row.status = RunStatus.FAILED
    assert reopen_run(run_id) is False
    with session_scope() as db:
        assert db.get(ScanRun, run_id).status == RunStatus.FAILED
    assert reopen_run(999999999) is False
