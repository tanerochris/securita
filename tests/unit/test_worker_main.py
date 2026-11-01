"""Worker entrypoint: run_once executes claimed runs and isolates crashes."""

from datetime import UTC, datetime
from unittest import mock

from sqlalchemy import select

from security_agent.control import repos
from security_agent.db.models import RepoKind, RunStatus, ScanRun
from security_agent.db.session import session_scope
from security_agent.worker import main as worker_main


def _run(repo_id: int) -> ScanRun:
    with session_scope() as db:
        row = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo_id))
        assert row is not None
        db.expunge(row)
        return row


def _settle_others() -> None:
    """Finish runs left by earlier tests: run_once drains oldest-first with
    a cap, so without this the test's own run may never be claimed."""
    with session_scope() as db:
        for row in db.scalars(select(ScanRun).where(ScanRun.status == RunStatus.RUNNING)):
            row.status = RunStatus.DONE
            row.finished_at = datetime.now(UTC)


def test_run_once_executes_claimed_run():
    _settle_others()
    repo = repos.connect_repo("wkr-r", RepoKind.GIT, url="https://example.com/w.git")
    graph = mock.Mock()
    with (
        mock.patch("security_agent.worker.build_graph", return_value=graph),
        mock.patch("security_agent.worker.news.poll_news", return_value={}),
        mock.patch(
            "security_agent.worker.news_intel.process_news",
            return_value={"classified": 0, "major": 0, "minted": 0, "linked": 0},
        ),
        mock.patch("security_agent.worker.scheduler.dep_tick", return_value=[]),
        mock.patch(
            "security_agent.worker.deps_check.drain_dep_checks",
            return_value={"executed": 0, "failed": 0},
        ),
        mock.patch(
            "security_agent.worker.deps_check.drain_dep_patches",
            return_value={"proposal_ids": [], "errors": []},
        ),
    ):
        summary = worker_main.run_once()
    graph.invoke.assert_any_call({"repo_id": repo.id, "run_id": _run(repo.id).id})
    assert summary["failed"] == 0 and summary["executed"] >= 1
    assert _run(repo.id).status == RunStatus.DONE


def test_run_once_isolates_crash():
    _settle_others()
    repo = repos.connect_repo("wkr-c", RepoKind.GIT, url="https://example.com/c.git")
    graph = mock.Mock()
    graph.invoke.side_effect = RuntimeError("boom")
    with (
        mock.patch("security_agent.worker.build_graph", return_value=graph),
        mock.patch("security_agent.worker.news.poll_news", return_value={}),
        mock.patch(
            "security_agent.worker.news_intel.process_news",
            return_value={"classified": 0, "major": 0, "minted": 0, "linked": 0},
        ),
        mock.patch("security_agent.worker.scheduler.dep_tick", return_value=[]),
        mock.patch(
            "security_agent.worker.deps_check.drain_dep_checks",
            return_value={"executed": 0, "failed": 0},
        ),
        mock.patch(
            "security_agent.worker.deps_check.drain_dep_patches",
            return_value={"proposal_ids": [], "errors": []},
        ),
    ):
        summary = worker_main.run_once()
    assert summary["failed"] >= 1
    row = _run(repo.id)
    assert row.status == RunStatus.FAILED and "boom" in (row.notes or "")


def test_ensure_schema_sqlite_is_idempotent():
    from security_agent.db.models import Repo

    worker_main.ensure_schema()  # test DB is sqlite: create_all, no alembic
    worker_main.ensure_schema()
    with session_scope() as db:
        assert isinstance(list(db.scalars(select(Repo.id))), list)


def test_ensure_schema_postgres_upgrades(monkeypatch):
    from security_agent.config import get_settings

    monkeypatch.setattr(get_settings(), "database_url", "postgresql+psycopg://x/x")
    with (
        mock.patch("alembic.command.upgrade") as upgrade,
        mock.patch("alembic.config.Config", return_value="cfg"),
    ):
        worker_main.ensure_schema()
    upgrade.assert_called_once_with("cfg", "head")


def test_ensure_schema_retries_contention_then_wins(monkeypatch):
    from security_agent.config import get_settings

    monkeypatch.setattr(get_settings(), "database_url", "postgresql+psycopg://x/x")
    with (
        mock.patch(
            "alembic.command.upgrade",
            side_effect=[RuntimeError("locked"), None],
        ) as upgrade,
        mock.patch("alembic.config.Config", return_value="cfg"),
        mock.patch.object(worker_main.time, "sleep") as sleep,
    ):
        worker_main.ensure_schema()
    assert upgrade.call_count == 2 and sleep.call_count == 1


def test_ensure_schema_gives_up_after_attempts(monkeypatch):
    import pytest

    from security_agent.config import get_settings

    monkeypatch.setattr(get_settings(), "database_url", "postgresql+psycopg://x/x")
    with (
        mock.patch("alembic.command.upgrade", side_effect=RuntimeError("locked")),
        mock.patch("alembic.config.Config", return_value="cfg"),
        mock.patch.object(worker_main.time, "sleep"),
    ):
        with pytest.raises(RuntimeError, match="schema upgrade failed"):
            worker_main.ensure_schema()


def test_main_migrates_before_any_query():
    calls: list[str] = []
    with (
        mock.patch.object(worker_main, "ensure_schema", side_effect=lambda: calls.append("schema")),
        mock.patch(
            "security_agent.sandbox.assert_sandbox_image",
            side_effect=lambda: calls.append("sandbox"),
        ),
        mock.patch("security_agent.worker.build_graph", side_effect=lambda: calls.append("graph")),
        mock.patch.object(
            worker_main, "reap_stale_runs", side_effect=lambda **kw: calls.append("reap")
        ),
        mock.patch.object(worker_main, "run_once", side_effect=KeyboardInterrupt),
        mock.patch.object(worker_main.time, "sleep"),
    ):
        try:
            worker_main.main()
        except KeyboardInterrupt:
            pass
    assert calls == ["schema", "sandbox", "graph", "reap"]
