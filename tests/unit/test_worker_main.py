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
            "security_agent.worker.news.run_matcher", return_value={"items": 0, "boosts": 0}
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
            "security_agent.worker.news.run_matcher", return_value={"items": 0, "boosts": 0}
        ),
    ):
        summary = worker_main.run_once()
    assert summary["failed"] >= 1
    row = _run(repo.id)
    assert row.status == RunStatus.FAILED and "boom" in (row.notes or "")
