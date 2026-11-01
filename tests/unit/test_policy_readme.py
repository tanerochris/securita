"""README sync: collection bounds, toggle, hash-gated no-op."""

from unittest import mock

import pytest

from security_agent.db.models import Repo, RepoKind
from security_agent.db.session import session_scope
from security_agent.policy.readme import collect_readme_text, sync_repo_readme
from security_agent.policy.service import get_document, set_repo_readme_policy


def _repo(name: str) -> int:
    # Direct insert: connect_repo enqueues a RUNNING scan that would trip
    # the single-flight invariant when a test adds its own run.
    with session_scope() as db:
        repo = Repo(name=name, kind=RepoKind.GIT, url=f"https://example.com/{name}.git")
        db.add(repo)
        db.flush()
        return repo.id


@pytest.fixture(autouse=True)
def _no_embeddings():
    with mock.patch("security_agent.brain.embeddings.embed_texts", return_value=None):
        yield


def test_collect_combines_repo_docs(tmp_path):
    (tmp_path / "README.md").write_text("# Title\n\nHello.\n")
    (tmp_path / "SECURITY.md").write_text("Report issues.\n")
    title, text = collect_readme_text(tmp_path)
    assert "README" in title
    assert "Hello." in text and "Report issues." in text


def test_collect_absent_returns_none(tmp_path):
    assert collect_readme_text(tmp_path) is None


def test_sync_ingests_then_noops_until_changed(tmp_path):
    repo_id = _repo("readme-r")
    (tmp_path / "README.md").write_text("# R\n\nFirst version here.\n")
    assert sync_repo_readme(repo_id, tmp_path) is not None
    assert sync_repo_readme(repo_id, tmp_path) is None  # unchanged: silent
    (tmp_path / "README.md").write_text("# R\n\nSecond version here.\n")
    assert sync_repo_readme(repo_id, tmp_path) is not None
    doc = get_document(f"readme:{repo_id}")
    assert doc is not None and doc.version == 2 and doc.source == "readme"


def test_sync_respects_opt_out(tmp_path):
    repo_id = _repo("readme-off")
    (tmp_path / "README.md").write_text("# R\n\nBody here.\n")
    set_repo_readme_policy(repo_id, enabled=False)
    assert sync_repo_readme(repo_id, tmp_path) is None
    assert get_document(f"readme:{repo_id}") is None
