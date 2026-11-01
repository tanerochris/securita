"""Policy documents: versioning, validation, secret screen, README upsert."""

import pytest

from security_agent.db.models import Repo, RepoKind
from security_agent.db.session import session_scope
from security_agent.policy.service import (
    PolicyError,
    create_document,
    document_chunks,
    document_history,
    get_document,
    list_documents,
    set_document_status,
    update_document,
    upsert_readme_doc,
)

LONG_TEXT = "# Policy\n\nNever auto-patch openssl without a note.\n"


def _repo() -> int:
    # Direct insert: connect_repo enqueues a RUNNING scan that would trip
    # the single-flight invariant when a test adds its own run.
    with session_scope() as db:
        repo = Repo(
            name="policydoc-r", kind=RepoKind.GIT, url="https://example.com/policydoc-r.git"
        )
        db.add(repo)
        db.flush()
        return repo.id


def test_create_and_list_platform_doc():
    doc = create_document(scope="platform", title="Corp policy", text=LONG_TEXT, embed=False)
    assert doc.version == 1 and doc.is_current and doc.status == "ready"
    assert doc.doc_key in {d.doc_key for d in list_documents(scope="platform")}
    assert len(document_chunks(doc.id)) >= 1


def test_update_appends_new_version_and_keeps_history():
    doc = create_document(scope="platform", title="Evolving", text=LONG_TEXT, embed=False)
    updated = update_document(doc.doc_key, text=LONG_TEXT + "\nMore words here.\n")
    assert updated.version == 2 and updated.is_current
    history = document_history(doc.doc_key)
    assert [d.version for d in history] == [2, 1]
    assert get_document(doc.doc_key, version=1) is not None


def test_metadata_only_edit_reuses_chunks():
    doc = create_document(scope="platform", title="Meta", text=LONG_TEXT, embed=False)
    before = [c.text for c in document_chunks(doc.id)]
    updated = update_document(doc.doc_key, title="Meta renamed")
    after = [c.text for c in document_chunks(updated.id)]
    assert before == after and updated.title == "Meta renamed"


def test_disable_and_enable():
    doc = create_document(scope="platform", title="Toggle", text=LONG_TEXT, embed=False)
    set_document_status(doc.doc_key, disabled=True)
    assert get_document(doc.doc_key).status == "disabled"
    set_document_status(doc.doc_key, disabled=False)
    assert get_document(doc.doc_key).status == "ready"


def test_scope_and_task_validation():
    repo_id = _repo()
    with pytest.raises(PolicyError, match="no repo"):
        create_document(scope="platform", title="x", text=LONG_TEXT, repo_id=repo_id, embed=False)
    with pytest.raises(PolicyError, match="need a repo"):
        create_document(scope="repo", title="x", text=LONG_TEXT, embed=False)
    with pytest.raises(PolicyError, match="Unknown policy tasks"):
        create_document(
            scope="platform",
            title="x",
            text=LONG_TEXT,
            tasks=["teleport"],
            embed=False,
        )
    with pytest.raises(PolicyError, match="Unknown repo"):
        create_document(scope="repo", title="x", text=LONG_TEXT, repo_id=999999999, embed=False)


def test_secret_material_rejected():
    with pytest.raises(PolicyError, match="secret material"):
        create_document(
            scope="platform",
            title="Leaky",
            text="Deploy with key AKIAIOSFODNN7EXAMPLE inside.",
            embed=False,
        )


def test_readme_upsert_hash_gated():
    repo_id = _repo()
    doc, changed = upsert_readme_doc(repo_id, title="docs", text="# R\n\nBody here.\n")
    assert changed and doc.source == "readme" and doc.doc_key == f"readme:{repo_id}"
    same, changed_again = upsert_readme_doc(repo_id, title="docs", text="# R\n\nBody here.\n")
    assert not changed_again and same.id == doc.id
    newer, changed_third = upsert_readme_doc(
        repo_id, title="docs", text="# R\n\nBody changed here.\n"
    )
    assert changed_third and newer.version == 2
