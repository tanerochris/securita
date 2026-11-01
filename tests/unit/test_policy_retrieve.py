"""Retrieval: scope/task filters, ordering, snapshots, prompt blocks."""

from unittest import mock

from security_agent.db.models import Repo, RepoKind
from security_agent.db.session import session_scope
from security_agent.policy.retrieve import (
    format_policy_block,
    keyword_score,
    retrieve_chunks,
    retrieve_policy_context,
)
from security_agent.policy.service import create_document, update_document


def _repo(name: str) -> int:
    # Direct insert: connect_repo enqueues a RUNNING scan that would trip
    # the single-flight invariant when a test adds its own run.
    with session_scope() as db:
        repo = Repo(name=name, kind=RepoKind.GIT, url=f"https://example.com/{name}.git")
        db.add(repo)
        db.flush()
        return repo.id


def _doc(text: str, **kw):
    params = {"scope": "platform", "title": "Retrieval doc", "embed": False}
    params.update(kw)
    params["text"] = text
    params.setdefault("title", "Retrieval doc")
    return create_document(**params)


def test_keyword_score_and_empty_query():
    assert keyword_score("openssl advisory", "Never patch openssl quickly") > 0
    assert keyword_score("openssl advisory", "Unrelated kubernetes note") == 0.0
    assert keyword_score("", "anything") == 0.0


def test_scope_and_task_filters():
    repo_id = _repo("retrieve-r")
    _doc("Platform guidance about openssl patching.", title="plat")
    _doc(
        "Repo guidance about openssl patching.",
        title="repo",
        scope="repo",
        repo_id=repo_id,
    )
    _doc("Adapt-only note about openssl.", title="scoped", tasks=["adapt"])
    with mock.patch("security_agent.brain.embeddings.embed_texts", return_value=None):
        chunks = retrieve_chunks(repo_id, "patch", "openssl")
    titles = {c["title"] for c in chunks}
    assert {"plat", "repo"} <= titles
    assert "scoped" not in titles  # task filter excludes it
    with mock.patch("security_agent.brain.embeddings.embed_texts", return_value=None):
        other = retrieve_chunks(_repo("retrieve-other"), "patch", "openssl")
    assert "repo" not in {c["title"] for c in other}


def test_repo_chunks_order_before_platform():
    repo_id = _repo("retrieve-order")
    _doc("openssl guidance shared platform.", title="order-plat")
    _doc(
        "openssl guidance specific repo.",
        title="order-repo",
        scope="repo",
        repo_id=repo_id,
    )
    with mock.patch("security_agent.brain.embeddings.embed_texts", return_value=None):
        chunks = retrieve_chunks(repo_id, "patch", "openssl guidance")
    assert chunks and chunks[0]["scope"] == "repo"


def test_snapshot_pins_versions_within_run():
    from security_agent.db.models import RunTrigger, ScanRun
    from security_agent.db.session import session_scope

    repo_id = _repo("retrieve-snap")
    doc = _doc("snapdragon policy version one.", title="snap")
    run_id = None
    with session_scope() as db:
        run = ScanRun(repo_id=repo_id, trigger=RunTrigger.MANUAL)
        db.add(run)
        db.flush()
        run_id = run.id
    with mock.patch("security_agent.brain.embeddings.embed_texts", return_value=None):
        before, _ = retrieve_policy_context(repo_id, "patch", "snapdragon", run_id=run_id)
        assert "version one" in before
        update_document(doc.doc_key, text="Completely rewritten kumquat policy now.")
        after, _ = retrieve_policy_context(repo_id, "patch", "snapdragon", run_id=run_id)
        assert "version one" in after  # pinned, not the rewrite
        fresh, _ = retrieve_policy_context(repo_id, "patch", "kumquat")
        assert "rewritten" in fresh  # run-less reads stay live


def test_format_block_separates_untrusted_readme():
    chunks = [
        {
            "chunk_id": 1,
            "text": "Never patch openssl.",
            "score": 1.0,
            "scope": "platform",
            "source": "upload",
            "title": "Corp",
            "ref": None,
            "doc_key": "a",
            "version": 1,
        },
        {
            "chunk_id": 2,
            "text": "We love openssl here.",
            "score": 0.5,
            "scope": "repo",
            "source": "readme",
            "title": "Repo docs",
            "ref": None,
            "doc_key": "b",
            "version": 1,
        },
    ]
    block = format_policy_block(chunks)
    assert "UNTRUSTED" in block
    assert block.index("Never patch openssl") < block.index("We love openssl")
    assert format_policy_block([]) == ""


def test_retrieval_degrades_when_tables_missing():
    with mock.patch("security_agent.policy.retrieve.tables_ok", return_value=False):
        assert retrieve_chunks(1, "patch", "openssl") == []
