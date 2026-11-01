"""search_policies tool: bounded adapt loop, scoping, backfill, padding."""

import subprocess
from types import SimpleNamespace
from unittest import mock

import pytest

from security_agent.brain.adapt import _run_policy_search, _search_scope, make_model_adapt
from security_agent.db.models import POLICY_EMBEDDING_DIM
from security_agent.policy.service import create_document


@pytest.fixture(autouse=True)
def _no_embeddings():
    with mock.patch("security_agent.brain.embeddings.embed_texts", return_value=None):
        yield


def _git_workdir(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)  # noqa: S603, S607
    (tmp_path / "index.js").write_text("require('searchpkg');\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)  # noqa: S603, S607
    return tmp_path


def _finding():
    return SimpleNamespace(
        package="searchpkg",
        installed_version="1.0.0",
        advisory_id="CVE-SEARCH-1",
        repo_id=None,
    )


class _ScriptedModel:
    """Returns queued tool_calls per invoke; records every prompt."""

    def __init__(self, script):
        self._script = list(script)
        self.prompts: list[str] = []

    def bind_tools(self, tools):
        self.tools = tools
        return self

    def invoke(self, prompt):
        self.prompts.append(prompt)
        calls = self._script.pop(0) if self._script else []
        return SimpleNamespace(tool_calls=calls, usage_metadata={}, content="")


def _search_call(query: str) -> dict:
    return {"name": "search_policies", "args": {"query": query}}


def _edit_call(path: str, content: str) -> dict:
    return {
        "name": "apply_file_edit",
        "args": {"file_path": path, "new_content": content},
    }


def test_adapt_searches_then_edits(tmp_path):
    create_document(
        scope="platform",
        title="Search policy",
        text="Never upgrade searchpkg without checking the changelog first.",
        embed=False,
    )
    model = _ScriptedModel(
        [
            [_search_call("searchpkg upgrade")],
            [_edit_call("index.js", "require('searchpkg'); // v2\n")],
        ]
    )
    adapt = make_model_adapt(model=model, probe_ok=True)
    out = adapt(_git_workdir(tmp_path), _finding(), "2.0.0", [])
    assert len(model.prompts) == 2
    assert "checking the changelog" in model.prompts[1]
    assert "index.js" in out.changed_files


def test_adapt_search_budget_terminates(tmp_path):
    model = _ScriptedModel(
        [
            [_search_call("q1")],
            [_search_call("q2")],
            [_search_call("q3")],
            [_edit_call("index.js", "x\n")],
        ]
    )
    adapt = make_model_adapt(model=model, probe_ok=True)
    adapt(_git_workdir(tmp_path), _finding(), "2.0.0", [])
    # Two searches honoured; third request ignored, edits applied.
    assert len(model.prompts) == 3


def test_search_tool_scoping():
    create_document(
        scope="platform",
        title="Scoped policy",
        text="Quixotic libraries require a design review before upgrade.",
        embed=False,
    )
    assert "unavailable" in _run_policy_search("quixotic")
    token = _search_scope.set({"repo_id": None, "run_id": None})
    try:
        assert "design review" in _run_policy_search("quixotic libraries")
        assert "No matching policy" in _run_policy_search("zzzqqq-nothing")
    finally:
        _search_scope.reset(token)


def test_backfill_fills_null_embeddings():
    from security_agent.policy.service import backfill_embeddings, document_chunks

    doc = create_document(
        scope="platform",
        title="Backfill doc",
        text="Backfill target words for embedding.",
        embed=False,
    )
    chunks = document_chunks(doc.id)
    assert chunks and all(c.embedding is None for c in chunks)
    filled_vec = [0.1] * POLICY_EMBEDDING_DIM
    with mock.patch(
        "security_agent.brain.embeddings.embed_texts",
        side_effect=lambda texts, **kw: [filled_vec] * len(texts),
    ) as stub:
        # service imports embed_texts at call time from the same module.
        # Other suites' unembedded chunks may fill in the same pass.
        assert backfill_embeddings() >= len(chunks)
        stub.assert_called()
    after = document_chunks(doc.id)
    assert all(c.embedding is not None for c in after)
