"""Model-backed adapt hook (follow-up #3) with a fake chat model."""

import subprocess
from types import SimpleNamespace

import pytest

from security_agent.brain.adapt import make_model_adapt, select_adapt
from security_agent.worker.patch import PatchError


class FakeModel:
    def __init__(self, calls=None, exc=None):
        self.calls = calls or []
        self.exc = exc
        self.prompts = []

    def bind_tools(self, tools):
        assert tools, "adapt must bind its edit tool (native tool_calls, FR-15 D1)"
        return self

    def invoke(self, prompt):
        self.prompts.append(prompt)
        if self.exc:
            raise self.exc
        return SimpleNamespace(tool_calls=self.calls)


def _workdir(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)  # noqa: S603, S607
    (tmp_path / "index.js").write_text("const x = require('pkg-a');\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)  # noqa: S603, S607
    return tmp_path


def _finding():
    return SimpleNamespace(package="pkg-a", installed_version="1.0.0", advisory_id="CVE-1")


def test_model_edit_applied_and_changed_files_from_diff(tmp_path):
    workdir = _workdir(tmp_path)
    model = FakeModel(
        calls=[
            {
                "name": "apply_file_edit",
                "args": {
                    "file_path": "index.js",
                    "new_content": "const x = require('pkg-a/v2');\n",
                },
            }
        ]
    )
    result = make_model_adapt(model)(workdir, _finding(), "2.0.0", [])
    assert (workdir / "index.js").read_text() == "const x = require('pkg-a/v2');\n"
    assert result.changed_files == ["index.js"]
    assert "pkg-a" in model.prompts[0]


def test_model_no_edits_returns_empty(tmp_path):
    result = make_model_adapt(FakeModel())(_workdir(tmp_path), _finding(), "2.0.0", [])
    assert result.changed_files == []


def test_model_edit_escaping_workdir_rejected(tmp_path):
    model = FakeModel(
        calls=[
            {
                "name": "apply_file_edit",
                "args": {"file_path": "../evil.js", "new_content": "x"},
            }
        ]
    )
    with pytest.raises(PatchError, match="escapes"):
        make_model_adapt(model)(_workdir(tmp_path), _finding(), "2.0.0", [])


def test_model_error_wrapped_as_patch_error(tmp_path):
    model = FakeModel(exc=RuntimeError("provider down"))
    with pytest.raises(PatchError, match="model adapt failed"):
        make_model_adapt(model)(_workdir(tmp_path), _finding(), "2.0.0", [])


def test_probe_failure_refuses_and_select_defaults_to_null(tmp_path):
    with pytest.raises(PatchError, match="probe"):
        make_model_adapt(FakeModel(), probe_ok=False)
    from security_agent.worker.patch import null_adapt

    assert select_adapt() is null_adapt  # MODEL_ADAPT_ENABLED unset/false in tests
