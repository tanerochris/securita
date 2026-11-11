"""PR copy: concise template fallback + model-written title/body."""

import json
from types import SimpleNamespace
from unittest import mock

import pytest

from security_agent.brain.pr_text import generate_pr_text
from security_agent.worker.deliver import _find_pr_template, _render_pr_text, render_pr


class _FakeModel:
    """Chat model stub: canned content, char-estimated usage via tracked_invoke."""

    prompts: list = []

    def __init__(self, content=None, exc=None):
        self._content = content
        self._exc = exc

    def invoke(self, prompt):
        _FakeModel.prompts.append(prompt)
        if self._exc is not None:
            raise self._exc
        return SimpleNamespace(content=self._content, usage_metadata={})


def _advs(n):
    return [f"CVE-2026-{44572 + i}" for i in range(n)]


def test_render_pr_single_advisory_unchanged():
    title, body = render_pr(
        "left-pad",
        "1.0.0",
        "1.0.1",
        ["CVE-1"],
        ["CVE-1"],
        ["v"],
        "single package",
        [],
        "http://dash",
    )
    assert title == "[security] left-pad 1.0.0→1.0.1 (CVE-1)"
    assert body.splitlines()[0] == "left-pad 1.0.0 → 1.0.1 fixes CVE-1."
    assert "WARNING: CVE-1 is CISA KEV exploited." in body


def test_render_pr_many_advisories_stays_short():
    advs = _advs(33)
    title, body = render_pr(
        "next",
        "16.2.4",
        "15.5.28",
        advs,
        [],
        ["v"],
        "single package",
        [],
        "http://dash",
    )
    assert len(title) <= 100
    assert "33 advisories" in title
    assert advs[-1] not in title
    assert body.splitlines()[0] == "next 16.2.4 → 15.5.28 fixes 33 advisories."
    assert "and 13 more" in body
    assert "Dashboard: http://dash" in body


def test_generate_uses_model_output():
    content = json.dumps(
        {
            "title": "[security] next 16.2.4→15.5.28 fixes 33 advisories",
            "body": "next 16.2.4 → 15.5.28 fixes 33 advisories.",
        }
    )
    title, body = generate_pr_text(
        "next",
        "16.2.4",
        "15.5.28",
        _advs(33),
        [],
        ["v"],
        "single package",
        [],
        "http://dash",
        model=_FakeModel(content),
    )
    assert title == "[security] next 16.2.4→15.5.28 fixes 33 advisories"
    assert "Dashboard: http://dash" in body  # repaired when the model omits it


def test_generate_rejects_bad_output():
    bad = [
        "not json",
        json.dumps({"title": "no prefix here", "body": "b"}),
        json.dumps({"title": "[security] a\ntwo lines", "body": "b"}),
        json.dumps({"title": "[security] " + "x" * 200, "body": "b"}),
        json.dumps({"title": "[security] ok", "body": ""}),
    ]
    for content in bad:
        assert (
            generate_pr_text(
                "p",
                "1",
                "2",
                ["CVE-1"],
                [],
                ["v"],
                "g",
                [],
                "d",
                model=_FakeModel(content),
            )
            is None
        )


def test_generate_model_error_raises_brain_error():
    from security_agent.brain import BrainError

    with pytest.raises(BrainError, match="Brain call failed"):
        generate_pr_text(
            "p",
            "1",
            "2",
            ["CVE-1"],
            [],
            ["v"],
            "g",
            [],
            "d",
            model=_FakeModel(exc=RuntimeError("provider down")),
        )


def test_generate_cost_cap_propagates():
    from security_agent.control.cost import CostCapExceeded

    with mock.patch("security_agent.brain.tracked_invoke", side_effect=CostCapExceeded("cap")):
        with pytest.raises(CostCapExceeded):
            generate_pr_text(
                "p",
                "1",
                "2",
                ["CVE-1"],
                [],
                ["v"],
                "g",
                [],
                "d",
                model=_FakeModel("{}"),
            )


def test_generate_live_path_needs_flag():
    settings = mock.Mock(pr_text_model_enabled=False)
    with (
        mock.patch("security_agent.config.get_settings", return_value=settings),
        mock.patch("security_agent.brain.get_chat_model") as fake,
    ):
        assert generate_pr_text("p", "1", "2", ["CVE-1"], [], ["v"], "g", [], "d") is None
        fake.assert_not_called()


_TEMPLATE = "## Summary\n\nWhat changed?\n\n## Checklist\n\n- [ ] Tests pass\n- [ ] Docs updated\n"


def test_generate_fills_repo_template():
    content = json.dumps(
        {
            "title": "[security] next 16.2.4→15.5.28 fixes 2 advisories",
            "body": "## Summary\n\nnext 16.2.4 → 15.5.28 fixes 2 advisories."
            "\n\n## Checklist\n\n- [x] Tests pass\n- [ ] Docs updated\nDashboard: http://dash",
        }
    )
    title, body = generate_pr_text(
        "next",
        "16.2.4",
        "15.5.28",
        _advs(2),
        [],
        ["v"],
        "single package",
        [],
        "http://dash",
        model=_FakeModel(content),
        template=_TEMPLATE,
    )
    assert title.startswith("[security] next")
    assert "## Checklist" in body and "[x] Tests pass" in body
    assert _TEMPLATE.splitlines()[0] in _FakeModel.prompts[-1]


def test_generate_rejects_template_structure_dropped():
    content = json.dumps({"title": "[security] p 1→2 fixes 1 advisory", "body": "free text"})
    assert (
        generate_pr_text(
            "p",
            "1",
            "2",
            ["CVE-1"],
            [],
            ["v"],
            "g",
            [],
            "d",
            model=_FakeModel(content),
            template=_TEMPLATE,
        )
        is None
    )


def test_find_pr_template(tmp_path):
    assert _find_pr_template(tmp_path) is None
    gh = tmp_path / ".github"
    gh.mkdir()
    (gh / "pull_request_template.md").write_text("## Summary\n\nTell us.\n")
    assert _find_pr_template(tmp_path).startswith("## Summary")


def test_find_pr_template_dir_keyword_pick(tmp_path):
    directory = tmp_path / ".github" / "PULL_REQUEST_TEMPLATE"
    directory.mkdir(parents=True)
    (directory / "feature.md").write_text("## Feature\n")
    (directory / "security_fix.md").write_text("## Security fix\n")
    assert "Security fix" in _find_pr_template(tmp_path)


def test_render_pr_text_forwards_template():
    with mock.patch("security_agent.brain.pr_text.generate_pr_text", return_value=None) as fake:
        _render_pr_text(
            "p",
            "1",
            "2",
            ["CVE-1"],
            [],
            ["v"],
            "g",
            [],
            "d",
            template=_TEMPLATE,
            repo_id=7,
        )
    fake.assert_called_once()
    assert fake.call_args.kwargs["template"] == _TEMPLATE
    assert fake.call_args.kwargs["repo_id"] == 7


def test_generate_includes_policy_guidance():
    from security_agent.policy.constants import GUIDANCE_TASKS

    assert "pr-text" in GUIDANCE_TASKS
    content = json.dumps({"title": "[security] p 1→2 fixes 1 advisory", "body": "b"})
    with mock.patch(
        "security_agent.policy.retrieve.retrieve_policy_context",
        return_value=("POLICY: use conventional commits", [3]),
    ) as fake:
        title, _ = generate_pr_text(
            "p",
            "1",
            "2",
            ["CVE-1"],
            [],
            ["v"],
            "g",
            [],
            "d",
            model=_FakeModel(content),
            repo_id=9,
        )
    assert title == "[security] p 1→2 fixes 1 advisory"
    assert fake.call_args.args[:2] == (9, "pr-text")
    assert "pull request" in fake.call_args.args[2]
    assert "POLICY: use conventional commits" in _FakeModel.prompts[-1]


def test_generate_policy_failure_still_returns_model_output():
    content = json.dumps({"title": "[security] p 1→2 fixes 1 advisory", "body": "b"})
    with mock.patch(
        "security_agent.policy.retrieve.retrieve_policy_context",
        side_effect=RuntimeError("store down"),
    ):
        result = generate_pr_text(
            "p",
            "1",
            "2",
            ["CVE-1"],
            [],
            ["v"],
            "g",
            [],
            "d",
            model=_FakeModel(content),
            repo_id=9,
        )
    assert result is not None and result[0] == "[security] p 1→2 fixes 1 advisory"


def test_render_pr_text_prefers_model_then_template():
    with mock.patch(
        "security_agent.brain.pr_text.generate_pr_text",
        return_value=("[security] p 1→2 fixes 1 advisory", "b\nDashboard: d"),
    ):
        assert _render_pr_text("p", "1", "2", ["CVE-1"], [], ["v"], "g", [], "d")[0] == (
            "[security] p 1→2 fixes 1 advisory"
        )
    with mock.patch(
        "security_agent.brain.pr_text.generate_pr_text", side_effect=RuntimeError("down")
    ):
        title, _ = _render_pr_text("p", "1", "2", ["CVE-1"], [], ["v"], "g", [], "d")
        assert title == "[security] p 1→2 (CVE-1)"
