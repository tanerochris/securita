"""Central prompt templates: loading, strict substitution, golden renders."""

import pytest

from security_agent.prompts import PROMPT_NAMES, render_prompt


def test_all_registered_templates_load():
    for name in PROMPT_NAMES:
        rendered = render_prompt(name, **_SAMPLES[name])
        assert rendered and "$" not in rendered


def test_unknown_template_rejected():
    with pytest.raises(ValueError, match="Unknown prompt template"):
        render_prompt("nope", x="y")


def test_missing_value_fails_loudly():
    with pytest.raises(KeyError):
        render_prompt("news_classify", title="t")


def test_draft_pr_golden_render():
    out = render_prompt(
        "draft_pr",
        package="next",
        from_version="16.2.4",
        to_version="15.5.28",
        advisory_count="33",
        advisories="CVE-2026-44572, and 3 more",
        kev="none",
        verification="tests passed",
        grouping="single package",
        ignored="none",
        dashboard="http://dash",
    )
    assert out.startswith("You write the title and body of a security-update pull request.")
    assert "ADVISORIES (33 total): CVE-2026-44572, and 3 more" in out
    assert "PACKAGE: next\nFROM: 16.2.4\nTO: 15.5.28" in out
    assert out.endswith("DASHBOARD: http://dash\n")


def test_template_block_keeps_leading_newline():
    out = render_prompt("draft_pr_template_block", template="## Summary")
    assert out.startswith("\nThe repository provides the pull request template")
    assert "## Summary" in out and out.endswith(">>>\n")


def test_adapt_templates_render_without_trailing_newline():
    out = render_prompt(
        "adapt",
        package="p",
        installed_version="1",
        target="2",
        failures="none",
        files_blob="--- a.js ---",
    )
    assert out == (
        "A dependency was bumped: p 1 -> 2. Prior failures: none. Call "
        "apply_file_edit for each file that must change for the new "
        "version; make no edits if none are needed. Company policy "
        "context is included below when found. If it is missing or does "
        "not cover this change, call search_policies with focused terms "
        "before editing — especially for auth, crypto, networking, or "
        "data-handling changes. At most two searches; if search finds "
        "nothing relevant, proceed.\n\n--- a.js ---"
    )


_SAMPLES = {
    "adapt": {
        "package": "p",
        "installed_version": "1",
        "target": "2",
        "failures": "none",
        "files_blob": "blob",
    },
    "adapt_search_followup": {"prompt": "p", "search_results": "s"},
    "deps_summary": {"max_words": "400", "sections": "left-pad 1.3.0 -> 1.4.0 (patch)"},
    "draft_pr": {
        "package": "p",
        "from_version": "1",
        "to_version": "2",
        "advisory_count": "1",
        "advisories": "CVE-1",
        "kev": "none",
        "verification": "v",
        "grouping": "g",
        "ignored": "none",
        "dashboard": "d",
    },
    "draft_pr_template_block": {"template": "t"},
    "news_classify": {"title": "t", "summary": "s", "excerpt": "e"},
    "news_relevance": {
        "profile_summary": "p",
        "verdict": "major",
        "category": "exploit",
        "cve_ids": "CVE-1",
        "title": "t",
        "summary": "s",
        "excerpt": "e",
    },
    "policy_extract": {"document": "d"},
}
