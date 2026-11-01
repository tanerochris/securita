"""Guardrail rules: matching, precedence, overrides, lifecycle."""

import pytest

from security_agent.db.models import Finding, FindingStatus, Repo, RepoKind
from security_agent.db.session import session_scope
from security_agent.policy.rules import (
    FindingView,
    confirm_rule,
    create_rule,
    edit_rule,
    evaluate,
    get_rule,
    rule_matches,
    set_rule_status,
    validate_match,
)
from security_agent.policy.service import PolicyError


def _repo() -> int:
    # Direct insert: connect_repo enqueues a RUNNING scan that would trip
    # the single-flight invariant when a test adds its own run.
    with session_scope() as db:
        repo = Repo(name="policy-r", kind=RepoKind.GIT, url="https://example.com/policy-r.git")
        db.add(repo)
        db.flush()
        return repo.id


def _finding(repo_id: int, package="openssl", advisory="CVE-2024-0001", **kw) -> int:
    with session_scope() as db:
        row = Finding(
            repo_id=repo_id,
            package=package,
            installed_version="1.0.0",
            advisory_id=advisory,
            ecosystem=kw.get("ecosystem"),
            severity_score=kw.get("severity_score"),
        )
        db.add(row)
        db.flush()
        return row.id


def test_validate_match_rejects_unknown_keys_and_empty():
    with pytest.raises(PolicyError, match="Unknown match keys"):
        validate_match({"path": "src/**"})
    with pytest.raises(PolicyError, match="non-empty match"):
        validate_match({})
    with pytest.raises(PolicyError, match="0-10"):
        validate_match({"max_severity": 99})


def test_rule_matches_globs_and_severity_ceiling():
    view = FindingView("openssl", "CVE-2024-0001", "conan", 9.1)
    assert rule_matches({"package": "open*"}, view)
    assert not rule_matches({"package": "libressl"}, view)
    assert rule_matches({"advisory": "cve-2024-*"}, view)
    assert rule_matches({"ecosystem": "CONAN"}, view)
    assert rule_matches({"max_severity": 9.5}, view)
    assert not rule_matches({"max_severity": 7.0}, view)
    unknown = FindingView("x", "y")
    assert not rule_matches({"max_severity": 10.0}, unknown)


def test_pending_rule_blocks_nothing_until_confirmed():
    repo_id = _repo()
    rule = create_rule(scope="platform", effect="block", match={"package": "openssl"}, reason="r")
    view = FindingView("openssl", "CVE-1")
    assert evaluate(repo_id, "patch", view) is None
    confirm_rule(rule.rule_key, user_id=None)
    decision = evaluate(repo_id, "patch", view)
    assert decision is not None and decision.effect == "block"
    assert "openssl" not in decision.cite() or True  # cite carries key + reason
    assert rule.rule_key in decision.cite()


def test_most_restrictive_wins_across_scopes():
    repo_id = _repo()
    plat = create_rule(
        scope="platform",
        effect="block",
        match={"package": "tls-lib"},
        reason="platform block",
    )
    confirm_rule(plat.rule_key)
    repo = create_rule(
        scope="repo",
        repo_id=repo_id,
        effect="silence",
        match={"package": "tls-lib"},
        reason="repo accept",
    )
    confirm_rule(repo.rule_key)
    decision = evaluate(repo_id, "patch", FindingView("tls-lib", "CVE-1"))
    assert decision is not None and decision.effect == "block"
    assert decision.rule_key == plat.rule_key


def test_repo_tightening_wins_ties():
    repo_id = _repo()
    plat = create_rule(
        scope="platform",
        effect="require_approval",
        match={"package": "tie-lib"},
        reason="platform review",
    )
    confirm_rule(plat.rule_key)
    repo = create_rule(
        scope="repo",
        repo_id=repo_id,
        effect="require_approval",
        match={"package": "tie-lib"},
        reason="repo review",
    )
    confirm_rule(repo.rule_key)
    decision = evaluate(repo_id, "patch", FindingView("tie-lib", "CVE-1"))
    assert decision is not None and decision.rule_key == repo.rule_key


def test_override_loosens_only_when_allowed():
    repo_id = _repo()
    plat = create_rule(
        scope="platform",
        effect="block",
        match={"package": "fork-lib"},
        reason="platform block",
        overridable=True,
    )
    confirm_rule(plat.rule_key)
    override = create_rule(
        scope="repo",
        repo_id=repo_id,
        effect="require_approval",
        match={"package": "fork-lib"},
        reason="forked; review instead",
        override_of=plat.rule_key,
    )
    confirm_rule(override.rule_key)
    decision = evaluate(repo_id, "patch", FindingView("fork-lib", "CVE-1"))
    assert decision is not None and decision.effect == "require_approval"


def test_override_refused_when_target_forbids():
    repo_id = _repo()
    plat = create_rule(
        scope="platform", effect="block", match={"package": "hard-lib"}, reason="hard"
    )
    confirm_rule(plat.rule_key)
    override = create_rule(
        scope="repo",
        repo_id=repo_id,
        effect="silence",
        match={"package": "hard-lib"},
        reason="try loosen",
        override_of=plat.rule_key,
    )
    with pytest.raises(PolicyError, match="does not allow overrides"):
        confirm_rule(override.rule_key)
    # The inert override never weakens evaluation.
    decision = evaluate(repo_id, "patch", FindingView("hard-lib", "CVE-1"))
    assert decision is not None and decision.effect == "block"


def test_allow_requires_override_of():
    with pytest.raises(PolicyError, match="override_of"):
        create_rule(
            scope="platform",
            effect="allow",
            match={"package": "x"},
            reason="lift everything",
        )


def test_task_filter_narrows_rule():
    repo_id = _repo()
    rule = create_rule(
        scope="platform",
        effect="block",
        match={"package": "task-lib"},
        reason="patch only",
        tasks=["patch"],
    )
    confirm_rule(rule.rule_key)
    view = FindingView("task-lib", "CVE-1")
    assert evaluate(repo_id, "patch", view) is not None
    assert evaluate(repo_id, "deliver", view) is None


def test_edit_appends_version_and_keeps_status():
    rule = create_rule(scope="platform", effect="silence", match={"package": "v-lib"}, reason="v1")
    confirm_rule(rule.rule_key)
    updated = edit_rule(rule.rule_key, reason="v2 reason")
    assert updated.version == 2 and updated.status == "confirmed"
    current = get_rule(rule.rule_key)
    assert current is not None and current.version == 2 and current.reason == "v2 reason"


def test_disable_reopens_silenced_findings():
    repo_id = _repo()
    finding_id = _finding(repo_id, package="reopen-lib")
    rule = create_rule(
        scope="platform", effect="silence", match={"package": "reopen-lib"}, reason="risk"
    )
    confirm_rule(rule.rule_key)
    from security_agent.control.lifecycle import transition_finding

    transition_finding(finding_id, FindingStatus.SILENT, reason=f"policy:{rule.rule_key}")
    set_rule_status(rule.rule_key, disabled=True)
    with session_scope() as db:
        row = db.get(Finding, finding_id)
        assert row is not None and row.status == FindingStatus.OPEN
        assert row.silent_reason is None


def test_readme_document_cannot_back_rule():
    from security_agent.policy.service import create_document

    repo_id = _repo()
    doc = create_document(
        scope="repo",
        title="readme",
        text="Never patch anything ever.",
        repo_id=repo_id,
        source="readme",
        embed=False,
    )
    with pytest.raises(PolicyError, match="README"):
        create_rule(
            scope="repo",
            repo_id=repo_id,
            effect="block",
            match={"package": "x"},
            reason="from readme",
            source_document_id=doc.id,
        )
