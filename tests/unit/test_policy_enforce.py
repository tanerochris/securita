"""Checkpoints: block, approval gates, silence, parks, fail-closed."""

from unittest import mock

from security_agent.db.models import (
    Finding,
    FindingStatus,
    Proposal,
    Repo,
    RepoKind,
    RunTrigger,
    ScanRun,
)
from security_agent.db.session import session_scope
from security_agent.policy.enforce import (
    apply_ingest_silence,
    park_for_policy,
    pre_deliver_check,
    pre_patch_check,
)
from security_agent.policy.rules import confirm_rule, create_rule
from security_agent.policy.service import PolicyStoreError


def _repo(name: str) -> int:
    # Direct insert: connect_repo enqueues a RUNNING scan that would trip
    # the single-flight invariant when a test adds its own run.
    with session_scope() as db:
        repo = Repo(name=name, kind=RepoKind.GIT, url=f"https://example.com/{name}.git")
        db.add(repo)
        db.flush()
        return repo.id


def _run(repo_id: int) -> int:
    with session_scope() as db:
        run = ScanRun(repo_id=repo_id, trigger=RunTrigger.MANUAL)
        db.add(run)
        db.flush()
        return run.id


def _finding(repo_id: int, package: str, advisory: str = "CVE-ENF-1") -> Finding:
    with session_scope() as db:
        row = Finding(
            repo_id=repo_id,
            package=package,
            installed_version="1.0.0",
            advisory_id=advisory,
        )
        db.add(row)
        db.flush()
        db.expunge(row)
        return row


def test_pre_patch_block_marks_and_holds():
    repo_id = _repo("enforce-block")
    run_id = _run(repo_id)
    finding = _finding(repo_id, "blocked-lib")
    rule = create_rule(
        scope="platform", effect="block", match={"package": "blocked-lib"}, reason="no"
    )
    confirm_rule(rule.rule_key)
    out = pre_patch_check(repo_id, run_id, [finding])
    assert out == {
        "proceed": [],
        "blocked": [finding.id],
        "awaiting": [],
        "silenced": [],
    }
    with session_scope() as db:
        row = db.get(Finding, finding.id)
        assert row is not None and row.status == FindingStatus.OPEN
        assert (row.policy_block or {}).get("rule_key") == rule.rule_key


def test_pre_patch_no_rules_proceeds():
    repo_id = _repo("enforce-open")
    run_id = _run(repo_id)
    finding = _finding(repo_id, "free-lib")
    out = pre_patch_check(repo_id, run_id, [finding])
    assert out["proceed"] == [finding.id]


def test_require_approval_gate_lifecycle():
    from security_agent.app import accounts as accounts_svc
    from security_agent.control.gates import decide_gate
    from security_agent.db.models import Role

    repo_id = _repo("enforce-gate")
    run_id = _run(repo_id)
    finding = _finding(repo_id, "gated-lib")
    rule = create_rule(
        scope="platform",
        effect="require_approval",
        match={"package": "gated-lib"},
        reason="review",
    )
    confirm_rule(rule.rule_key)
    first = pre_patch_check(repo_id, run_id, [finding])
    assert first["awaiting"] == [finding.id]
    # Re-check while pending stays awaiting (idempotent gate request).
    again = pre_patch_check(repo_id, run_id, [finding])
    assert again["awaiting"] == [finding.id]
    from security_agent.control.gates import list_pending_gates

    gate = [g for g in list_pending_gates() if g.repo_id == repo_id][0]
    owner = accounts_svc.create_user("enf-owner@example.com", None, Role.OWNER)
    decide_gate(gate.id, owner, True)
    third = pre_patch_check(repo_id, run_id, [finding])
    assert third["proceed"] == [finding.id]


def test_denied_gate_behaves_as_block():
    from security_agent.app import accounts as accounts_svc
    from security_agent.control.gates import decide_gate, list_pending_gates
    from security_agent.db.models import Role

    repo_id = _repo("enforce-deny")
    run_id = _run(repo_id)
    finding = _finding(repo_id, "deny-lib")
    rule = create_rule(
        scope="platform",
        effect="require_approval",
        match={"package": "deny-lib"},
        reason="review",
    )
    confirm_rule(rule.rule_key)
    assert pre_patch_check(repo_id, run_id, [finding])["awaiting"] == [finding.id]
    gate = [g for g in list_pending_gates() if g.repo_id == repo_id][0]
    owner = accounts_svc.create_user("enf-denier@example.com", None, Role.OWNER)
    decide_gate(gate.id, owner, False)
    out = pre_patch_check(repo_id, run_id, [finding])
    assert out["blocked"] == [finding.id]


def test_ingest_silence_and_verdict_exemption():
    from security_agent.control.lifecycle import apply_verdict

    repo_id = _repo("enforce-silence")
    finding = _finding(repo_id, "quiet-lib")
    rule = create_rule(
        scope="platform",
        effect="silence",
        match={"package": "quiet-lib"},
        reason="accepted",
    )
    confirm_rule(rule.rule_key)
    assert apply_ingest_silence(repo_id, [finding.id]) == 1
    with session_scope() as db:
        row = db.get(Finding, finding.id)
        assert row is not None and row.status == FindingStatus.SILENT
    # A reachable verdict must not reopen policy silence.
    apply_verdict(finding.id, _run(repo_id), True, reason_code="import")
    with session_scope() as db:
        row = db.get(Finding, finding.id)
        assert row is not None and row.status == FindingStatus.SILENT


def test_pre_deliver_holds_blocked_proposals():
    repo_id = _repo("enforce-deliver")
    run_id = _run(repo_id)
    finding = _finding(repo_id, "ship-lib")
    with session_scope() as db:
        proposal = Proposal(
            repo_id=repo_id,
            finding_ids=[finding.id],
            package_from="1.0.0",
            package_to="1.0.1",
            verification_result="ok",
        )
        db.add(proposal)
        db.flush()
        db.expunge(proposal)
    rule = create_rule(
        scope="platform", effect="block", match={"package": "ship-lib"}, reason="hold"
    )
    confirm_rule(rule.rule_key)
    out = pre_deliver_check(repo_id, run_id, [proposal])
    assert out == {"deliver": [], "held": [proposal.id]}


def test_mid_run_tightening_holds_pending_delivery():
    repo_id = _repo("enforce-tighten")
    run_id = _run(repo_id)
    finding = _finding(repo_id, "tighten-lib")
    with session_scope() as db:
        proposal = Proposal(
            repo_id=repo_id,
            finding_ids=[finding.id],
            package_from="1.0.0",
            package_to="1.0.1",
            verification_result="ok",
        )
        db.add(proposal)
        db.flush()
        db.expunge(proposal)
    assert pre_deliver_check(repo_id, run_id, [proposal])["deliver"] == [proposal.id]
    rule = create_rule(
        scope="platform",
        effect="block",
        match={"package": "tighten-lib"},
        reason="tightened mid-run",
    )
    confirm_rule(rule.rule_key)
    out = pre_deliver_check(repo_id, run_id, [proposal])
    assert out == {"deliver": [], "held": [proposal.id]}


def test_evaluation_failure_parks_fail_closed():
    repo_id = _repo("enforce-park")
    run_id = _run(repo_id)
    finding = _finding(repo_id, "park-lib")
    with mock.patch(
        "security_agent.policy.enforce.applicable_rules",
        side_effect=RuntimeError("db gone"),
    ):
        try:
            pre_patch_check(repo_id, run_id, [finding])
        except PolicyStoreError:
            parked = park_for_policy(run_id, "probe")
        else:  # pragma: no cover - the checkpoint must raise
            parked = False
    assert parked
    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        assert run is not None and run.parked
        assert "policy" in (run.park_reason or "")


def test_park_is_idempotent_and_notifies_once():
    repo_id = _repo("enforce-park2")
    run_id = _run(repo_id)
    with mock.patch("security_agent.notify.notify_event") as notified:
        assert park_for_policy(run_id, "first") is True
        assert park_for_policy(run_id, "second") is False
        notified.assert_called_once()
