"""Dependency lifecycle: cadence, budget, decisions, silences, D20 (D7/D10/D15/D21/D23)."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select

from security_agent.app import accounts as accounts_svc
from security_agent.control import deps as deps_svc
from security_agent.control import repos as repo_svc
from security_agent.db.models import (
    Dependency,
    DependencyReport,
    DependencyStatus,
    Finding,
    FindingStatus,
    NotifyState,
    Proposal,
    ProposalStatus,
    RepoKind,
    Role,
)
from security_agent.db.session import session_scope


def _user(role: Role):
    email = f"deps-{role.value}-{datetime.now(UTC).timestamp()}@example.com"
    return accounts_svc.create_user(email, None, role)


def _reset_deps_budget():
    with session_scope() as db:
        db.execute(
            delete(NotifyState).where(NotifyState.key.in_(["deps.token_cap", "deps.spend_cap"]))
        )


def _usd(tokens: int) -> float:
    """Budget dollars for a token count at the resolved model price."""
    from security_agent.control.brain_settings import price_per_token_usd

    return tokens * price_per_token_usd()


def _repo():
    return repo_svc.connect_repo(
        f"deps-{datetime.now(UTC).timestamp()}", RepoKind.LOCAL, local_path="/tmp/x"
    )


def _dep(repo_id: int, **overrides) -> Dependency:
    base = {
        "repo_id": repo_id,
        "ecosystem": "npm",
        "manifest_path": "package.json",
        "package": "left-pad",
        "manifest_spec": "^1.3.0",
        "installed_version": "1.3.0",
        "latest_version": "1.9.0",
        "update_class": "minor",
        "status": DependencyStatus.UPDATE_AVAILABLE,
    }
    base.update(overrides)
    with session_scope() as db:
        row = Dependency(**base)
        db.add(row)
        db.flush()
        db.expunge(row)
        return row


def test_cadence_global_and_override():
    owner, dev = _user(Role.OWNER), _user(Role.DEVELOPER)
    repo = _repo()
    assert deps_svc.effective_dep_interval(repo) == 24  # install default
    deps_svc.set_dep_check_hours(48, owner)
    try:
        with session_scope() as db:
            fresh = db.get(type(repo), repo.id)
            assert fresh is not None
            assert deps_svc.effective_dep_interval(fresh) == 48
        deps_svc.set_repo_dep_interval(repo.id, 0, owner)  # never automatically
        with session_scope() as db:
            fresh = db.get(type(repo), repo.id)
            assert deps_svc.effective_dep_interval(fresh) is None
        deps_svc.set_repo_dep_interval(repo.id, None, owner)  # inherit again
        with session_scope() as db:
            fresh = db.get(type(repo), repo.id)
            assert deps_svc.effective_dep_interval(fresh) == 48
        with pytest.raises(PermissionError):
            deps_svc.set_dep_check_hours(12, dev)
    finally:
        deps_svc.set_dep_check_hours(24, owner)


def test_budget_is_separate_and_ledgers():
    owner = _user(Role.OWNER)
    _reset_deps_budget()
    state = deps_svc.deps_budget_state()
    assert state["cap"] > 0 and not state["exhausted"]
    deps_svc.set_deps_spend_cap(10**9, owner)
    try:
        out = deps_svc.record_deps_usage("report", 100, 50)
        assert out["total"] == 150
        with session_scope() as db:
            from security_agent.db.models import ModelUsage

            row = db.scalar(
                select(ModelUsage).where(ModelUsage.task.like("deps-%")).order_by(
                    ModelUsage.id.desc()
                )
            )
            assert row is not None and row.run_id is None  # never touches run caps
    finally:
        _reset_deps_budget()


def test_budget_hit_raises():
    owner = _user(Role.OWNER)
    _reset_deps_budget()
    deps_svc.set_deps_spend_cap(_usd(10), owner)
    try:
        with pytest.raises(deps_svc.DepsBudgetExceeded):
            deps_svc.record_deps_usage("report", 10, 10)
    finally:
        _reset_deps_budget()


def test_legacy_token_budget_still_enforced_as_usd():
    """Pre-USD installs keep working: deps.token_cap tokens convert at price."""
    _reset_deps_budget()
    with session_scope() as db:
        db.add(NotifyState(key="deps.token_cap", value="1000"))
    try:
        assert deps_svc.get_deps_spend_cap() == pytest.approx(_usd(1000))
        deps_svc.set_deps_spend_cap(1.5, _user(Role.OWNER))
        with session_scope() as db:
            assert db.get(NotifyState, "deps.token_cap") is None
        assert deps_svc.get_deps_spend_cap() == 1.5
    finally:
        _reset_deps_budget()


def test_deps_budget_roles_floor_and_disable():
    owner, dev = _user(Role.OWNER), _user(Role.DEVELOPER)
    _reset_deps_budget()
    try:
        with pytest.raises(PermissionError):
            deps_svc.set_deps_spend_cap(1.0, dev)
        with pytest.raises(ValueError, match="at least 0"):
            deps_svc.set_deps_spend_cap(-1.0, owner)
        deps_svc.set_deps_spend_cap(0, owner)  # disables
        state = deps_svc.deps_budget_state()
        assert state["cap"] == 0.0 and state["exhausted"] is False
    finally:
        _reset_deps_budget()


def test_notify_email_opt_in_owner_only():
    owner, maintainer = _user(Role.OWNER), _user(Role.MAINTAINER)
    assert deps_svc.deps_notify_email_enabled() is False  # dashboard-only default
    with pytest.raises(PermissionError):
        deps_svc.set_deps_notify_email(True, maintainer)
    deps_svc.set_deps_notify_email(True, owner)
    try:
        assert deps_svc.deps_notify_email_enabled() is True
    finally:
        deps_svc.set_deps_notify_email(False, owner)


def test_decline_ignore_unignore_roundtrip():
    owner, dev = _user(Role.OWNER), _user(Role.DEVELOPER)
    repo = _repo()
    row = _dep(repo.id)
    with pytest.raises(PermissionError):
        deps_svc.ignore_package(row.id, dev)
    deps_svc.decline_version(row.id, owner, reason="waiting")
    with session_scope() as db:
        stored = db.get(Dependency, row.id)
        assert stored is not None
        assert stored.status == DependencyStatus.DECLINED
        assert stored.declined_version == "1.9.0"
    deps_svc.ignore_package(row.id, owner)
    with session_scope() as db:
        stored = db.get(Dependency, row.id)
        assert stored is not None
        assert stored.status == DependencyStatus.IGNORED
        assert stored.ignored_by == owner.id and stored.ignored_at is not None
    deps_svc.unignore_package(row.id, owner)
    with session_scope() as db:
        stored = db.get(Dependency, row.id)
        assert stored is not None
        assert stored.status == DependencyStatus.UPDATE_AVAILABLE
        assert stored.ignored_by is None


def _report(repo_id: int, keys: list[str]) -> DependencyReport:
    with session_scope() as db:
        report = DependencyReport(
            repo_id=repo_id,
            status="pending",
            summary="s",
            sections=[],
            undecided_keys=keys,
        )
        db.add(report)
        db.flush()
        db.expunge(report)
        return report


def test_decide_report_included_proposed_excluded_declined():
    owner = _user(Role.OWNER)
    repo = _repo()
    a = _dep(repo.id, package="a", status=DependencyStatus.AWAITING_DECISION)
    b = _dep(repo.id, package="b", status=DependencyStatus.AWAITING_DECISION)
    ka, kb = f"npm|package.json|{a.package}", f"npm|package.json|{b.package}"
    report = _report(repo.id, [ka, kb])
    deps_svc.decide_report(report.id, owner, [ka], reason="ship a")
    with session_scope() as db:
        stored_a, stored_b = db.get(Dependency, a.id), db.get(Dependency, b.id)
        assert stored_a is not None and stored_b is not None
        assert stored_a.status == DependencyStatus.PROPOSED
        assert stored_b.status == DependencyStatus.DECLINED
        assert stored_b.declined_version == stored_b.latest_version
        stored_r = db.get(DependencyReport, report.id)
        assert stored_r is not None and stored_r.status == "decided"
        assert stored_r.decided_keys == [ka] and stored_r.excluded_keys == [kb]
        assert stored_r.decided_by == owner.id
    with pytest.raises(ValueError, match="already decided"):
        deps_svc.decide_report(report.id, owner, [ka, kb])


def test_decide_report_developer_forbidden():
    dev = _user(Role.DEVELOPER)
    repo = _repo()
    report = _report(repo.id, ["npm|package.json|a"])
    with pytest.raises(PermissionError):
        deps_svc.decide_report(report.id, dev, ["npm|package.json|a"])


def test_live_finding_proposal_blocks_package():
    repo = _repo()
    assert deps_svc.live_finding_proposal(repo.id, "left-pad") is None
    with session_scope() as db:
        finding = Finding(
            repo_id=repo.id,
            package="left-pad",
            installed_version="1.0.0",
            advisory_id="CVE-X",
            status=FindingStatus.PROPOSED,
        )
        db.add(finding)
        db.flush()
        proposal = Proposal(
            repo_id=repo.id,
            finding_ids=[finding.id],
            package_from="1.0.0",
            package_to="1.0.1",
            verification_result="ok",
            status=ProposalStatus.OPEN,
        )
        db.add(proposal)
    live = deps_svc.live_finding_proposal(repo.id, "left-pad")
    assert live is not None and live.status == ProposalStatus.OPEN
    assert deps_svc.live_finding_proposal(repo.id, "other") is None


def test_security_fix_for_tags_when_target_ships_fix():
    repo = _repo()
    with session_scope() as db:
        db.add(
            Finding(
                repo_id=repo.id,
                package="left-pad",
                installed_version="1.0.0",
                advisory_id="CVE-X",
                status=FindingStatus.OPEN,
                fixed_versions=["1.0.1"],
            )
        )
    fix = deps_svc.security_fix_for(repo.id, "left-pad", "1.0.0", "1.9.0")
    assert fix is not None and fix.advisory_id == "CVE-X"
    # Target below the fix: no tag.
    assert deps_svc.security_fix_for(repo.id, "left-pad", "1.0.0", "1.0.0") is None
