"""Slice G: gates, delegation, timeout sweep, merge execution."""

from datetime import UTC, datetime, timedelta
from unittest import mock

import pytest
from sqlalchemy import select

from security_agent.app import accounts as accounts_svc
from security_agent.control import gates
from security_agent.control import repos as repo_svc
from security_agent.db.models import (
    Approval,
    Finding,
    FindingStatus,
    GateAction,
    GateStatus,
    Proposal,
    RepoKind,
    Role,
    ScanRun,
    User,
)
from security_agent.db.session import session_scope
from security_agent.worker import build_graph
from security_agent.worker import deliver as deliver_mod
from security_agent.worker.deliver import DeliverError


def _email(tag: str) -> str:
    return f"{tag}-{datetime.now(UTC).timestamp()}@example.com"


def _user(tag: str, role: Role) -> User:
    return accounts_svc.create_user(_email(tag), None, role)


def _repo(tag: str = "gate-r", host: str = "example.com"):
    return repo_svc.connect_repo(tag, RepoKind.GIT, url=f"https://{host}/{tag}.git")


_ADVISORY_SEQ = 0


def _seed_proposal(repo_id: int, pr_url: str | None = "https://github.com/o/r/pull/7") -> int:
    global _ADVISORY_SEQ
    _ADVISORY_SEQ += 1
    with session_scope() as db:
        finding = Finding(
            repo_id=repo_id,
            package="left-pad",
            installed_version="1.0.0",
            advisory_id=f"CVE-G-{_ADVISORY_SEQ}",
            status=FindingStatus.PROPOSED,
        )
        db.add(finding)
        db.flush()
        proposal = Proposal(
            repo_id=repo_id,
            finding_ids=[finding.id],
            package_from="1.0.0",
            package_to="1.0.1",
            verification_result="tests passed",
            pr_url=pr_url,
            pr_state="open" if pr_url else None,
            branch="security/left-pad-CVE-1",
            base_branch="main",
        )
        db.add(proposal)
        db.flush()
        return proposal.id


def test_request_gate_idempotent_per_target():
    repo = _repo("idem-r")
    first = gates.request_gate(repo.id, GateAction.MERGE, "https://pr/1")
    again = gates.request_gate(repo.id, GateAction.MERGE, "https://pr/1")
    other = gates.request_gate(repo.id, GateAction.MERGE, "https://pr/2")
    assert first.id == again.id != other.id


def test_decide_rights_ladder():
    repo = _repo("ladder-r")
    owner = _user("owner", Role.OWNER)
    maintainer = _user("maint", Role.MAINTAINER)
    developer = _user("dev", Role.DEVELOPER)
    reporter = _user("rep", Role.REPORTER)
    g1 = gates.request_gate(repo.id, GateAction.MERGE, "t1")
    assert gates.decide_gate(g1.id, owner, True).status == GateStatus.APPROVED
    g2 = gates.request_gate(repo.id, GateAction.MERGE, "t2")
    assert gates.decide_gate(g2.id, maintainer, False).status == GateStatus.DENIED
    g3 = gates.request_gate(repo.id, GateAction.MERGE, "t3")
    with pytest.raises(PermissionError):
        gates.decide_gate(g3.id, developer, True)
    with pytest.raises(PermissionError):
        gates.decide_gate(g3.id, reporter, True)
    with pytest.raises(ValueError, match="already"):
        gates.decide_gate(g1.id, owner, True)


def test_delegation_grants_and_narrows():
    repo = _repo("deleg-r")
    owner = _user("downer", Role.OWNER)
    developer = _user("ddev", Role.DEVELOPER)
    gates.delegate_approval(owner.id, developer.id, classes=["rotation"])
    assert gates.may_decide(developer, GateAction.ROTATION) is True
    assert gates.may_decide(developer, GateAction.MERGE) is False
    narrow = gates.request_gate(repo.id, GateAction.ROTATION, "tok")
    assert gates.decide_gate(narrow.id, developer, True).status == GateStatus.APPROVED
    with pytest.raises(PermissionError, match="Only an Owner"):
        gates.delegate_approval(developer.id, developer.id)
    with pytest.raises(ValueError, match="Developers only"):
        gates.delegate_approval(owner.id, owner.id)
    with pytest.raises(ValueError, match="Unknown gate classes"):
        gates.delegate_approval(owner.id, developer.id, classes=["nope"])


def test_delegation_revoke_and_expiry():
    owner = _user("rowner", Role.OWNER)
    developer = _user("rdev", Role.DEVELOPER)
    delegation = gates.delegate_approval(owner.id, developer.id)
    assert gates.may_decide(developer, GateAction.MERGE) is True
    gates.revoke_delegation(delegation.id, owner.id)
    assert gates.may_decide(developer, GateAction.MERGE) is False
    with pytest.raises(PermissionError):
        gates.revoke_delegation(delegation.id, developer.id)
    expired = gates.delegate_approval(owner.id, developer.id, hours=-1)
    assert gates.may_decide(developer, GateAction.MERGE) is False
    assert expired.id != delegation.id


def test_sweep_expires_and_requeues_with_cap():
    repo = _repo("sweep-r")
    gate = gates.request_gate(repo.id, GateAction.MERGE, "stale")
    past = datetime.now(UTC) - timedelta(hours=73)
    with session_scope() as db:
        db.get(Approval, gate.id).expires_at = past
    assert gates.sweep_expired_gates() == {"expired": 1, "requeued": 1}
    with session_scope() as db:
        assert db.get(Approval, gate.id).status == GateStatus.EXPIRED
        fresh = db.scalar(
            select(Approval).where(
                Approval.target == "stale", Approval.status == GateStatus.PENDING
            )
        )
        assert fresh is not None and "re-queue" in (fresh.reason or "")
        fresh.expires_at = past
        fresh.requeues = 3
    assert gates.sweep_expired_gates() == {"expired": 1, "requeued": 0}
    with pytest.raises(ValueError, match="expired"):
        gates.decide_gate(fresh.id, _user("sowner", Role.OWNER), True)


def test_resolve_gates_for_proposal():
    repo = _repo("resolve-r")
    pid = _seed_proposal(repo.id)
    pending = gates.request_gate(repo.id, GateAction.MERGE, "https://pr/x", proposal_id=pid)
    assert gates.resolve_gates_for_proposal(pid, "provider") == 1
    assert gates.get_gate(pending.id).status == GateStatus.APPROVED
    assert gates.get_gate(pending.id).source == "provider"
    assert "outside dashboard" in (gates.get_gate(pending.id).reason or "")
    assert gates.resolve_gates_for_proposal(999999, "provider") == 0


def test_pending_gate_index_rejects_duplicates():
    from datetime import timedelta

    import sqlalchemy.exc

    repo = _repo("dupgate-r")
    with session_scope() as db:
        db.add(
            Approval(
                repo_id=repo.id,
                action=GateAction.MERGE,
                target="https://pr/dup",
                expires_at=datetime.now(UTC) + timedelta(hours=72),
            )
        )
        db.flush()
        db.add(
            Approval(
                repo_id=repo.id,
                action=GateAction.MERGE,
                target="https://pr/dup",
                expires_at=datetime.now(UTC) + timedelta(hours=72),
            )
        )
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            db.flush()
        db.rollback()


def test_execute_merge_happy_path():
    repo = _repo("exec-r", host="github.com")
    repo_svc.store_merge_token(repo.id, "merge-tok")
    pid = _seed_proposal(repo.id)
    owner = _user("xowner", Role.OWNER)
    gate = gates.request_gate(repo.id, GateAction.MERGE, "https://github.com/o/r/pull/7")
    with session_scope() as db:
        db.get(Approval, gate.id).proposal_id = pid
    gates.decide_gate(gate.id, owner, True)
    with (
        mock.patch.object(deliver_mod, "merge_pr") as fake_merge,
        mock.patch.object(
            deliver_mod, "sync_proposal_states", return_value={"synced": 1}
        ) as fake_sync,
    ):
        result = gates.execute_merge(gate.id, owner)
    fake_merge.assert_called_once_with("https://github.com/o/r/pull/7", "merge-tok")
    fake_sync.assert_called_once_with(repo.id)
    assert result["status"] == "merged"


def test_execute_merge_refusals():
    repo = _repo("refuse-r", host="github.com")
    owner = _user("fowner", Role.OWNER)
    pending = gates.request_gate(repo.id, GateAction.MERGE, "t-pending")
    with pytest.raises(PermissionError, match="not approved"):
        gates.execute_merge(pending.id, owner)
    pid = _seed_proposal(repo.id, pr_url=None)
    gate = gates.request_gate(repo.id, GateAction.MERGE, "branch-only", proposal_id=pid)
    gates.decide_gate(gate.id, owner, True)
    with pytest.raises(ValueError, match="Manual merge"):
        gates.execute_merge(gate.id, owner)
    pid2 = _seed_proposal(repo.id)
    gate2 = gates.request_gate(repo.id, GateAction.MERGE, "https://github.com/o/r/pull/7")
    with session_scope() as db:
        db.get(Approval, gate2.id).proposal_id = pid2
    gates.decide_gate(gate2.id, owner, True)
    with pytest.raises(ValueError, match="merge credential"):
        gates.execute_merge(gate2.id, owner)
    reporter = _user("frep", Role.REPORTER)
    with pytest.raises(PermissionError):
        gates.execute_merge(gate2.id, reporter)
    other = _repo("refuse-other", host="github.com")
    foreign_pid = _seed_proposal(other.id)
    gate3 = gates.request_gate(repo.id, GateAction.MERGE, "https://github.com/o/r/pull/99")
    with session_scope() as db:
        db.get(Approval, gate3.id).proposal_id = foreign_pid
    gates.decide_gate(gate3.id, owner, True)
    with pytest.raises(ValueError, match="repo mismatch"):
        gates.execute_merge(gate3.id, owner)


def test_merge_pr_api_shapes():
    gh = mock.Mock()
    gh.json.return_value = {"merged": True}
    with mock.patch.object(deliver_mod.httpx, "put", return_value=gh) as fake:
        deliver_mod.merge_pr("https://github.com/o/r/pull/7", "tok")
    url, kwargs = fake.call_args[0][0], fake.call_args[1]
    assert url.endswith("/repos/o/r/pulls/7/merge")
    assert kwargs["json"] == {"merge_method": "merge"}
    rej = mock.Mock()
    rej.json.return_value = {"merged": False, "message": "blocked"}
    with (
        mock.patch.object(deliver_mod.httpx, "put", return_value=rej),
        pytest.raises(DeliverError, match="blocked"),
    ):
        deliver_mod.merge_pr("https://github.com/o/r/pull/7", "tok")
    proj = mock.Mock()
    proj.json.return_value = {"id": 9}
    with (
        mock.patch.object(deliver_mod.httpx, "get", return_value=proj),
        mock.patch.object(deliver_mod.httpx, "put", return_value=mock.Mock()) as fake_put,
    ):
        deliver_mod.merge_pr("https://git.example/g/-/merge_requests/4", "tok")
    assert fake_put.call_args[0][0].endswith("/projects/9/merge_requests/4/merge")
    with pytest.raises(DeliverError, match="unrecognized"):
        deliver_mod.merge_pr("https://example.com/x", "tok")


def test_run_merge_executes_approved_skips_pending():
    repo = _repo("runmerge-r", host="github.com")
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    repo_svc.store_merge_token(repo.id, "tok")
    approved_pid = _seed_proposal(repo.id, "https://github.com/o/r/pull/11")
    pending_pid = _seed_proposal(repo.id, "https://github.com/o/r/pull/12")
    owner = _user("mowner", Role.OWNER)
    gate = gates.request_gate(repo.id, GateAction.MERGE, "https://github.com/o/r/pull/11")
    with session_scope() as db:
        db.get(Approval, gate.id).proposal_id = approved_pid
    gates.decide_gate(gate.id, owner, True)
    gates.request_gate(repo.id, GateAction.MERGE, "https://github.com/o/r/pull/12")
    with (
        mock.patch.object(deliver_mod, "merge_pr"),
        mock.patch.object(deliver_mod, "sync_proposal_states", return_value={"synced": 1}),
    ):
        result = gates.run_merge(repo.id, run_id, [approved_pid, pending_pid])
    assert result == {"status": "done", "merged": [approved_pid], "skipped": [pending_pid]}
    with session_scope() as db:
        assert "merge: 1 merged, 1 skipped" in (db.get(ScanRun, run_id).notes or "")
    with pytest.raises(ValueError, match="Unknown repo"):
        gates.run_merge(999999, run_id, [])


def test_graph_merge_node_and_withhold():
    from security_agent.worker import patch as patch_mod
    from security_agent.worker import reachability as reach_mod
    from security_agent.worker import scan as scan_mod

    with (
        mock.patch("security_agent.worker.news.poll_news", return_value={}),
        mock.patch(
            "security_agent.worker.news.run_matcher", return_value={"items": 0, "boosts": 0}
        ),
        mock.patch.object(scan_mod, "run_scan", return_value={"finding_ids": []}),
        mock.patch.object(reach_mod, "run_reachability", return_value={"verdict_ids": []}),
        mock.patch.object(patch_mod, "run_patch", return_value={"proposal_ids": [9]}),
        mock.patch.object(deliver_mod, "run_deliver", return_value={"proposal_ids": [9]}),
        mock.patch.object(
            gates, "run_merge", return_value={"status": "done", "merged": [9], "skipped": []}
        ) as fake,
    ):
        result = build_graph().invoke({"repo_id": 1, "run_id": 2, "proposals": [{"id": 9}]})
    fake.assert_called_once_with(1, 2, [9])
    assert result["merges"] == [{"id": 9}]
    assert "merge" in result["done"]


def test_tick_sweeps_expired_gates():
    from security_agent.worker.scheduler import tick

    repo = _repo("ticksweep-r")
    gate = gates.request_gate(repo.id, GateAction.MERGE, "tick-stale")
    with session_scope() as db:
        db.get(Approval, gate.id).expires_at = datetime.now(UTC) - timedelta(hours=73)
    with (
        mock.patch("security_agent.worker.news.poll_news", return_value={}),
        mock.patch(
            "security_agent.worker.news.run_matcher", return_value={"items": 0, "boosts": 0}
        ),
    ):
        tick()
    assert gates.get_gate(gate.id).status == GateStatus.EXPIRED


def test_gate_view_queries():
    repo = _repo("views-r")
    pending = gates.request_gate(repo.id, GateAction.MERGE, "view-pending")
    assert pending.id in [g.id for g in gates.list_pending_gates()]
    ctx = gates.gate_context(pending)
    assert ctx["repo_name"] == "views-r" and ctx["decider_email"] is None
    owner = _user("vowner", Role.OWNER)
    gates.decide_gate(pending.id, owner, True)
    assert pending.id in [
        g["gate"].id for g in [gates.gate_context(x) for x in gates.list_gate_history()]
    ]
    assert gates.get_gate(999999) is None
