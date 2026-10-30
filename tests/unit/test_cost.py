"""H6 Slice B: token ledger, caps, park/resume, spend alerts (NFR-8)."""

from datetime import UTC, datetime
from unittest import mock

import pytest
from sqlalchemy import delete, select

from security_agent.app import accounts as accounts_svc
from security_agent.control import repos as repo_svc
from security_agent.control.cost import (
    CostCapExceeded,
    check_spend_alerts,
    current_run_id,
    effective_cap,
    list_parked_runs,
    record_usage,
    resume_run,
    run_context,
    set_cap,
    spend_today,
)
from security_agent.db.models import ModelUsage, NotifyState, RepoKind, Role, RunTrigger, ScanRun
from security_agent.db.session import session_scope
from security_agent.worker.patch import PatchError
from security_agent.worker.scheduler import enqueue_scan


def _owner():
    email = f"cost-owner-{datetime.now(UTC).timestamp()}@example.com"
    return accounts_svc.create_user(email, None, Role.OWNER)


def _dev():
    email = f"cost-dev-{datetime.now(UTC).timestamp()}@example.com"
    return accounts_svc.create_user(email, None, Role.DEVELOPER)


def _reset_cost_state():
    with session_scope() as db:
        db.execute(
            delete(NotifyState).where(NotifyState.key.in_(["cost.run_cap", "cost.spend_alert"]))
        )


def _run():
    repo = repo_svc.connect_repo(
        f"cost-r-{datetime.now(UTC).timestamp()}", RepoKind.GIT, url="https://example.com/c.git"
    )
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        db.expunge(run)
        return run


def test_record_usage_ledgers_and_accumulates():
    run = _run()
    _reset_cost_state()
    with mock.patch("security_agent.notify.notify_event"):
        outcome = record_usage(run.id, "adapt", 100, 50)
    assert outcome["total"] == 150 and outcome["run_usage"] >= 150
    with session_scope() as db:
        row = db.scalar(select(ModelUsage).where(ModelUsage.run_id == run.id))
        assert row is not None and row.total_tokens == 150 and row.estimated is False


def test_warn_once_then_park_at_cap():
    owner = _owner()
    run = _run()
    _reset_cost_state()
    set_cap(1000, owner)
    try:
        with mock.patch("security_agent.notify.notify_event") as fake:
            record_usage(run.id, "adapt", 700, 100)  # 800/1000: warn
            assert fake.call_count == 1 and fake.call_args[0][0] == "medium"
            record_usage(run.id, "adapt", 50, 50)  # still under cap: no second warn
            assert fake.call_count == 1
            with pytest.raises(CostCapExceeded):
                record_usage(run.id, "adapt", 500, 500)  # over cap: park
            assert fake.call_count == 2 and fake.call_args[0][0] == "high"
        with session_scope() as db:
            parked = db.get(ScanRun, run.id)
            assert parked.parked is True and "cap" in (parked.park_reason or "")
            assert "parked" in (parked.notes or "")
        assert run.id in [r["id"] for r in list_parked_runs()]
    finally:
        _reset_cost_state()


def test_cap_abort_escapes_the_repair_loop():
    """CostCapExceeded must not be Retryable: patch swallows PatchError/RuntimeError."""
    assert not issubclass(CostCapExceeded, PatchError)
    assert not issubclass(CostCapExceeded, RuntimeError)


def test_resume_needs_raised_cap_and_approver():
    owner, dev = _owner(), _dev()
    run = _run()
    _reset_cost_state()
    set_cap(1000, owner)
    try:
        with mock.patch("security_agent.notify.notify_event"):
            with pytest.raises(CostCapExceeded):
                record_usage(run.id, "adapt", 600, 500)
        with pytest.raises(PermissionError):
            resume_run(run.id, dev, new_cap=2000)
        with pytest.raises(ValueError, match="raise the cap"):
            resume_run(run.id, owner)
        with pytest.raises(ValueError, match="must exceed usage"):
            resume_run(run.id, owner, new_cap=500)
        outcome = resume_run(run.id, owner, new_cap=5000)
        assert outcome == {"run_id": run.id, "cap": 5000}
        assert effective_cap() == 5000
        with session_scope() as db:
            resumed = db.get(ScanRun, run.id)
            assert resumed.parked is False and resumed.cost_warned is False
            assert resumed.claimed_by is None
        with pytest.raises(ValueError, match="not parked"):
            resume_run(run.id, owner)
    finally:
        _reset_cost_state()


def test_set_cap_roles_and_floor():
    owner, dev = _owner(), _dev()
    _reset_cost_state()
    try:
        with pytest.raises(PermissionError):
            set_cap(10, dev)
        with pytest.raises(ValueError, match="at least 1"):
            set_cap(0, owner)
        assert set_cap(42, owner) == 42
        assert effective_cap() == 42
    finally:
        _reset_cost_state()


def test_spend_alerts_once_per_level_per_day_with_escalation():
    _reset_cost_state()
    with session_scope() as db:
        db.add(ModelUsage(run_id=None, task="adapt", total_tokens=1, cost_usd=30.0))
    try:
        with mock.patch("security_agent.notify.notify_event") as fake:
            assert spend_today() >= 30.0
            first = check_spend_alerts()
            assert first["level"] == "warn" and first["alerted"] is True
            assert check_spend_alerts()["alerted"] is False  # same day: silent
            assert fake.call_count == 1
        with session_scope() as db:
            db.add(ModelUsage(run_id=None, task="adapt", total_tokens=1, cost_usd=80.0))
        with mock.patch("security_agent.notify.notify_event") as fake:
            escalated = check_spend_alerts()
            assert escalated["level"] == "critical" and escalated["alerted"] is True
            assert fake.call_args[0][0] == "high"
    finally:
        with session_scope() as db:
            db.execute(delete(ModelUsage).where(ModelUsage.run_id.is_(None)))


def test_tracked_invoke_prefers_usage_metadata_then_estimates():
    from security_agent.brain import tracked_invoke

    _reset_cost_state()

    class Meta:
        usage_metadata = {"input_tokens": 10, "output_tokens": 5}
        content = "x"
        tool_calls = []

    class NoMeta:
        content = "y" * 400
        tool_calls = []

    class FakeModel:
        def __init__(self, result):
            self._result = result

        def invoke(self, prompt):
            return self._result

    with mock.patch("security_agent.notify.notify_event"):
        tracked_invoke(FakeModel(Meta()), "prompt", task="adapt")
        with session_scope() as db:
            row = db.scalar(
                select(ModelUsage)
                .where(ModelUsage.task == "adapt", ModelUsage.run_id.is_(None))
                .order_by(ModelUsage.id.desc())
            )
            assert row.total_tokens == 15 and row.estimated is False
            db.execute(
                delete(ModelUsage).where(ModelUsage.task == "adapt", ModelUsage.run_id.is_(None))
            )
        with run_context(123456):
            assert current_run_id() == 123456
            tracked_invoke(FakeModel(NoMeta()), "p" * 400, task="adapt")
        assert current_run_id() is None
        with session_scope() as db:
            row = db.scalar(select(ModelUsage).where(ModelUsage.run_id == 123456))
            assert row is not None and row.estimated is True
            db.execute(delete(ModelUsage).where(ModelUsage.run_id == 123456))


def test_adapt_propagates_cap_abort_not_patch_error(tmp_path):
    from security_agent.brain.adapt import make_model_adapt

    run = _run()
    _reset_cost_state()
    set_cap(10, _owner())
    try:

        class Hungry:
            def bind_tools(self, tools):
                return self

            def invoke(self, prompt):
                result = mock.Mock()
                result.usage_metadata = {"input_tokens": 1000, "output_tokens": 0}
                result.tool_calls = []
                return result

        adapt = make_model_adapt(Hungry(), probe_ok=True)
        finding = mock.Mock(package="pkg", installed_version="1.0.0")
        with mock.patch("security_agent.notify.notify_event"):
            with run_context(run.id), pytest.raises(CostCapExceeded):
                adapt(tmp_path, finding, "2.0.0", [])
    finally:
        _reset_cost_state()


def test_worker_never_fails_parked_runs():
    from security_agent.worker.main import _fail_run

    run = _run()
    with session_scope() as db:
        db.get(ScanRun, run.id).parked = True
    _fail_run(run.id, "pipeline crashed: boom")
    with session_scope() as db:
        row = db.get(ScanRun, run.id)
        assert row.status.value == "running"  # still resumable, not failed
    with session_scope() as db:
        db.get(ScanRun, run.id).parked = False


def test_enqueue_connect_still_works_with_new_columns():
    repo = repo_svc.connect_repo("cost-cols", RepoKind.GIT, url="https://example.com/cc.git")
    run = enqueue_scan(repo.id, RunTrigger.MANUAL)
    assert run.token_usage == 0 and run.parked is False
