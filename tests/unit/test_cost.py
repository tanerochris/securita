"""H6 Slice B: token ledger, USD caps, park/resume, spend alerts (NFR-8)."""

from datetime import UTC, datetime, timedelta
from unittest import mock

import pytest
from sqlalchemy import delete, select

from security_agent.app import accounts as accounts_svc
from security_agent.control import repos as repo_svc
from security_agent.control.cost import (
    CostCapExceeded,
    check_monthly_cap_alerts,
    check_spend_alerts,
    current_run_id,
    effective_run_cap,
    effective_spend_cap,
    format_usd,
    list_parked_runs,
    record_usage,
    resume_run,
    run_context,
    set_run_cap,
    set_spend_cap,
    spend_cap_state,
    spend_today,
    usage_summary,
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
            delete(NotifyState).where(
                NotifyState.key.in_(
                    [
                        "cost.run_cap",  # legacy token override, still honored
                        "cost.run_cap_usd",
                        "cost.spend_alert",
                        "cost.spend_cap_monthly",
                        "cost.spend_cap_alert",
                    ]
                )
            )
        )


def _run():
    repo = repo_svc.connect_repo(
        f"cost-r-{datetime.now(UTC).timestamp()}", RepoKind.GIT, url="https://example.com/c.git"
    )
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        db.expunge(run)
        return run


def _usd(tokens: int) -> float:
    """Cap dollars for a token count at the configured model price."""
    from security_agent.config import get_settings

    return tokens * max(0.0, get_settings().model_price_per_mtok_usd) / 1_000_000


def test_disconnect_repo_removes_cost_ledger_rows():
    """Regression: disconnect must delete model_usage before scan_runs.

    SQLite never enforced the FK, so the suite stayed green while
    Postgres raised ForeignKeyViolation on every disconnect of a repo
    that had recorded model usage.
    """
    from security_agent.control import repos as repo_ctl

    run = _run()
    with session_scope() as db:
        db.add(ModelUsage(run_id=run.id, task="adapt", total_tokens=10, cost_usd=0.01))
    repo_ctl.disconnect_repo(run.repo_id)
    with session_scope() as db:
        assert db.get(ScanRun, run.id) is None
        assert db.scalar(select(ModelUsage).where(ModelUsage.run_id == run.id)) is None


def test_record_usage_ledgers_and_accumulates():
    run = _run()
    _reset_cost_state()
    with mock.patch("security_agent.notify.notify_event"):
        outcome = record_usage(run.id, "adapt", 100, 50)
    assert outcome["total"] == 150 and outcome["run_usage"] >= 150
    assert outcome["run_spend"] == pytest.approx(_usd(150))
    with session_scope() as db:
        row = db.scalar(select(ModelUsage).where(ModelUsage.run_id == run.id))
        assert row is not None and row.total_tokens == 150 and row.estimated is False


def test_warn_once_then_park_at_cap():
    owner = _owner()
    run = _run()
    _reset_cost_state()
    set_run_cap(_usd(1000), owner)
    try:
        with mock.patch("security_agent.notify.notify_event") as fake:
            record_usage(run.id, "adapt", 750, 100)  # 850 of 1000 equiv: warn
            assert fake.call_count == 1 and fake.call_args[0][0] == "medium"
            record_usage(run.id, "adapt", 25, 25)  # still under cap: no second warn
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
    set_run_cap(_usd(1000), owner)
    try:
        with mock.patch("security_agent.notify.notify_event"):
            with pytest.raises(CostCapExceeded):
                record_usage(run.id, "adapt", 600, 500)
        with pytest.raises(PermissionError):
            resume_run(run.id, dev, new_cap=_usd(2000))
        with pytest.raises(ValueError, match="raise the cap"):
            resume_run(run.id, owner)
        with pytest.raises(ValueError, match="must exceed spend"):
            resume_run(run.id, owner, new_cap=_usd(500))
        outcome = resume_run(run.id, owner, new_cap=_usd(5000))
        assert outcome == {"run_id": run.id, "cap": _usd(5000)}
        assert effective_run_cap() == _usd(5000)
        with session_scope() as db:
            resumed = db.get(ScanRun, run.id)
            assert resumed.parked is False and resumed.cost_warned is False
            assert resumed.claimed_by is None
        with pytest.raises(ValueError, match="not parked"):
            resume_run(run.id, owner)
    finally:
        _reset_cost_state()


def test_set_run_cap_roles_and_floor():
    owner, dev = _owner(), _dev()
    _reset_cost_state()
    try:
        with pytest.raises(PermissionError):
            set_run_cap(10.0, dev)
        with pytest.raises(ValueError, match="at least 0"):
            set_run_cap(-1.0, owner)
        assert set_run_cap(2.5, owner) == 2.5
        assert effective_run_cap() == 2.5
        assert set_run_cap(0, owner) == 0  # 0 disables the cap
        assert effective_run_cap() == 0.0
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
    set_run_cap(_usd(10), _owner())
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
    assert run.token_usage == 0 and run.cost_usd == 0 and run.parked is False


def _add_usage(task, prompt, completion, cost, *, created_at=None):
    with session_scope() as db:
        db.add(
            ModelUsage(
                run_id=None,
                task=task,
                prompt_tokens=prompt,
                completion_tokens=completion,
                total_tokens=prompt + completion,
                cost_usd=cost,
                created_at=created_at or datetime.now(UTC),
            )
        )


def test_usage_summary_windows_split_input_output_and_spend():
    """Day/week/month windows slice the whole ledger with in/out splits.

    Deltas (not absolutes): other tests leave ledger rows behind, so
    the test snapshots before inserting and diffs after.
    """
    tag = f"usage-{datetime.now(UTC).timestamp()}"
    before = usage_summary()
    assert set(before) == {"day", "week", "month"}
    now = datetime.now(UTC).replace(tzinfo=None)  # sqlite stores naive UTC
    two_days_ago = now - timedelta(days=2)
    try:
        _add_usage(f"{tag}-a", 100, 50, 1.50, created_at=now)
        _add_usage(f"{tag}-b", 10, 5, 0.15, created_at=two_days_ago)
        _add_usage(f"{tag}-c", 1000, 1000, 20.0, created_at=now - timedelta(days=40))
        after = usage_summary()
        delta = {
            name: {
                field: after[name][field] - before[name][field]
                for field in ("prompt_tokens", "completion_tokens", "total_tokens")
            }
            for name in ("day", "week", "month")
        }
        assert delta["day"] == {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150,
        }
        assert after["day"]["spend_usd"] - before["day"]["spend_usd"] == pytest.approx(1.50)
        # Rolling 7 days always holds today + two days ago, never 40 days ago.
        assert delta["week"] == {
            "prompt_tokens": 110,
            "completion_tokens": 55,
            "total_tokens": 165,
        }
        # Calendar month holds today; two-days-ago only when same month.
        same_month = (two_days_ago.year, two_days_ago.month) == (now.year, now.month)
        expected_month = {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
        if same_month:
            expected_month = {
                "prompt_tokens": 110,
                "completion_tokens": 55,
                "total_tokens": 165,
            }
        assert delta["month"] == expected_month
    finally:
        with session_scope() as db:
            db.execute(delete(ModelUsage).where(ModelUsage.task.like(f"{tag}%")))


def test_spend_cap_default_override_roles_and_floor():
    from security_agent.config import get_settings

    owner, dev = _owner(), _dev()
    _reset_cost_state()
    try:
        assert effective_spend_cap() == max(0.0, get_settings().spend_cap_monthly_usd)
        with pytest.raises(PermissionError):
            set_spend_cap(10.0, dev)
        with pytest.raises(ValueError, match="at least 0"):
            set_spend_cap(-1.0, owner)
        assert set_spend_cap(250.0, owner) == 250.0
        assert effective_spend_cap() == 250.0
        assert set_spend_cap(0, owner) == 0  # 0 disables the cap
        assert effective_spend_cap() == 0.0
    finally:
        _reset_cost_state()


def test_monthly_cap_alerts_once_per_level_per_month_with_escalation():
    """Warn at 80%, exceeded at 100%, once per level per calendar month."""
    from security_agent.control.cost import month_spend

    owner = _owner()
    tag = f"cap-{datetime.now(UTC).timestamp()}"
    _reset_cost_state()
    base = month_spend()
    set_spend_cap(base + 10.0, owner)
    _add_usage(tag, 1, 0, 8.5)
    try:
        with mock.patch("security_agent.notify.notify_event") as fake:
            first = check_monthly_cap_alerts()
            assert first["level"] == "warn" and first["alerted"] is True
            assert first["cap"] == base + 10.0 and first["spent"] >= base + 8.5
            assert check_monthly_cap_alerts()["alerted"] is False  # same month: silent
            assert fake.call_count == 1
        _add_usage(tag, 1, 0, 5.0)
        with mock.patch("security_agent.notify.notify_event") as fake:
            escalated = check_monthly_cap_alerts()
            assert escalated["level"] == "exceeded" and escalated["alerted"] is True
            assert fake.call_args[0][0] == "high"
    finally:
        with session_scope() as db:
            db.execute(delete(ModelUsage).where(ModelUsage.task == tag))
        _reset_cost_state()


def test_zero_spend_cap_disables_monthly_alerts():
    owner = _owner()
    tag = f"nocap-{datetime.now(UTC).timestamp()}"
    _reset_cost_state()
    set_spend_cap(0, owner)
    _add_usage(tag, 1, 0, 100.0)
    try:
        with mock.patch("security_agent.notify.notify_event") as fake:
            outcome = check_monthly_cap_alerts()
            assert outcome["level"] == "" and "alerted" not in outcome
            assert fake.call_count == 0
        state = spend_cap_state()
        assert state["cap"] == 0.0 and state["level"] == "" and state["pct"] == 0
        assert state["spent"] >= 100.0
    finally:
        with session_scope() as db:
            db.execute(delete(ModelUsage).where(ModelUsage.task == tag))
        _reset_cost_state()


def test_spend_cap_state_reports_level_without_alerting():
    """Dashboard state is side-effect-free: levels computed, nothing sent."""
    from security_agent.control.cost import month_spend

    tag = f"state-{datetime.now(UTC).timestamp()}"
    _reset_cost_state()
    base = month_spend()
    set_spend_cap(base + 100.0, _owner())
    try:
        with mock.patch("security_agent.notify.notify_event") as fake:
            assert spend_cap_state()["level"] == ""
            assert fake.call_count == 0
        _add_usage(tag, 1, 0, 85.0)  # 85% of the headroom: warn, not exceeded
        with mock.patch("security_agent.notify.notify_event") as fake:
            warned = spend_cap_state()
            assert warned["level"] == "warn" and warned["pct"] >= 80
            assert fake.call_count == 0
        _add_usage(tag, 1, 0, 20.0)  # past the cap: exceeded
        exceeded = spend_cap_state()
        assert exceeded["level"] == "exceeded" and exceeded["pct"] >= 100
    finally:
        with session_scope() as db:
            db.execute(delete(ModelUsage).where(ModelUsage.task == tag))
        _reset_cost_state()


def test_record_usage_checks_monthly_cap():
    run = _run()
    _reset_cost_state()
    try:
        with (
            mock.patch("security_agent.notify.notify_event"),
            mock.patch("security_agent.control.cost.check_monthly_cap_alerts") as monthly,
        ):
            record_usage(run.id, "adapt", 10, 5)
        assert monthly.call_count == 1
    finally:
        _reset_cost_state()


def test_deps_usage_counts_toward_monthly_cap():
    """Overall means overall: deps ledger rows add to the monthly total."""
    from security_agent.config import get_settings
    from security_agent.control.cost import month_spend
    from security_agent.control.deps import record_deps_usage

    base = month_spend()
    price = max(0.0, get_settings().model_price_per_mtok_usd) / 1_000_000
    task = f"cap-{datetime.now(UTC).timestamp()}"
    with mock.patch("security_agent.notify.notify_event"):
        record_deps_usage(task, 100, 50)
    try:
        assert month_spend() - base == pytest.approx(150 * price)
    finally:
        with session_scope() as db:
            db.execute(delete(ModelUsage).where(ModelUsage.task == f"deps-{task}"))


def test_format_usd_widens_only_past_zero():
    assert format_usd(2.0) == "$2.00"
    assert format_usd(0) == "$0.00"
    assert format_usd(0.40) == "$0.40"
    assert format_usd(1234.5) == "$1234.50"
    assert format_usd(0.0049) == "$0.0049"
    assert format_usd(0.0003) == "$0.0003"
    assert format_usd(0.0000001) == "$0.000000"


def test_zero_run_cap_disables_park():
    run = _run()
    _reset_cost_state()
    set_run_cap(0, _owner())
    try:
        with mock.patch("security_agent.notify.notify_event") as fake:
            record_usage(run.id, "adapt", 10_000_000, 0)  # uncapped: never parks
            assert fake.call_count == 0
        with session_scope() as db:
            row = db.get(ScanRun, run.id)
            assert row.parked is False and row.cost_warned is False
            assert row.cost_usd == pytest.approx(_usd(10_000_000))
    finally:
        _reset_cost_state()


def test_legacy_token_cap_override_still_enforced_as_usd():
    """Pre-USD installs keep working: cost.run_cap tokens convert at price."""
    run = _run()
    _reset_cost_state()
    with session_scope() as db:
        db.add(NotifyState(key="cost.run_cap", value="1000"))
    try:
        assert effective_run_cap() == pytest.approx(_usd(1000))
        with mock.patch("security_agent.notify.notify_event"):
            record_usage(run.id, "adapt", 500, 100)  # under: ledgers fine
            with pytest.raises(CostCapExceeded):
                record_usage(run.id, "adapt", 500, 500)  # over: parks
        # Setting a USD cap retires the legacy token override.
        set_run_cap(9.99, _owner())
        with session_scope() as db:
            assert db.get(NotifyState, "cost.run_cap") is None
            assert db.get(NotifyState, "cost.run_cap_usd") is not None
        assert effective_run_cap() == 9.99
    finally:
        _reset_cost_state()


def test_run_cap_env_usd_wins_legacy_tokens_convert(monkeypatch, tmp_path):
    from security_agent.config import Settings

    monkeypatch.chdir(tmp_path)  # ignore the workspace .env; real env only
    monkeypatch.delenv("RUN_SPEND_CAP_USD", raising=False)
    monkeypatch.delenv("RUN_TOKEN_CAP", raising=False)
    fresh = Settings()
    price = max(0.0, fresh.model_price_per_mtok_usd) / 1_000_000
    assert fresh.run_cap_default_usd == pytest.approx(1_000_000 * price)
    monkeypatch.setenv("RUN_TOKEN_CAP", "500000")
    assert Settings().run_cap_default_usd == pytest.approx(500000 * price)
    monkeypatch.setenv("RUN_SPEND_CAP_USD", "5")
    assert Settings().run_cap_default_usd == 5.0


def test_warn_fraction_env_old_and_new_names(monkeypatch, tmp_path):
    from security_agent.config import Settings

    monkeypatch.chdir(tmp_path)  # ignore the workspace .env; real env only
    monkeypatch.delenv("RUN_SPEND_WARN_FRACTION", raising=False)
    monkeypatch.setenv("RUN_TOKEN_WARN_FRACTION", "0.6")
    assert Settings().run_spend_warn_fraction == 0.6
    monkeypatch.setenv("RUN_SPEND_WARN_FRACTION", "0.5")
    assert Settings().run_spend_warn_fraction == 0.5


def test_parked_runs_carry_spend_usd():
    run = _run()
    _reset_cost_state()
    set_run_cap(_usd(100), _owner())
    try:
        with mock.patch("security_agent.notify.notify_event"):
            with pytest.raises(CostCapExceeded):
                record_usage(run.id, "adapt", 60, 60)
        parked = [r for r in list_parked_runs() if r["id"] == run.id]
        assert len(parked) == 1
        assert parked[0]["spend_usd"] == pytest.approx(_usd(120))
        assert "spend cap hit" in parked[0]["reason"]
    finally:
        _reset_cost_state()
