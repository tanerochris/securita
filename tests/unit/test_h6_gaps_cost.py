"""H6 gaps (cluster C): atomic cost accounting, spend stamps, retention, probe ledger."""

import threading
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest import mock

import pytest
from sqlalchemy import delete, func, select

from security_agent.app import accounts as accounts_svc
from security_agent.config import get_settings
from security_agent.control import repos as repo_svc
from security_agent.control.cost import (
    CostCapExceeded,
    check_spend_alerts,
    purge_old_usage,
    record_usage,
    set_run_cap,
)
from security_agent.db.models import ModelUsage, NotifyState, RepoKind, Role, ScanRun
from security_agent.db.session import session_scope


def _owner():
    email = f"h6gap-owner-{datetime.now(UTC).timestamp()}@example.com"
    return accounts_svc.create_user(email, None, Role.OWNER)


def _run():
    repo = repo_svc.connect_repo(
        f"h6gap-r-{datetime.now(UTC).timestamp()}", RepoKind.GIT, url="https://example.com/g.git"
    )
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        db.expunge(run)
        return run


def _reset_cost_state():
    with session_scope() as db:
        db.execute(
            delete(NotifyState).where(
                NotifyState.key.in_(["cost.run_cap", "cost.run_cap_usd", "cost.spend_alert"])
            )
        )


def _usd(tokens: int) -> float:
    """Cap dollars for a token count at the configured model price."""
    price = max(0.0, get_settings().model_price_per_mtok_usd) / 1_000_000
    return tokens * price


def _kinds(fake):
    return [c.kwargs.get("kind") for c in fake.call_args_list]


def test_concurrent_record_usage_sums_exactly_with_single_warn_and_park():
    owner, run = _owner(), _run()
    _reset_cost_state()
    set_run_cap(_usd(999), owner)  # warn at ~799, park at 999 token-equivalents
    threads_n, calls_each, per_call = 8, 5, 25
    expected = threads_n * calls_each * per_call
    assert expected == 1000
    start = threading.Barrier(threads_n)
    parked_hits = []
    try:
        with mock.patch("security_agent.notify.notify_event") as fake:

            def hammer():
                start.wait(timeout=30)
                for _ in range(calls_each):
                    try:
                        record_usage(run.id, "adapt", 20, 5)
                    except CostCapExceeded:
                        parked_hits.append(1)

            workers = [threading.Thread(target=hammer) for _ in range(threads_n)]
            [w.start() for w in workers]
            [w.join(timeout=120) for w in workers]
            assert not [w for w in workers if w.is_alive()]
            kinds = _kinds(fake)
            assert kinds.count("cost-warn") == 1
            assert kinds.count("cost-parked") == 1
        assert parked_hits, "the parking call must raise CostCapExceeded"
        with session_scope() as db:
            row = db.get(ScanRun, run.id)
            assert row.token_usage == expected
            assert row.cost_usd == pytest.approx(_usd(expected))
            assert row.parked is True
            assert (
                db.scalar(
                    select(func.count()).select_from(ModelUsage).where(ModelUsage.run_id == run.id)
                )
                == threads_n * calls_each
            )
    finally:
        _reset_cost_state()


def test_record_usage_on_parked_run_raises_without_second_alert():
    owner, run = _owner(), _run()
    _reset_cost_state()
    set_run_cap(_usd(100), owner)
    try:
        with mock.patch("security_agent.notify.notify_event") as fake:
            try:
                record_usage(run.id, "adapt", 60, 60)
                raise AssertionError("expected the parking call to raise")
            except CostCapExceeded:
                pass
            assert _kinds(fake).count("cost-parked") == 1
            try:
                record_usage(run.id, "adapt", 1, 1)
                raise AssertionError("expected an over-cap call on a parked run to raise")
            except CostCapExceeded:
                pass
            assert _kinds(fake).count("cost-parked") == 1  # no second park alert
            assert "cost-warn" not in _kinds(fake)
    finally:
        _reset_cost_state()


def test_spend_stamp_single_winner_under_race():
    settings = get_settings()
    future = datetime.now(UTC) + timedelta(days=30)
    stamp_prefix = future.date().isoformat()
    _reset_cost_state()
    with session_scope() as db:
        db.add(
            ModelUsage(
                run_id=None,
                task="spend-race",
                total_tokens=1,
                cost_usd=settings.spend_critical_daily_usd + 10.0,
                created_at=future.replace(hour=1, minute=0, second=0, microsecond=0),
            )
        )
    try:
        start = threading.Barrier(8)
        outcomes = []
        with mock.patch("security_agent.notify.notify_event") as fake:

            def claim():
                start.wait(timeout=30)
                outcomes.append(check_spend_alerts(now=future))

            workers = [threading.Thread(target=claim) for _ in range(8)]
            [w.start() for w in workers]
            [w.join(timeout=120) for w in workers]
            assert [o["level"] for o in outcomes] == ["critical"] * 8
            assert sum(1 for o in outcomes if o.get("alerted")) == 1
            assert fake.call_count == 1
        with session_scope() as db:
            row = db.get(NotifyState, "cost.spend_alert")
            assert row.value == f"{stamp_prefix}:critical"
    finally:
        with session_scope() as db:
            db.execute(delete(ModelUsage).where(ModelUsage.task == "spend-race"))
        _reset_cost_state()


def test_spend_escalates_warn_to_critical():
    settings = get_settings()
    future = datetime.now(UTC) + timedelta(days=31)
    stamp_prefix = future.date().isoformat()
    _reset_cost_state()
    with session_scope() as db:
        db.add(
            ModelUsage(
                run_id=None,
                task="spend-escalate",
                total_tokens=1,
                cost_usd=settings.spend_warn_daily_usd + 5.0,
                created_at=future.replace(hour=1, minute=0, second=0, microsecond=0),
            )
        )
    try:
        with mock.patch("security_agent.notify.notify_event"):
            first = check_spend_alerts(now=future)
            assert first["level"] == "warn" and first["alerted"] is True
            assert check_spend_alerts(now=future)["alerted"] is False
        with session_scope() as db:
            db.add(
                ModelUsage(
                    run_id=None,
                    task="spend-escalate",
                    total_tokens=1,
                    cost_usd=settings.spend_critical_daily_usd + 5.0,
                    created_at=future.replace(hour=2, minute=0, second=0, microsecond=0),
                )
            )
        start = threading.Barrier(4)
        outcomes = []
        with mock.patch("security_agent.notify.notify_event") as fake:

            def escalate():
                start.wait(timeout=30)
                outcomes.append(check_spend_alerts(now=future))

            workers = [threading.Thread(target=escalate) for _ in range(4)]
            [w.start() for w in workers]
            [w.join(timeout=120) for w in workers]
            assert [o["level"] for o in outcomes] == ["critical"] * 4
            assert sum(1 for o in outcomes if o.get("alerted")) == 1
            assert fake.call_count == 1
        with session_scope() as db:
            row = db.get(NotifyState, "cost.spend_alert")
            assert row.value == f"{stamp_prefix}:critical"
    finally:
        with session_scope() as db:
            db.execute(delete(ModelUsage).where(ModelUsage.task == "spend-escalate"))
        _reset_cost_state()


def test_purge_old_usage_keeps_recent_deletes_old():
    with session_scope() as db:
        db.add(
            ModelUsage(
                run_id=None,
                task="purge-old",
                total_tokens=1,
                created_at=datetime.now(UTC).replace(tzinfo=None) - timedelta(days=100),
            )
        )
        db.add(ModelUsage(run_id=None, task="purge-recent", total_tokens=2))
    try:
        assert purge_old_usage(older_than_days=90) == 1
        with session_scope() as db:
            assert db.scalar(select(ModelUsage).where(ModelUsage.task == "purge-old")) is None
            kept = db.scalar(select(ModelUsage).where(ModelUsage.task == "purge-recent"))
            assert kept is not None and kept.total_tokens == 2
            assert purge_old_usage() == 0
    finally:
        with session_scope() as db:
            db.execute(delete(ModelUsage).where(ModelUsage.task.in_(["purge-old", "purge-recent"])))


def test_probe_tokens_are_ledgered_run_less():
    from security_agent.brain.probe import run_probe

    class FakeModel:
        def invoke(self, prompt):
            return SimpleNamespace(
                tool_calls=[{"name": "probe_echo", "args": {"text": "probe-ok"}}],
                content="done",
                usage_metadata={"input_tokens": 12, "output_tokens": 7},
            )

    with (
        mock.patch(
            "security_agent.brain.get_chat_model",
            return_value=SimpleNamespace(bind_tools=lambda tools: FakeModel()),
        ),
        mock.patch("security_agent.notify.notify_event"),
    ):
        assert run_probe() is True
    try:
        with session_scope() as db:
            row = db.scalar(
                select(ModelUsage)
                .where(ModelUsage.task == "probe", ModelUsage.run_id.is_(None))
                .order_by(ModelUsage.id.desc())
            )
            assert row is not None and row.total_tokens == 19 and row.estimated is False
    finally:
        with session_scope() as db:
            db.execute(
                delete(ModelUsage).where(ModelUsage.task == "probe", ModelUsage.run_id.is_(None))
            )


def test_tracked_invoke_estimates_each_side_independently():
    from security_agent.brain import tracked_invoke

    class FakeModel:
        def __init__(self, result):
            self._result = result

        def invoke(self, prompt):
            return self._result

    cases = [
        # (usage_metadata, prompt_len_chars, content_len_chars, exp_in, exp_out)
        ({"input_tokens": 10}, 400, 400, 10, 100),  # output estimated only
        ({"output_tokens": 8}, 400, 400, 100, 8),  # input estimated only
        ({}, 400, 400, 100, 100),  # both estimated
        ({"input_tokens": 10, "output_tokens": 8}, 400, 400, 10, 8),  # none estimated
    ]
    with mock.patch("security_agent.notify.notify_event"):
        for i, (meta, plen, clen, _exp_in, _exp_out) in enumerate(cases):
            result = SimpleNamespace(content="y" * clen, tool_calls=[], usage_metadata=dict(meta))
            tracked_invoke(FakeModel(result), "p" * plen, task=f"est-side-{i}")
    try:
        with session_scope() as db:
            for i, (meta, _plen, _clen, exp_in, exp_out) in enumerate(cases):
                row = db.scalar(select(ModelUsage).where(ModelUsage.task == f"est-side-{i}"))
                assert row is not None
                assert (row.prompt_tokens, row.completion_tokens) == (exp_in, exp_out)
                assert row.estimated is (len(meta) < 2)
    finally:
        with session_scope() as db:
            db.execute(delete(ModelUsage).where(ModelUsage.task.like("est-side-%")))
