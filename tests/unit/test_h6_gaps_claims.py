"""H6 gaps: claim fencing, heartbeat renewal, lease-aware reap (K1/K2/G5)."""

import time
import uuid
from datetime import UTC, datetime, timedelta
from unittest import mock

from sqlalchemy import select

from security_agent.control import repos as repo_svc
from security_agent.db.models import RepoKind, RunStatus, ScanRun
from security_agent.db.session import session_scope
from security_agent.worker.scheduler import (
    CLAIM_LEASE_MINUTES,
    claim_pending_runs,
    reap_stale_runs,
    touch_claim,
)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _repo(tag: str):
    return repo_svc.connect_repo(
        f"h6c-{tag}-{uuid.uuid4().hex[:8]}",
        RepoKind.GIT,
        url=f"https://example.com/h6c-{tag}.git",
    )


def _run_id(repo_id: int) -> int:
    with session_scope() as db:
        return db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo_id))


def _row(run_id: int) -> ScanRun:
    with session_scope() as db:
        row = db.get(ScanRun, run_id)
        assert row is not None
        db.expunge(row)
        return row


def _settle(run_id: int, status: RunStatus = RunStatus.DONE) -> None:
    with session_scope() as db:
        row = db.get(ScanRun, run_id)
        row.status = status
        row.finished_at = datetime.now(UTC)


def _backdate(run_id: int, *, started_hours_ago=None, claimed_minutes_ago=None) -> None:
    with session_scope() as db:
        row = db.get(ScanRun, run_id)
        if started_hours_ago is not None:
            row.started_at = datetime.now(UTC) - timedelta(hours=started_hours_ago)
        if claimed_minutes_ago is not None:
            row.claimed_at = datetime.now(UTC) - timedelta(minutes=claimed_minutes_ago)


def test_touch_claim_renews_owned_lease_only():
    repo = _repo("touch")
    rid = _run_id(repo.id)
    try:
        assert rid in [r.id for r in claim_pending_runs("w-hb-owner", limit=10000)]
        _backdate(rid, claimed_minutes_ago=5)
        old = _row(rid).claimed_at
        assert touch_claim(rid, "w-hb-owner") is True
        assert _aware(_row(rid).claimed_at) > _aware(old)  # heartbeat advanced it
        assert touch_claim(rid, "w-hb-stranger") is False  # not the owner
        assert _row(rid).claimed_by == "w-hb-owner"
    finally:
        _settle(rid)


def test_finish_and_fail_fenced_to_claim_owner():
    from security_agent.worker.main import _ensure_finished, _fail_run

    repo = _repo("fence")
    rid = _run_id(repo.id)
    try:
        assert rid in [r.id for r in claim_pending_runs("w-fence-loser", limit=10000)]
        _backdate(rid, claimed_minutes_ago=CLAIM_LEASE_MINUTES + 1)
        assert rid in [r.id for r in claim_pending_runs("w-fence-winner", limit=10000)]  # stolen
        _ensure_finished(rid, "w-fence-loser")
        assert _row(rid).status == RunStatus.RUNNING  # loser cannot finish it
        _fail_run(rid, "loser boom", "w-fence-loser")
        row = _row(rid)
        assert row.status == RunStatus.RUNNING  # ... nor fail it
        assert "loser boom" not in (row.notes or "")
        _ensure_finished(rid, "w-fence-winner")
        assert _row(rid).status == RunStatus.DONE  # owner finishes fine
    finally:
        _settle(rid)

    repo2 = _repo("fence-fail")
    rid2 = _run_id(repo2.id)
    try:
        assert rid2 in [r.id for r in claim_pending_runs("w-fence-winner", limit=10000)]
        _fail_run(rid2, "owner boom", "w-fence-winner")
        row2 = _row(rid2)
        assert row2.status == RunStatus.FAILED and "owner boom" in (row2.notes or "")
    finally:
        _settle(rid2, RunStatus.FAILED)


def test_reap_skips_fresh_claim_but_reaps_expired():
    stale = _run_id(_repo("reap-stale").id)
    fresh = None
    try:
        assert stale in [r.id for r in claim_pending_runs("w-reap-dead", limit=10000)]
        _backdate(stale, started_hours_ago=25)
        fresh = _run_id(_repo("reap-fresh").id)
        assert fresh in [r.id for r in claim_pending_runs("w-reap-live", limit=10000)]
        _backdate(fresh, started_hours_ago=25)  # stale but live lease
        _backdate(stale, claimed_minutes_ago=CLAIM_LEASE_MINUTES + 1)  # lease died
        assert reap_stale_runs() >= 1
        assert _row(fresh).status == RunStatus.RUNNING  # live lease spared
        row = _row(stale)
        assert row.status == RunStatus.FAILED  # expired lease reaped
        assert "reaped" in (row.notes or "")
    finally:
        if fresh is not None:
            _settle(fresh)
        _settle(stale, RunStatus.FAILED)


def test_boot_reap_spares_fresh_claim():
    live = _run_id(_repo("boot-live").id)
    dead = None
    try:
        assert live in [r.id for r in claim_pending_runs("w-boot-old", limit=10000)]
        # Created after the claim sweep, so it stays unclaimed: prior incarnation died.
        dead = _run_id(_repo("boot-dead").id)
        _backdate(dead, started_hours_ago=1)
        reap_stale_runs(older_than_hours=0)  # boot: prior incarnation is dead
        assert _row(live).status == RunStatus.RUNNING  # fresh lease spared
        assert _row(dead).status == RunStatus.FAILED  # unclaimed run reaped
    finally:
        _settle(live)
        if dead is not None:
            _settle(dead, RunStatus.FAILED)


def test_run_once_heartbeat_renews_during_long_run():
    import security_agent.worker.main as worker_main

    with session_scope() as db:  # isolate: run_once drains oldest-first
        for row in db.scalars(select(ScanRun).where(ScanRun.status == RunStatus.RUNNING)):
            row.status = RunStatus.DONE
            row.finished_at = datetime.now(UTC)
    rid = _run_id(_repo("beat").id)
    seen: dict = {}

    def slow_invoke(payload):
        if payload["run_id"] != rid:
            return {}
        with session_scope() as db:
            seen["first"] = db.get(ScanRun, rid).claimed_at
        time.sleep(0.3)
        with session_scope() as db:
            seen["last"] = db.get(ScanRun, rid).claimed_at
        return {}

    graph = mock.Mock()
    graph.invoke.side_effect = slow_invoke
    try:
        with (
            mock.patch.object(worker_main, "HEARTBEAT_SECONDS", 0.05),
            mock.patch("security_agent.worker.build_graph", return_value=graph),
            mock.patch("security_agent.worker.news.poll_news", return_value={}),
            mock.patch(
                "security_agent.worker.news.run_matcher",
                return_value={"items": 0, "boosts": 0},
            ),
        ):
            summary = worker_main.run_once()
    finally:
        _settle(rid)
    graph.invoke.assert_any_call({"repo_id": _row(rid).repo_id, "run_id": rid})
    assert summary["executed"] >= 1
    assert _aware(seen["last"]) > _aware(seen["first"])  # beats renewed the lease
    assert _row(rid).status == RunStatus.DONE
