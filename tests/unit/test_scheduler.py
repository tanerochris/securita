"""Slice B: repo intake, credentials, scheduler triggers."""

import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from unittest import mock

import pytest
from sqlalchemy import select

from security_agent.control import repos
from security_agent.db.models import (
    EncryptedToken,
    RepoKind,
    RunStatus,
    RunTrigger,
    ScanRun,
)
from security_agent.db.session import session_scope
from security_agent.worker.scheduler import due_repos, enqueue_scan, tick, trigger_manual_scan


def _runs(repo_id: int) -> list[ScanRun]:
    with session_scope() as db:
        rows = list(db.scalars(select(ScanRun).where(ScanRun.repo_id == repo_id)))
        for r in rows:
            db.expunge(r)
        return rows


def test_connect_git_enqueues_first_run():
    repo = repos.connect_repo("git-r", RepoKind.GIT, url="https://example.com/r.git")
    runs = _runs(repo.id)
    assert len(runs) == 1 and runs[0].trigger == RunTrigger.CONNECT


def test_connect_validates_shapes():
    with pytest.raises(ValueError, match="valid git URL"):
        repos.connect_repo("bad", RepoKind.GIT, url="notaurl")
    with pytest.raises(ValueError, match="absolute local_path"):
        repos.connect_repo("bad", RepoKind.LOCAL, local_path="relative/path")
    with pytest.raises(ValueError, match="not local_path"):
        repos.connect_repo(
            "bad", RepoKind.GIT, url="https://example.com/r.git", local_path="/tmp/x"
        )
    local = repos.connect_repo("local-r", RepoKind.LOCAL, local_path="/tmp/repo")
    assert local.kind == RepoKind.LOCAL


def test_token_stored_encrypted_and_roundtrips():
    repo = repos.connect_repo(
        "tok-r", RepoKind.GIT, url="https://example.com/t.git", token="ghp-secret"
    )
    with session_scope() as db:
        row = db.scalar(
            select(EncryptedToken).where(EncryptedToken.owner == f"repo-token:{repo.id}")
        )
        assert row is not None and row.ciphertext != "ghp-secret"
    assert repos.get_repo_token(repo.id) == "ghp-secret"
    assert repos.get_repo_token(999999) is None


def test_webhook_secret_verify_both_providers():
    repo = repos.connect_repo("hook-r", RepoKind.GIT, url="https://example.com/h.git")
    assert repos.verify_github_signature(repo.id, b"{}", "sha256=00") is False
    secret = repos.issue_webhook_secret(repo.id)
    body = b'{"ref":"refs/heads/main"}'
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert repos.verify_github_signature(repo.id, body, sig) is True
    assert repos.verify_github_signature(repo.id, body, "sha256=dead") is False
    assert repos.verify_gitlab_token(repo.id, secret) is True
    assert repos.verify_gitlab_token(repo.id, "wrong") is False


def test_due_skips_inflight_and_fresh():
    repo = repos.connect_repo("due-r", RepoKind.GIT, url="https://example.com/d.git")
    assert repo.id not in [r.id for r in due_repos()]  # fresh + QUEUED connect run
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        run.status = RunStatus.DONE
        db.get(type(repo), repo.id).last_scan_at = datetime.now(UTC) - timedelta(hours=7)
    assert repo.id in [r.id for r in due_repos()]


def _finish_runs(repo_id: int) -> None:
    with session_scope() as db:
        for run in db.scalars(select(ScanRun).where(ScanRun.repo_id == repo_id)):
            run.status = RunStatus.DONE
            run.finished_at = datetime.now(UTC)


def test_tick_and_manual_enqueue():
    repo = repos.connect_repo("tick-r", RepoKind.GIT, url="https://example.com/k.git")
    _finish_runs(repo.id)
    with session_scope() as db:
        db.get(type(repo), repo.id).last_scan_at = datetime.now(UTC) - timedelta(hours=7)
    with (
        mock.patch("security_agent.worker.news.poll_news", return_value={}),
        mock.patch(
            "security_agent.worker.news_intel.process_news",
            return_value={"classified": 0, "major": 0, "minted": 0, "linked": 0},
        ),
    ):
        scheduled = tick()
    assert repo.id in [r.repo_id for r in scheduled]
    assert all(r.trigger == RunTrigger.SCHEDULED for r in scheduled if r.repo_id == repo.id)
    _finish_runs(repo.id)
    manual = trigger_manual_scan(repo.id)
    assert manual.trigger == RunTrigger.MANUAL
    with pytest.raises(ValueError, match="Unknown repo"):
        enqueue_scan(999999, RunTrigger.MANUAL)


def test_enqueue_coalesces_with_inflight_run():
    repo = repos.connect_repo("coal-r", RepoKind.GIT, url="https://example.com/c.git")
    first = _runs(repo.id)[0]
    second = enqueue_scan(repo.id, RunTrigger.MANUAL)
    assert second.id == first.id
    assert len(_runs(repo.id)) == 1


def test_single_flight_index_rejects_second_inflight():
    import sqlalchemy.exc

    repo = repos.connect_repo("sfl-r", RepoKind.GIT, url="https://example.com/s.git")
    with session_scope() as db:
        db.add(ScanRun(repo_id=repo.id, trigger=RunTrigger.MANUAL))
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            db.flush()
        db.rollback()
    # Finished runs never collide.
    _finish_runs(repo.id)
    with session_scope() as db:
        db.add(ScanRun(repo_id=repo.id, trigger=RunTrigger.MANUAL))
        db.flush()


def test_reap_spares_queued_runs():
    from security_agent.worker.scheduler import claim_pending_runs, reap_stale_runs

    repo = repos.connect_repo("reap-r", RepoKind.GIT, url="https://example.com/p.git")
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        run.started_at = datetime.now(UTC) - timedelta(hours=25)
    reap_stale_runs()
    (run,) = _runs(repo.id)
    assert run.status == RunStatus.QUEUED  # queued rows never reap
    assert repo.id not in [r.id for r in due_repos(datetime.now(UTC) + timedelta(hours=7))]
    owned = [r.id for r in claim_pending_runs("w-reap-queue", limit=10000)]
    assert run.id in owned  # still claimable; the claim flips it to RUNNING
    with session_scope() as db:
        row = db.get(ScanRun, run.id)
        row.status = RunStatus.DONE
        row.finished_at = datetime.now(UTC)


def test_claim_pending_runs_oldest_first():
    from security_agent.worker.scheduler import claim_pending_runs

    a = repos.connect_repo("clm-a", RepoKind.GIT, url="https://example.com/a.git")
    b = repos.connect_repo("clm-b", RepoKind.GIT, url="https://example.com/b.git")
    ids = [r.id for r in claim_pending_runs(limit=10000)]
    assert ids.index(_runs(a.id)[0].id) < ids.index(_runs(b.id)[0].id)
    assert ids == sorted(ids)


def test_claim_is_atomic_one_winner_per_run():
    """Two workers racing a claim split the runs with no overlap (H6 #31)."""
    import threading

    from security_agent.worker.scheduler import claim_pending_runs

    mine = []
    for tag in ("w1", "w2", "w3"):
        r = repos.connect_repo(f"race-{tag}", RepoKind.GIT, url=f"https://example.com/{tag}.git")
        mine.append(_runs(r.id)[0].id)
    won: dict[str, list[int]] = {"w1": [], "w2": []}
    barrier = threading.Barrier(2)

    def grab(worker: str) -> None:
        barrier.wait(timeout=10)
        won[worker] = [r.id for r in claim_pending_runs(worker, limit=10000)]

    threads = [threading.Thread(target=grab, args=(w,)) for w in ("w1", "w2")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    got = [i for w in won.values() for i in w if i in mine]
    assert sorted(got) == sorted(mine)  # every run claimed exactly once
    assert not (set(won["w1"]) & set(won["w2"]))  # no double execution


def test_claim_skips_parked_and_honors_lease():
    from security_agent.worker.scheduler import claim_pending_runs

    repo = repos.connect_repo("lease-r", RepoKind.GIT, url="https://example.com/l.git")
    (run,) = _runs(repo.id)
    first = claim_pending_runs("worker-a", limit=10000)
    assert run.id in [r.id for r in first]
    assert run.id not in [r.id for r in claim_pending_runs("worker-b", limit=10000)]
    with session_scope() as db:  # expired lease is stealable
        row = db.get(ScanRun, run.id)
        row.claimed_at = datetime.now(UTC) - timedelta(minutes=11)
    assert run.id in [r.id for r in claim_pending_runs("worker-b", limit=10000)]
    with session_scope() as db:  # parked runs are never claimed
        row = db.get(ScanRun, run.id)
        row.parked = True
        row.claimed_at = None
    assert run.id not in [r.id for r in claim_pending_runs("worker-c", limit=10000)]


def test_reap_skips_parked_runs():
    from security_agent.worker.scheduler import reap_stale_runs

    repo = repos.connect_repo("reap-park", RepoKind.GIT, url="https://example.com/rp.git")
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        run.started_at = datetime.now(UTC) - timedelta(hours=25)
        run.parked = True
        run.park_reason = "cap"
    reap_stale_runs()
    (run,) = _runs(repo.id)
    assert run.status == RunStatus.QUEUED  # parked is a resume handle, not a wedge


def test_due_respects_per_repo_schedule_in_sql():
    repo = repos.connect_repo("due-sql", RepoKind.GIT, url="https://example.com/ds.git")
    _finish_runs(repo.id)
    with session_scope() as db:
        row = db.get(type(repo), repo.id)
        row.schedule_hours = 48
        row.last_scan_at = datetime.now(UTC) - timedelta(hours=7)
    assert repo.id not in [r.id for r in due_repos()]
    with session_scope() as db:
        row = db.get(type(repo), repo.id)
        row.last_scan_at = datetime.now(UTC) - timedelta(hours=49)
    assert repo.id in [r.id for r in due_repos()]
    with session_scope() as db:
        row = db.get(type(repo), repo.id)
        row.last_scan_at = None
    assert repo.id in [r.id for r in due_repos()]
