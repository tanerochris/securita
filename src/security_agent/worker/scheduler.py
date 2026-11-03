"""Per-repo scan scheduler (FR-2 D2/D3).

Triggers: 6h poll default (per-repo configurable) + scan-on-connect +
manual + webhooks. Enqueueing is idempotent: an in-flight run is
returned instead of double-enqueueing, enforced atomically by a
partial unique index so concurrent workers coalesce. Runs a crashed
worker never finished are reaped, so no repo wedges forever.

H6 #14: due/reap predicates run in SQL (no per-repo ORM round-trips).
H6 #31: workers claim runs with an atomic guarded UPDATE + lease, so
scale-out no longer double-executes.
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import String, and_, func, literal, or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError

from security_agent.db.models import Repo, RunStatus, RunTrigger, ScanRun
from security_agent.db.session import session_scope

log = logging.getLogger(__name__)

STALE_RUN_HOURS = 24
CLAIM_LEASE_MINUTES = 10


def _aware(dt: datetime) -> datetime:
    """SQLite returns naive datetimes; Postgres returns aware. Normalize."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _is_sqlite(db) -> bool:
    bind = db.get_bind()
    return bind is not None and bind.dialect.name == "sqlite"


_INFLIGHT = (RunStatus.QUEUED, RunStatus.RUNNING)


def _inflight_run(db, repo_id: int) -> ScanRun | None:
    return db.scalar(
        select(ScanRun)
        .where(ScanRun.repo_id == repo_id, ScanRun.status.in_(_INFLIGHT))
        .order_by(ScanRun.id.desc())
    )


def _due_predicate(db, now: datetime):
    """Repo is due when never scanned or its per-repo interval elapsed.

    The per-row `schedule_hours` addition is dialect-specific: SQLite
    date arithmetic on the stored (naive) timestamp, Postgres interval
    math on the aware one. Callers pass `now` in the matching flavor.
    """
    if _is_sqlite(db):
        now_str = now.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
        modifier = (
            literal("+")
            .op("||")(func.cast(Repo.schedule_hours, String))
            .op("||")(literal(" hours"))
        )
        due_at = func.datetime(Repo.last_scan_at, modifier)
        return (Repo.last_scan_at.is_(None)) | (due_at <= now_str)  # noqa: E712
    # make_interval(years, months, weeks, days, hours): hours ride 5th.
    cutoff_expr = Repo.last_scan_at + func.make_interval(0, 0, 0, 0, Repo.schedule_hours)
    return (Repo.last_scan_at.is_(None)) | (cutoff_expr <= now)  # noqa: E712


def due_repos(now: datetime | None = None) -> list[Repo]:
    """Repos due for a scan, in one query: no in-flight run + interval elapsed."""
    now = now or datetime.now(UTC)
    with session_scope() as db:
        running = (
            select(ScanRun.id)
            .where(ScanRun.repo_id == Repo.id, ScanRun.status.in_(_INFLIGHT))
            .exists()
        )
        rows = list(db.scalars(select(Repo).where(~running, _due_predicate(db, now))))
        for r in rows:
            db.expunge(r)
        return rows


def enqueue_scan(repo_id: int, trigger: RunTrigger, *, notes: str = "") -> ScanRun:
    """Enqueue a run, or return the in-flight one (webhook replay/manual spam safe)."""
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        if repo is None:
            raise ValueError(f"Unknown repo {repo_id}.")
        existing = _inflight_run(db, repo_id)
        if existing is not None:
            db.expunge(existing)
            return existing
        run = ScanRun(repo_id=repo_id, trigger=trigger, notes=notes or None)
        db.add(run)
        repo.last_scan_at = datetime.now(UTC)
        try:
            db.flush()
        except IntegrityError:
            # Lost a cross-process race: return the winner.
            db.rollback()
            winner = _inflight_run(db, repo_id)
            if winner is None:
                raise
            db.expunge(winner)
            return winner
        db.expunge(run)
        return run


def trigger_manual_scan(repo_id: int) -> ScanRun:
    return enqueue_scan(repo_id, RunTrigger.MANUAL)


def claim_pending_runs(
    worker_id: str | None = None,
    limit: int = 20,
    *,
    lease_minutes: float = CLAIM_LEASE_MINUTES,
    now: datetime | None = None,
) -> list[ScanRun]:
    """Atomically claim owned runs, oldest first; losers get nothing.

    Each candidate is taken with a single guarded UPDATE; `rowcount == 1`
    means this worker won, and the win flips QUEUED to RUNNING in the
    same statement. Fresh QUEUED rows and lease-expired RUNNING rows
    (dead worker) are claimable; parked runs (NFR-8 hard stop) are never
    claimed — only an explicit resume re-queues them. Without a
    worker_id the call stays a read-only peek (tooling/tests); the
    worker always passes one.
    """
    now = now or datetime.now(UTC)
    with session_scope() as db:
        sql_now = now.replace(tzinfo=None) if _is_sqlite(db) else now
        lease_cutoff = sql_now - timedelta(minutes=lease_minutes)
        expired = (ScanRun.claimed_at.is_(None)) | (ScanRun.claimed_at < lease_cutoff)
        claimable = or_(
            and_(ScanRun.status == RunStatus.QUEUED, ScanRun.claimed_at.is_(None)),
            and_(ScanRun.status == RunStatus.RUNNING, expired),
        )
        candidates = list(
            db.scalars(
                select(ScanRun)
                .where(claimable, ScanRun.parked.is_(False))
                .order_by(ScanRun.id)
                .limit(limit)
            )
        )
        if worker_id is None:
            for r in candidates:
                db.expunge(r)
            return candidates
        owned: list[ScanRun] = []
        for candidate in candidates:
            result = db.execute(
                update(ScanRun)
                .where(ScanRun.id == candidate.id, claimable, ScanRun.parked.is_(False))
                .values(
                    status=RunStatus.RUNNING, claimed_by=worker_id, claimed_at=sql_now
                )
            )
            updated = cast("CursorResult[Any]", result).rowcount
            if updated == 1:
                db.expunge(candidate)
                candidate.status = RunStatus.RUNNING
                candidate.claimed_by = worker_id
                owned.append(candidate)
            else:
                db.expunge(candidate)  # lost the race (or it parked); skip it
        return owned


def touch_claim(run_id: int, worker_id: str, *, now: datetime | None = None) -> bool:
    """Renew an owned claim's lease; False when the lease is gone or stolen.

    Single guarded UPDATE (`id AND claimed_by AND RUNNING`); only the
    current owner moves `claimed_at`.
    """
    now = now or datetime.now(UTC)
    with session_scope() as db:
        sql_now = now.replace(tzinfo=None) if _is_sqlite(db) else now
        result = db.execute(
            update(ScanRun)
            .where(
                ScanRun.id == run_id,
                ScanRun.claimed_by == worker_id,
                ScanRun.status == RunStatus.RUNNING,
            )
            .values(claimed_at=sql_now)
        )
        return cast("CursorResult[Any]", result).rowcount == 1


def reap_stale_runs(
    *,
    older_than_hours: float = STALE_RUN_HOURS,
    lease_minutes: float = CLAIM_LEASE_MINUTES,
    now: datetime | None = None,
) -> int:
    """Fail stale RUNNING runs older than the horizon (dead worker).

    One UPDATE ... RETURNING id (SQLite and Postgres both support
    RETURNING); the returned ids are the count. Parked runs are exempt
    (their in-flight row is the resume handle, not a wedged worker),
    and so are runs holding a fresh claim lease — reap never kills a
    live worker. QUEUED rows are never reaped: a live worker claims
    them instead, and the boot reap (horizon zero) must spare them.
    """
    now = now or datetime.now(UTC)
    with session_scope() as db:
        sql_now = now.replace(tzinfo=None) if _is_sqlite(db) else now
        cutoff = sql_now - timedelta(hours=older_than_hours)
        lease_cutoff = sql_now - timedelta(minutes=lease_minutes)
        note = "\nreaped: no worker finished this run in time"
        result = db.execute(
            update(ScanRun)
            .where(
                ScanRun.status == RunStatus.RUNNING,
                ScanRun.parked.is_(False),
                ScanRun.started_at < cutoff,
                (ScanRun.claimed_at.is_(None)) | (ScanRun.claimed_at < lease_cutoff),
            )
            .values(
                status=RunStatus.FAILED,
                finished_at=sql_now,
                notes=func.coalesce(ScanRun.notes, "").op("||")(literal(note)),
            )
            .returning(ScanRun.id)
        )
        reaped = len(result.scalars().all())
    if reaped:
        log.warning("reaped %d stale runs", reaped)
    return reaped


def new_worker_id() -> str:
    """Per-process worker identity for run claims (H6 #31)."""
    return f"worker-{uuid.uuid4().hex[:12]}"


def dep_tick(now: datetime | None = None) -> list:
    """One dependency poll iteration: reap, then a SCHEDULED check per due repo.

    Isolated from the security scan tick (D5): dependency failures never
    fail or delay a security scan, and vice versa.
    """
    from security_agent.db.models import RunTrigger
    from security_agent.worker.deps_check import (
        dep_due_repos,
        enqueue_dependency_check,
        purge_old_dep_records,
        reap_stale_dep_checks,
    )

    try:
        reap_stale_dep_checks()
    except Exception as exc:  # noqa: BLE001 - housekeeping never fails the tick
        log.warning("dep reap failed: %s", exc)
    try:
        purge_old_dep_records()
    except Exception as exc:  # noqa: BLE001 - housekeeping never fails the tick
        log.warning("dep retention purge failed: %s", exc)
    enqueued = []
    try:
        due = dep_due_repos(now)
    except Exception as exc:  # noqa: BLE001 - dep scheduling never fails the tick
        log.warning("dep due query failed: %s", exc)
        return []
    for repo in due:
        try:
            enqueued.append(enqueue_dependency_check(repo.id, RunTrigger.SCHEDULED))
        except Exception as exc:  # noqa: BLE001 - one bad repo never fails the tick
            log.warning("dep enqueue failed for repo %d: %s", repo.id, exc)
    return enqueued


def tick(now: datetime | None = None) -> list[ScanRun]:
    """One poll iteration: sweeps, retention, news, then a SCHEDULED run per due repo."""
    from security_agent.control.cost import purge_old_usage
    from security_agent.control.gates import sweep_expired_gates
    from security_agent.control.lifecycle import (
        purge_old_news,
        purge_old_polls,
        purge_old_verdicts,
    )
    from security_agent.notify.digest import maybe_send_digest
    from security_agent.worker.deliver import purge_old_deliveries
    from security_agent.worker.news import poll_news
    from security_agent.worker.news_intel import process_news

    def _news() -> None:
        poll_news()
        process_news()

    for label, job in (
        ("gate sweep", lambda: sweep_expired_gates(now)),
        ("verdict retention", purge_old_verdicts),
        ("news retention", purge_old_news),
        ("poll-log retention", purge_old_polls),
        ("delivery retention", purge_old_deliveries),
        ("usage retention", purge_old_usage),
        ("news signals", _news),
        ("stale-run reap", lambda: reap_stale_runs(now=now)),
        ("risk digest", lambda: maybe_send_digest(now)),
    ):
        try:
            job()
        except Exception as exc:  # noqa: BLE001 - housekeeping never fails the tick
            log.warning("%s failed: %s", label, exc)
    return [enqueue_scan(r.id, RunTrigger.SCHEDULED) for r in due_repos(now)]
