"""Worker entrypoint: schedule, then execute claimed runs through the graph.

One loop iteration enqueues due scans and runs every claimed run to
completion. Claims are atomic with a 10-minute lease (H6 #31), so a
second worker only picks up expired leases instead of double-executing.
A crash mid-run leaves a RUNNING row that the next boot reaps (or a
stale lease another worker steals), so the queue never wedges.

Boot reaps stale runs but spares fresh claim leases, so after a
single-replica restart the new process may idle up to one lease
(10 minutes) before it can re-claim the previous incarnation's runs.
"""

import logging
import threading
import time
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import update
from sqlalchemy.engine import CursorResult

from security_agent.db.models import RunStatus, ScanRun
from security_agent.db.session import session_scope
from security_agent.worker.scheduler import (
    claim_pending_runs,
    new_worker_id,
    reap_stale_runs,
    tick,
    touch_claim,
)

log = logging.getLogger(__name__)

WORKER_ID = new_worker_id()

HEARTBEAT_SECONDS = 4 * 60

_MIGRATE_ATTEMPTS = 5
_MIGRATE_RETRY_SECONDS = 5


def ensure_schema() -> None:
    """Bring this worker's schema to head before any query runs.

    The app upgrades the schema in its own lifespan, but the worker boots
    independently (and can win the race), so it must not assume the DB
    already has the columns its queries select. Postgres upgrades run via
    alembic with retries: a concurrent app/worker upgrade holds the DDL
    locks, and the loser just tries again.
    """
    from security_agent.config import get_settings

    if get_settings().database_url.startswith("postgresql"):
        from alembic import command
        from alembic.config import Config

        last: Exception | None = None
        for attempt in range(_MIGRATE_ATTEMPTS):
            try:
                command.upgrade(Config("alembic.ini"), "head")
                return
            except Exception as exc:  # noqa: BLE001 - contention is expected
                last = exc
                log.warning("schema upgrade attempt %d failed; retrying", attempt + 1)
                time.sleep(_MIGRATE_RETRY_SECONDS)
        raise RuntimeError(f"schema upgrade failed after {_MIGRATE_ATTEMPTS} attempts") from last
    from security_agent.db.models import Base
    from security_agent.db.session import get_engine

    Base.metadata.create_all(get_engine())


def _session_now(db, now: datetime) -> datetime:
    """Naive timestamps for SQLite, aware for Postgres (matches scheduler)."""
    bind = db.get_bind()
    if bind is not None and bind.dialect.name == "sqlite":
        return now.replace(tzinfo=None)
    return now


def _is_parked(run_id: int) -> bool:
    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        return bool(run is not None and run.parked)


def _owner_guard(worker_id: str | None):
    """Claim-ownership predicate: `None` matches unclaimed rows (legacy callers)."""
    if worker_id is None:
        return ScanRun.claimed_by.is_(None)
    return ScanRun.claimed_by == worker_id


def _fail_run(run_id: int, error: str, worker_id: str | None = None) -> None:
    """Fail a run only when this worker still owns its claim (fencing)."""
    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        if run is None or run.parked:
            return  # parked runs stay resumable; the cap note is already on them
        prior = f"{run.notes}\n" if run.notes else ""
        result = db.execute(
            update(ScanRun)
            .where(
                ScanRun.id == run_id,
                _owner_guard(worker_id),
                ScanRun.parked.is_(False),
            )
            .values(
                status=RunStatus.FAILED,
                finished_at=_session_now(db, datetime.now(UTC)),
                notes=prior + error,
            )
        )
        if cast("CursorResult[Any]", result).rowcount != 1:
            log.warning("run %d: claim lease lost; not failing another worker's run", run_id)


def _ensure_finished(run_id: int, worker_id: str | None = None) -> None:
    """Mark a run DONE only when this worker still owns its claim (fencing)."""
    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        if run is None or run.status != RunStatus.RUNNING:
            return
        prior = f"{run.notes}\n" if run.notes else ""
        result = db.execute(
            update(ScanRun)
            .where(
                ScanRun.id == run_id,
                _owner_guard(worker_id),
                ScanRun.status == RunStatus.RUNNING,
            )
            .values(
                status=RunStatus.DONE,
                finished_at=_session_now(db, datetime.now(UTC)),
                notes=prior + "pipeline complete",
            )
        )
        if cast("CursorResult[Any]", result).rowcount != 1:
            log.warning("run %d: claim lease lost; not finishing another worker's run", run_id)


def _claim_heartbeat(run_id: int, worker_id: str, stop: threading.Event) -> None:
    """Renew the run's claim until `stop` is set (daemon thread body)."""
    while not stop.wait(HEARTBEAT_SECONDS):
        try:
            if not touch_claim(run_id, worker_id):
                log.warning("run %d: claim lease lost; heartbeat stopping", run_id)
                return
        except Exception:  # noqa: BLE001 - a failed beat must not kill the run
            log.warning("run %d: claim heartbeat failed", run_id)


def run_once(*, max_runs: int = 100) -> dict:
    """One iteration: tick the scheduler, drain claimed runs oldest-first."""
    from security_agent.worker import build_graph

    enqueued = tick()
    graph = build_graph()
    executed = failed = parked = 0
    while executed + failed + parked < max_runs:
        pending = claim_pending_runs(WORKER_ID)
        if not pending:
            break
        for run in pending:
            stop = threading.Event()
            beat = threading.Thread(
                target=_claim_heartbeat,
                args=(run.id, WORKER_ID, stop),
                daemon=True,
                name=f"claim-heartbeat-{run.id}",
            )
            beat.start()
            try:
                graph.invoke({"repo_id": run.repo_id, "run_id": run.id})
            except Exception as exc:  # noqa: BLE001 - one bad run never kills the worker
                if _is_parked(run.id):
                    parked += 1
                    log.warning("run %d parked: cost cap", run.id)
                    continue
                failed += 1
                _fail_run(run.id, f"pipeline crashed: {exc}", WORKER_ID)
                log.exception("run %d crashed", run.id)
                continue
            else:
                executed += 1
                _ensure_finished(run.id, WORKER_ID)
            finally:
                stop.set()
                beat.join(timeout=10)
    return {"enqueued": len(enqueued), "executed": executed, "failed": failed, "parked": parked}


def main() -> None:
    from security_agent.sandbox import assert_sandbox_image
    from security_agent.worker import build_graph

    ensure_schema()  # schema before any query (this worker migrates itself)
    assert_sandbox_image()  # image before any scan (fail loud, not per-run)
    build_graph()  # fail fast when the pipeline does not compile
    reap_stale_runs(older_than_hours=0)  # boot: prior incarnation is dead by definition
    log.warning("worker ready")
    while True:
        try:
            summary = run_once()
            log.info("tick: %r", summary)
        except Exception:  # noqa: BLE001 - scheduler must not kill the worker
            log.exception("scheduler tick failed")
        time.sleep(60)


if __name__ == "__main__":
    main()
