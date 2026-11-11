"""Worker entrypoint: the orchestrator schedules, executors run the graph.

Roles (WORKER_ROLE): "orchestrator" ticks housekeeping/enqueues only,
"executor" claims and executes runs only, "all" does both (dev and
single-process deploys). Deploy exactly one orchestrator — duplicate
ticks would repeat digests and news work — and scale executors freely:
claims are atomic with a 10-minute lease (H6 #31), so executors split
the queue without double-executing. Executors poll faster than the
orchestrator tick because claim checks are cheap and pickup latency
is user-visible.

A crash mid-run leaves a RUNNING row that the next orchestrator boot
reaps (or a stale lease another executor steals), so the queue never
wedges. Boot reaps spare fresh claim leases, so after a restart an
executor may idle up to one lease (10 minutes) before it can re-claim
the previous incarnation's runs.
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

ORCHESTRATE_SECONDS = 60
EXECUTOR_POLL_SECONDS = 10

WORKER_ROLES = ("all", "orchestrator", "executor")

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


def resolve_role() -> str:
    """Active worker role from WORKER_ROLE; fail fast on a bad value."""
    from security_agent.config import get_settings

    role = (get_settings().worker_role or "all").strip().lower()
    if role not in WORKER_ROLES:
        raise ValueError(f"Unknown WORKER_ROLE {role!r}: want one of {WORKER_ROLES}.")
    return role


def orchestrate_once() -> dict:
    """One scheduling pass: housekeeping plus due scan/check enqueues.

    Never executes: enqueued rows sit QUEUED until an executor claims
    them. The orchestrator owns this half (and the boot reaps).
    """
    from security_agent.worker.scheduler import dep_tick

    enqueued = tick()
    dep_enqueued = dep_tick()
    return {"enqueued": len(enqueued), "dep_enqueued": len(dep_enqueued)}


def execute_once(*, max_runs: int = 100) -> dict:
    """One execution pass: drain claimed scans, dep checks, dep patches.

    Never schedules: no tick, no new enqueues. Executors own this half
    and split the queue via atomic claims (H6 #31).
    """
    from security_agent.control.lifecycle import append_run_note
    from security_agent.worker import build_graph
    from security_agent.worker.deps_check import drain_dep_checks, drain_dep_patches

    dep_drain: dict = {"executed": 0, "failed": 0}
    dep_patches: dict = {"proposal_ids": [], "errors": []}
    graph = build_graph()
    executed = failed = parked = 0
    while executed + failed + parked < max_runs:
        pending = claim_pending_runs(WORKER_ID)
        if not pending:
            break
        for run in pending:
            # First log line within seconds of the claim, before the
            # pipeline's own stages write anything.
            append_run_note(run.id, f"claimed by {WORKER_ID}; pipeline starting")
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
                from security_agent.brain import BrainError

                if isinstance(exc, BrainError):
                    from security_agent.control.cost import park_run_for_brain

                    park_run_for_brain(run.id, str(exc))
                    parked += 1
                    log.warning("run %d parked: brain error: %s", run.id, exc)
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
    # Dependency work drains after security scans: separate failure
    # domains (D5) and no head-of-line latency for the scan pipeline.
    try:
        dep_drain = drain_dep_checks(WORKER_ID)
    except Exception:  # noqa: BLE001 - dep checks never kill the worker loop
        log.exception("dependency check drain failed")
    try:
        dep_patches = drain_dep_patches()
    except Exception:  # noqa: BLE001 - dep patches never kill the worker loop
        log.exception("dependency patch drain failed")
    return {
        "executed": executed,
        "failed": failed,
        "parked": parked,
        "dep_executed": dep_drain.get("executed", 0),
        "dep_failed": dep_drain.get("failed", 0),
        "dep_proposals": dep_patches.get("proposal_ids", []),
    }


def run_once(*, max_runs: int = 100) -> dict:
    """One iteration: tick the scheduler, drain claimed runs oldest-first."""
    summary = orchestrate_once()
    summary.update(execute_once(max_runs=max_runs))
    return summary


def run_role_once(role: str, *, max_runs: int = 100) -> dict:
    """One loop iteration for `role` (see resolve_role)."""
    if role == "orchestrator":
        return orchestrate_once()
    if role == "executor":
        return execute_once(max_runs=max_runs)
    if role == "all":
        return run_once(max_runs=max_runs)
    raise ValueError(f"Unknown worker role {role!r}: want one of {WORKER_ROLES}.")


def main() -> None:
    from security_agent.sandbox import assert_sandbox_image
    from security_agent.worker import build_graph
    from security_agent.worker.deps_check import reap_stale_dep_checks

    role = resolve_role()  # fail fast on a bad WORKER_ROLE
    ensure_schema()  # schema before any query (this worker migrates itself)
    if role in ("orchestrator", "all"):
        reap_stale_runs(older_than_hours=0)  # boot: prior incarnation is dead
        reap_stale_dep_checks(older_than_hours=0)  # same for dep checks (D5)
    if role in ("executor", "all"):
        assert_sandbox_image()  # image before any scan (fail loud, not per-run)
        build_graph()  # fail fast when the pipeline does not compile
    sleep = ORCHESTRATE_SECONDS if role != "executor" else EXECUTOR_POLL_SECONDS
    log.warning("worker ready (role=%s)", role)
    while True:
        try:
            summary = run_role_once(role)
            log.info("tick: %r", summary)
        except Exception:  # noqa: BLE001 - one bad iteration must not kill the worker
            log.exception("%s iteration failed", role)
        time.sleep(sleep)


if __name__ == "__main__":
    main()
