"""Dependency freshness checks in a disposable sandbox (D4/D5/D14/D19/D20).

Each check creates its own fresh disposable sandbox, initializes it,
runs the native tooling to extract every piece of information needed,
and is destroyed afterwards — the same disposable-sandbox principle as
the scan pipeline (NFR-1: zero host-executed agent commands).

A DependencyCheck is its own run type with its own status and failure
domain (D5): a failed freshness check never fails or delays a security
scan, and vice versa. Partial results ship; every gap is a named state
(D19): a failed tool for one manifest leaves that manifest's section
`check_failed` with the tool error and its rows at last-known values
marked stale, while other manifests update normally. A check where
everything fails marks the run failed and fires a notification.

A new combined report is generated automatically only when the update
set changed since the last report (D14); unchanged sets reuse the
previous report with no model call. A dependency update defers to an
active Finding patch for the same package (D20).
"""

import hashlib
import json
import logging
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from security_agent.control.deps import append_check_note
from security_agent.db.models import (
    Dependency,
    DependencyCheck,
    DependencyReport,
    DependencyStatus,
    Repo,
    RunStatus,
    RunTrigger,
)
from security_agent.db.session import session_scope
from security_agent.sandbox import assert_host_execution_allowed, make_workdir
from security_agent.worker.deps_freshness import check_npm_manifest, check_pip_packages
from security_agent.worker.deps_manifests import (
    DepManifest,
    discover_dep_manifests,
    npm_spec_base,
    pip_spec_base,
    resolved_versions,
)
from security_agent.worker.scan import clone_repo

log = logging.getLogger(__name__)


class DependencyCheckError(RuntimeError):
    """Expected check failure: recorded on the check, not raised past run."""


# --- Enqueue / due (D5/D14/D15) ---


def _running_check(db, repo_id: int) -> DependencyCheck | None:
    return db.scalar(
        select(DependencyCheck)
        .where(
            DependencyCheck.repo_id == repo_id,
            DependencyCheck.status == RunStatus.RUNNING,
        )
        .order_by(DependencyCheck.id.desc())
    )


def enqueue_dependency_check(
    repo_id: int, trigger: RunTrigger, *, notes: str = ""
) -> DependencyCheck:
    """Enqueue a check, or return the in-flight one (manual spam safe)."""
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        if repo is None:
            raise ValueError(f"Unknown repo {repo_id}.")
        existing = _running_check(db, repo_id)
        if existing is not None:
            db.expunge(existing)
            return existing
        check = DependencyCheck(repo_id=repo_id, trigger=trigger, notes=notes or None)
        db.add(check)
        repo.dep_last_check_at = datetime.now(UTC)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            winner = _running_check(db, repo_id)
            if winner is None:
                raise
            db.expunge(winner)
            return winner
        db.expunge(check)
        return check


def dep_due_repos(now: datetime | None = None) -> list[Repo]:
    """Repos due for a dependency check: no RUNNING check + interval elapsed.

    Per-repo override wins (NULL inherits the install setting, 0 never);
    the per-row interval math mirrors the scan scheduler per dialect.
    """
    from sqlalchemy import String, func, literal

    from security_agent.control.deps import get_dep_check_hours

    now = now or datetime.now(UTC)
    with session_scope() as db:
        bind = db.get_bind()
        is_sqlite = bind is not None and bind.dialect.name == "sqlite"
        running = (
            select(DependencyCheck.id)
            .where(
                DependencyCheck.repo_id == Repo.id,
                DependencyCheck.status == RunStatus.RUNNING,
            )
            .exists()
        )
        fallback = get_dep_check_hours()
        hours = func.coalesce(Repo.dep_schedule_hours, fallback)
        if is_sqlite:
            now_str = now.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
            modifier = (
                literal("+").op("||")(func.cast(hours, String)).op("||")(literal(" hours"))
            )
            due_at = func.datetime(Repo.dep_last_check_at, modifier)
            due = (Repo.dep_last_check_at.is_(None)) | (due_at <= now_str)  # noqa: E712
        else:
            cutoff = Repo.dep_last_check_at + func.make_interval(0, 0, 0, 0, hours)
            due = (Repo.dep_last_check_at.is_(None)) | (cutoff <= now)  # noqa: E712
        rows = list(
            db.scalars(
                select(Repo)
                .where(
                    ~running,
                    Repo.dep_schedule_hours.is_(None) | (Repo.dep_schedule_hours != 0),
                    due,
                )
                .order_by(Repo.id)
                .limit(200)  # bounded burst per tick; the rest wait a minute
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


# --- Update-set hash (D14) ---


def update_set_hash(entries: list[tuple[str, str, str, str]]) -> str:
    """Stable hash over (key, installed, latest, bucket) tuples."""
    blob = json.dumps(sorted(entries), separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def _row_marker(row: Dependency) -> tuple[str, str, str, str]:
    """Hash entry with a state-stable bucket (D14).

    Transient reporting states (update_available, awaiting_decision,
    proposed, report_pending_cap, up_to_date) all map to "tracked", so
    creating a report does not itself change the set — an unchanged set
    reuses the previous report with no model call. Only membership moves
    flip the bucket: declined:<version> (quiet until a newer version),
    ignored (still checked, never reported), covered_by_finding (queued
    behind a Finding patch), and check_failed (last-known values).
    """
    key = f"{row.ecosystem}|{row.manifest_path}|{row.package}"
    status = row.status
    if status == DependencyStatus.DECLINED:
        bucket = f"declined:{row.declined_version or ''}"
    elif status == DependencyStatus.IGNORED:
        bucket = "ignored"
    elif status == DependencyStatus.COVERED_BY_FINDING:
        bucket = "covered"
    elif status == DependencyStatus.CHECK_FAILED:
        bucket = "failed"
    else:
        bucket = "tracked"
    return (
        key,
        row.installed_version or "",
        row.latest_version or "",
        bucket,
    )


# --- Persist (D2/D3) ---


def persist_dependencies(repo_id: int, records: list[dict]) -> list[Dependency]:
    """Upsert by (repo, ecosystem, manifest, package); returns fresh rows.

    Silence and patch states survive untouched: ignored rows keep their
    ignore (still freshness-checked so Latest stays honest, D21),
    declined rows re-propose only when a newer version appears (D10),
    and proposed rows stay queued until the patch flow resolves them.
    """
    rows: list[Dependency] = []
    with session_scope() as db:
        for record in records:
            row = db.scalar(
                select(Dependency).where(
                    Dependency.repo_id == repo_id,
                    Dependency.ecosystem == record["ecosystem"],
                    Dependency.manifest_path == record["manifest_path"],
                    Dependency.package == record["package"],
                )
            )
            if row is None:
                row = Dependency(
                    repo_id=repo_id,
                    ecosystem=record["ecosystem"],
                    manifest_path=record["manifest_path"],
                    package=record["package"],
                    status=DependencyStatus.UP_TO_DATE,
                )
                db.add(row)
                try:
                    with db.begin_nested():
                        db.flush()
                except IntegrityError:
                    # Lost an insert race to a concurrent check for the
                    # same repo: adopt the winner's row (scan precedent).
                    row = db.scalar(
                        select(Dependency).where(
                            Dependency.repo_id == repo_id,
                            Dependency.ecosystem == record["ecosystem"],
                            Dependency.manifest_path == record["manifest_path"],
                            Dependency.package == record["package"],
                        )
                    )
                    if row is None:
                        raise
            _apply_record(row, record)
            db.flush()
            db.expunge(row)
            rows.append(row)
    return rows


def _apply_record(row: Dependency, record: dict) -> None:
    """Merge one freshness record, honouring sticky states (D10/D20/D21)."""
    failed = record.get("failed", False)
    if failed:
        # Silences and approvals are user state, not freshness state: a
        # tool failure marks values stale but never erases them (D10/D21).
        if row.status not in (
            DependencyStatus.IGNORED,
            DependencyStatus.DECLINED,
            DependencyStatus.PROPOSED,
        ):
            row.status = DependencyStatus.CHECK_FAILED
        row.stale = True
        row.check_error = record.get("error") or "freshness tool failed"
        row.last_checked_at = datetime.now(UTC)
        return
    row.section = record.get("section")
    row.manifest_spec = record.get("manifest_spec")
    row.installed_version = record.get("installed")
    row.latest_version = record.get("latest")
    row.wanted_version = record.get("wanted")
    row.update_class = record.get("update_class")
    row.stale = False
    row.check_error = None
    row.last_checked_at = datetime.now(UTC)
    if row.status == DependencyStatus.IGNORED:
        return  # D21: still checked, never reported
    if row.status == DependencyStatus.PROPOSED:
        return  # patch queued or running; the patch flow owns the outcome
    if record.get("covered_by_finding"):
        row.status = DependencyStatus.COVERED_BY_FINDING
        row.security = True
        row.finding_id = record.get("finding_id")
        return
    row.security = bool(record.get("security"))
    row.finding_id = record.get("finding_id")
    installed, latest = record.get("installed"), record.get("latest")
    has_update = bool(latest) and latest != installed
    if not has_update:
        row.status = DependencyStatus.UP_TO_DATE
        row.declined_version = None
        return
    if row.declined_version == latest and row.status == DependencyStatus.DECLINED:
        return  # D10: quiet until a newer version appears
    if row.status not in (
        DependencyStatus.AWAITING_DECISION,
        DependencyStatus.REPORT_PENDING_CAP,
    ):
        row.status = DependencyStatus.UPDATE_AVAILABLE
    # AWAITING/REPORT_PENDING rows keep their state until the report step
    # re-decides them below; a changed set re-reports, else they stand.


def prune_absent_packages(repo_id: int, manifests: list[DepManifest], *, truncated: bool) -> int:
    """Drop rows for packages/manifests no longer declared (D3 tracked set).

    Guarded: never prunes when discovery hit the cap (the walk may have
    missed the manifest) or for manifests whose freshness failed (their
    rows sit at last-known values, D19).
    """
    if truncated:
        return 0
    with session_scope() as db:
        rows = list(db.scalars(select(Dependency).where(Dependency.repo_id == repo_id)))
        live = {
            (m.ecosystem, m.rel, p.name) for m in manifests for p in m.packages
        }
        failed_manifests = {m.rel for m in manifests if m.failed}
        removed = 0
        for row in rows:
            if row.manifest_path in failed_manifests:
                continue
            if (row.ecosystem, row.manifest_path, row.package) not in live:
                db.delete(row)
                removed += 1
        return removed


# --- The check (D4/D5) ---


def _finish_check(
    check_id: int, status: RunStatus, notes: list[str], *, worker_id: str | None = None
) -> None:
    """Finish a check; worker-owned finishes are fenced on the claim.

    A stale owner whose lease was taken over cannot overwrite the new
    owner's status/notes: the guarded UPDATE matches only while this
    worker still holds the claim on a RUNNING row.
    """
    from typing import Any, cast

    from sqlalchemy import func, literal, update
    from sqlalchemy.engine import CursorResult

    joined = "\n".join(n for n in notes if n)
    if worker_id is None:
        with session_scope() as db:
            check = db.get(DependencyCheck, check_id)
            if check is None:
                return
            check.status = status
            check.finished_at = datetime.now(UTC)
            prior = f"{check.notes}\n" if check.notes else ""
            check.notes = prior + joined
        return
    with session_scope() as db:
        bind = db.get_bind()
        now = datetime.now(UTC)
        sql_now = now.replace(tzinfo=None) if bind and bind.dialect.name == "sqlite" else now
        result = db.execute(
            update(DependencyCheck)
            .where(
                DependencyCheck.id == check_id,
                DependencyCheck.claimed_by == worker_id,
                DependencyCheck.status == RunStatus.RUNNING,
            )
            .values(
                status=status,
                finished_at=sql_now,
                notes=func.coalesce(DependencyCheck.notes, "").op("||")(
                    literal(f"\n{joined}" if joined else "")
                ),
            )
        )
        if cast("CursorResult[Any]", result).rowcount != 1:
            log.debug("dep check %d finish fenced off (claim lost)", check_id)


def _record_manifest_outcome(check_id: int, outcome: dict) -> None:
    with session_scope() as db:
        check = db.get(DependencyCheck, check_id)
        if check is None:
            return
        manifests = list(check.manifests or [])
        manifests.append(outcome)
        check.manifests = manifests


def fail_dependency_check(
    check_id: int, error: str, *, worker_id: str | None = None
) -> None:
    """Fail a check the worker could not execute (queue fencing for deps)."""
    _finish_check(check_id, RunStatus.FAILED, [error], worker_id=worker_id)


def touch_dep_claim(check_id: int, worker_id: str) -> bool:
    """Renew one dep check's lease; False when the claim was lost."""
    from typing import Any, cast

    from sqlalchemy import update
    from sqlalchemy.engine import CursorResult

    now = datetime.now(UTC)
    with session_scope() as db:
        bind = db.get_bind()
        sql_now = now.replace(tzinfo=None) if bind and bind.dialect.name == "sqlite" else now
        result = db.execute(
            update(DependencyCheck)
            .where(
                DependencyCheck.id == check_id,
                DependencyCheck.claimed_by == worker_id,
                DependencyCheck.status == RunStatus.RUNNING,
            )
            .values(claimed_at=sql_now)
        )
        return cast("CursorResult[Any]", result).rowcount == 1


def claim_dep_checks(worker_id: str | None = None, limit: int = 20) -> list[DependencyCheck]:
    """Atomically claim owned checks, oldest first (H6 #31 shape, no parking).

    Dependency checks never park: the tooling half is unbudgeted and the
    report half degrades to `report_pending_cap` rows instead of a stuck
    RUNNING row (D23). Without a worker_id the call stays a read-only
    peek (tooling/tests).
    """
    from datetime import timedelta
    from typing import Any, cast

    from sqlalchemy import update
    from sqlalchemy.engine import CursorResult

    from security_agent.worker.scheduler import CLAIM_LEASE_MINUTES

    now = datetime.now(UTC)
    with session_scope() as db:
        bind = db.get_bind()
        sql_now = now.replace(tzinfo=None) if bind and bind.dialect.name == "sqlite" else now
        lease_cutoff = sql_now - timedelta(minutes=CLAIM_LEASE_MINUTES)
        candidates = list(
            db.scalars(
                select(DependencyCheck)
                .where(
                    DependencyCheck.status == RunStatus.RUNNING,
                    (DependencyCheck.claimed_at.is_(None))
                    | (DependencyCheck.claimed_at < lease_cutoff),
                )
                .order_by(DependencyCheck.id)
                .limit(limit)
            )
        )
        if worker_id is None:
            for r in candidates:
                db.expunge(r)
            return candidates
        owned: list[DependencyCheck] = []
        for candidate in candidates:
            result = db.execute(
                update(DependencyCheck)
                .where(
                    DependencyCheck.id == candidate.id,
                    DependencyCheck.status == RunStatus.RUNNING,
                    (DependencyCheck.claimed_at.is_(None))
                    | (DependencyCheck.claimed_at < lease_cutoff),
                )
                .values(claimed_by=worker_id, claimed_at=sql_now)
            )
            if cast("CursorResult[Any]", result).rowcount == 1:
                db.expunge(candidate)
                candidate.claimed_by = worker_id
                owned.append(candidate)
            else:
                db.expunge(candidate)
        return owned


def reap_stale_dep_checks(*, older_than_hours: float = 24) -> int:
    """Fail in-flight checks older than the horizon (dead worker, wedged queue)."""
    from datetime import timedelta

    from sqlalchemy import func, literal, update

    now = datetime.now(UTC)
    with session_scope() as db:
        bind = db.get_bind()
        sql_now = now.replace(tzinfo=None) if bind and bind.dialect.name == "sqlite" else now
        cutoff = sql_now - timedelta(hours=older_than_hours)
        note = "\nreaped: no worker finished this check in time"
        from security_agent.worker.scheduler import CLAIM_LEASE_MINUTES

        lease_cutoff = sql_now - timedelta(minutes=CLAIM_LEASE_MINUTES)
        result = db.execute(
            update(DependencyCheck)
            .where(
                DependencyCheck.status == RunStatus.RUNNING,
                DependencyCheck.started_at < cutoff,
                # Spare live claim holders, like reap_stale_runs: only
                # unclaimed or lease-expired rows are dead.
                (DependencyCheck.claimed_at.is_(None))
                | (DependencyCheck.claimed_at < lease_cutoff),
            )
            .values(
                status=RunStatus.FAILED,
                finished_at=sql_now,
                notes=func.coalesce(DependencyCheck.notes, "").op("||")(literal(note)),
            )
            .returning(DependencyCheck.id)
        )
        reaped = len(result.scalars().all())
    if reaped:
        log.warning("reaped %d stale dependency checks", reaped)
    return reaped


def _dep_heartbeat(check_id: int, worker_id: str, stop) -> None:
    """Renew the claim lease until the check finishes (lease is 10 min)."""
    while not stop.wait(DEP_HEARTBEAT_SECONDS):
        try:
            if not touch_dep_claim(check_id, worker_id):
                log.error(
                    "dep check %d claim lost mid-run; finish will be fenced", check_id
                )
                return
        except Exception:  # noqa: BLE001 - a lost beat never kills the check
            log.exception("dep check %d heartbeat failed", check_id)
            return


def purge_old_dep_records(
    *, notification_days: int = 90, check_days: int = 90, report_days: int = 180
) -> dict:
    """Retention for dependency records (bounded storage growth).

    Notifications and finished checks age out after 90 days; decided or
    superseded reports after 180 days. References are nulled before
    deletes so live rows never dangle; running checks and pending
    reports are never purged.
    """
    from datetime import timedelta
    from typing import Any, cast

    from sqlalchemy import delete, update
    from sqlalchemy.engine import CursorResult

    from security_agent.db.models import (
        DashboardNotification,
        NotificationRead,
    )

    now = datetime.now(UTC)
    counts = {"notifications": 0, "checks": 0, "reports": 0}
    with session_scope() as db:
        bind = db.get_bind()
        sql_now = now.replace(tzinfo=None) if bind and bind.dialect.name == "sqlite" else now
        old_notifs = select(DashboardNotification.id).where(
            DashboardNotification.created_at < sql_now - timedelta(days=notification_days)
        )
        db.execute(
            delete(NotificationRead).where(
                NotificationRead.notification_id.in_(old_notifs)
            )
        )
        res = db.execute(
            delete(DashboardNotification).where(
                DashboardNotification.created_at
                < sql_now - timedelta(days=notification_days)
            )
        )
        counts["notifications"] = cast("CursorResult[Any]", res).rowcount or 0
        old_checks = select(DependencyCheck.id).where(
            DependencyCheck.finished_at.is_not(None),
            DependencyCheck.started_at < sql_now - timedelta(days=check_days),
        )
        db.execute(
            update(DependencyReport)
            .where(DependencyReport.check_id.in_(old_checks))
            .values(check_id=None)
        )
        res = db.execute(
            delete(DependencyCheck).where(
                DependencyCheck.finished_at.is_not(None),
                DependencyCheck.started_at < sql_now - timedelta(days=check_days),
            )
        )
        counts["checks"] = cast("CursorResult[Any]", res).rowcount or 0
        old_reports = select(DependencyReport.id).where(
            DependencyReport.status != "pending",
            DependencyReport.created_at < sql_now - timedelta(days=report_days),
        )
        db.execute(
            update(DependencyCheck)
            .where(DependencyCheck.report_id.in_(old_reports))
            .values(report_id=None)
        )
        db.execute(
            update(DashboardNotification)
            .where(DashboardNotification.report_id.in_(old_reports))
            .values(report_id=None)
        )
        res = db.execute(
            delete(DependencyReport).where(
                DependencyReport.status != "pending",
                DependencyReport.created_at < sql_now - timedelta(days=report_days),
            )
        )
        counts["reports"] = cast("CursorResult[Any]", res).rowcount or 0
    return counts


def drain_dep_checks(worker_id: str, *, max_checks: int = 100) -> dict:
    """Execute claimed checks oldest-first; one bad check never kills the drain."""
    import threading

    executed = failed = 0
    while executed + failed < max_checks:
        pending = claim_dep_checks(worker_id)
        if not pending:
            break
        for check in pending:
            force = "force-report" in (check.notes or "")
            stop = threading.Event()
            beat = threading.Thread(
                target=_dep_heartbeat,
                args=(check.id, worker_id, stop),
                daemon=True,
            )
            beat.start()
            try:
                run_dependency_check(
                    check.repo_id, check.id, force_report=force, worker_id=worker_id
                )
            except Exception as exc:  # noqa: BLE001 - one bad check never kills the drain
                failed += 1
                fail_dependency_check(
                    check.id, f"check crashed: {exc}", worker_id=worker_id
                )
                log.exception("dependency check %d crashed", check.id)
                continue
            finally:
                stop.set()
                beat.join(timeout=10)
            executed += 1
    return {"executed": executed, "failed": failed}


def drain_dep_patches(*, max_repos: int = 50) -> dict:
    """Patch + deliver approved updates for repos with pending approvals (D7).

    Runs after the check drain: approval authorizes exactly this worker
    pass. Delivery rides the existing branch/PR + FR-9 merge gate.
    """
    from security_agent.worker.deps_patch import run_approved_updates, run_dep_deliver

    with session_scope() as db:
        repo_ids = list(
            db.scalars(
                select(Dependency.repo_id)
                .where(
                    Dependency.status == DependencyStatus.PROPOSED,
                    Dependency.proposal_id.is_(None),
                )
                .distinct()
                .limit(max_repos)
            )
        )
    proposals: list[int] = []
    errors: list[str] = []
    for repo_id in repo_ids:
        try:
            patched = run_approved_updates(repo_id)
            proposals.extend(patched["proposal_ids"])
            delivered = run_dep_deliver(repo_id)
            errors.extend(delivered["errors"])
        except Exception as exc:  # noqa: BLE001 - one bad repo never kills the drain
            errors.append(f"repo {repo_id}: {exc}")
            log.exception("dependency patch drain failed for repo %d", repo_id)
    return {"proposal_ids": proposals, "errors": errors}


DEP_HEARTBEAT_SECONDS = 4 * 60


def run_dependency_check(
    repo_id: int,
    check_id: int,
    *,
    source_dir: Path | None = None,
    force_report: bool = False,
    npm_fetch=None,
    pip_fetch=None,
    usage_fetch=None,
    summary_model=None,
    worker_id: str | None = None,
) -> dict:
    """Execute one freshness check; failures land on the check record.

    Injectable fetchers (npm_fetch, pip_fetch, usage_fetch, summary_model)
    let tests drive the whole flow without network or a sandbox; each
    defaults to the native-tooling path (D4).
    """
    assert_host_execution_allowed()
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        check = db.get(DependencyCheck, check_id)
        if repo is None or check is None:
            raise ValueError(f"Unknown repo {repo_id} or check {check_id}.")
        db.expunge(repo)
    from security_agent.control.deps import (
        live_proposal_packages,
        package_finding_index,
    )
    from security_agent.worker.deps_patch import release_settled_proposals

    release_settled_proposals(repo_id)
    finding_index = package_finding_index(repo_id)
    live_packages = live_proposal_packages(repo_id, finding_index)
    notes: list[str] = []
    workdir = source_dir
    owned = workdir is None
    try:
        if workdir is None:
            append_check_note(check_id, f"deps: cloning {repo.name}...")
            clone_started = time.monotonic()
            workdir = make_workdir(f"depcheck-{check_id}-")
            clone_repo(repo, workdir)
            append_check_note(
                check_id, f"deps: cloned in {time.monotonic() - clone_started:.1f}s"
            )
        manifests, truncated = discover_dep_manifests(workdir)
        if truncated:
            line = "manifest walk capped; some manifests unchecked (see tab)"
            notes.append(line)
            append_check_note(check_id, line)
        if not manifests:
            line = "no supported manifests; nothing to track"
            notes.append(line)
            append_check_note(check_id, line)
            prune_absent_packages(repo_id, [], truncated=False)
            _finish_check(check_id, RunStatus.DONE, [], worker_id=worker_id)
            return {"status": RunStatus.DONE.value, "manifests": 0}
        append_check_note(check_id, f"deps: found {len(manifests)} manifest(s)")
        peer_ranges: dict[str, dict[str, str]] = {}
        failures = 0
        for manifest in manifests:
            try:
                records = _check_manifest(
                    manifest,
                    repo_id,
                    npm_fetch=npm_fetch,
                    pip_fetch=pip_fetch,
                    finding_index=finding_index,
                    live_packages=live_packages,
                )
            except (DependencyCheckError, RuntimeError, TimeoutError) as exc:
                failures += 1
                manifest.failed = True
                records = [
                    {
                        "ecosystem": manifest.ecosystem,
                        "manifest_path": manifest.rel,
                        "package": pkg.name,
                        "failed": True,
                        "error": f"{manifest.kind} freshness failed: {exc}",
                    }
                    for pkg in manifest.packages
                ]
                _record_manifest_outcome(
                    check_id,
                    {
                        "manifest": manifest.rel,
                        "status": "check_failed",
                        "error": str(exc),
                    },
                )
                line = f"{manifest.rel}: check failed ({exc})"
                notes.append(line)
                append_check_note(check_id, line)
            else:
                _record_manifest_outcome(
                    check_id,
                    {"manifest": manifest.rel, "status": "ok", "packages": len(records)},
                )
                append_check_note(
                    check_id, f"deps: {manifest.rel}: {len(records)} package(s) tracked"
                )
            peer_ranges[manifest.rel] = dict(manifest.peer_ranges)
            persist_dependencies(repo_id, records)
        if failures and failures == len(manifests):
            line = "all manifests failed"
            notes.append(line)
            append_check_note(check_id, line)
            _finish_check(check_id, RunStatus.FAILED, [], worker_id=worker_id)
            _notify_failure(repo_id, check_id, notes)
            return {"status": RunStatus.FAILED.value, "error": "; ".join(notes)}
        prune_absent_packages(repo_id, manifests, truncated=truncated)
        append_check_note(check_id, "report: assessing updates...")
        outcome = _maybe_report(
            repo_id,
            check_id,
            workdir,
            peer_ranges,
            force_report=force_report,
            usage_fetch=usage_fetch,
            summary_model=summary_model,
        )
        _finish_check(check_id, RunStatus.DONE, outcome.get("notes", []), worker_id=worker_id)
        with session_scope() as db:
            check_row = db.get(DependencyCheck, check_id)
            if check_row is not None:
                check_row.update_set_hash = outcome.get("hash")
                check_row.report_id = outcome.get("report_id")
        return {
            "status": RunStatus.DONE.value,
            "manifests": len(manifests),
            "report_id": outcome.get("report_id"),
            "reused_report_id": outcome.get("reused_report_id"),
        }
    except (DependencyCheckError, RuntimeError, TimeoutError) as exc:
        line = f"failed: {exc}"
        notes.append(line)
        _finish_check(check_id, RunStatus.FAILED, [line], worker_id=worker_id)
        _notify_failure(repo_id, check_id, notes)
        return {"status": RunStatus.FAILED.value, "error": str(exc)}
    finally:
        if owned and workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)


def _failed_record(manifest: DepManifest, package: str, error: str) -> dict:
    return {
        "ecosystem": manifest.ecosystem,
        "manifest_path": manifest.rel,
        "package": package,
        "failed": True,
        "error": error,
    }


def _check_manifest(
    manifest: DepManifest,
    repo_id: int,
    *,
    npm_fetch,
    pip_fetch,
    finding_index,
    live_packages,
) -> list[dict]:
    """Freshness records for one manifest via native tooling (D4)."""
    from security_agent.control.deps import security_fix_from
    from security_agent.worker.scan import normalize_dist_name

    resolved = resolved_versions(manifest)  # one lockfile parse per manifest
    specs: dict[str, tuple[str | None, str]] = {}
    for pkg in manifest.packages:
        if manifest.ecosystem == "npm":
            base = npm_spec_base(pkg.spec)
            installed = resolved.get(pkg.name) or (
                base if base and base[0].isdigit() else None
            )
        else:
            installed = resolved.get(normalize_dist_name(pkg.name)) or pip_spec_base(
                pkg.spec
            )
        specs[pkg.name] = (installed, pkg.spec)
    if manifest.ecosystem == "npm":
        pm = {"package-lock": "npm", "yarn": "yarn", "pnpm": "pnpm"}.get(
            manifest.lock_kind or "", "npm"
        )
        if npm_fetch is not None:
            freshness = npm_fetch(manifest.path.parent, specs, pm=pm)
        else:
            freshness = check_npm_manifest(manifest.path.parent, specs, pm=pm)
    else:
        if pip_fetch is not None:
            freshness = pip_fetch(specs)
        else:
            freshness = check_pip_packages(specs)
    records = []
    for pkg in manifest.packages:
        fresh = freshness.get(pkg.name)
        if fresh is None:
            records.append(_failed_record(manifest, pkg.name, "no freshness answer"))
            continue
        if fresh.latest is None and fresh.error:
            records.append(_failed_record(manifest, pkg.name, fresh.error))
            continue
        installed = fresh.installed or specs[pkg.name][0]
        live = pkg.name in live_packages
        fix = security_fix_from(
            finding_index.get(pkg.name, []), installed, fresh.latest
        )
        records.append(
            {
                "ecosystem": manifest.ecosystem,
                "manifest_path": manifest.rel,
                "package": pkg.name,
                "section": pkg.section,
                "manifest_spec": pkg.spec,
                "installed": installed,
                "latest": fresh.latest,
                "wanted": fresh.wanted,
                "update_class": fresh.update_class,
                "security": fix is not None,
                "finding_id": fix.id if fix else None,
                "covered_by_finding": live,
            }
        )
    return records


def _maybe_report(
    repo_id: int,
    check_id: int,
    workdir: Path,
    peer_ranges: dict[str, dict[str, str]],
    *,
    force_report: bool,
    usage_fetch,
    summary_model,
) -> dict:
    """Create a combined report only when the update set changed (D14)."""
    from security_agent.control.deps import DepsBudgetExceeded
    from security_agent.worker.deps_report import (
        ReportError,
        advisories_for_finding,
        build_section,
        create_report,
        gather_usage,
        generate_summary,
    )

    with session_scope() as db:
        rows = list(db.scalars(select(Dependency).where(Dependency.repo_id == repo_id)))
        for r in rows:
            db.expunge(r)
        last_report = db.scalar(
            select(DependencyReport)
            .where(
                DependencyReport.repo_id == repo_id,
                DependencyReport.status != "superseded",
            )
            .order_by(DependencyReport.id.desc())
            .limit(1)
        )
        last_hash = last_report.update_set_hash if last_report else None
        last_id = last_report.id if last_report else None
        if last_report is not None:
            db.expunge(last_report)
    current_hash = update_set_hash([_row_marker(r) for r in rows])
    reportable = [
        r
        for r in rows
        if r.latest_version
        and r.latest_version != r.installed_version
        and r.status
        in (
            DependencyStatus.UPDATE_AVAILABLE,
            DependencyStatus.AWAITING_DECISION,
            DependencyStatus.REPORT_PENDING_CAP,
        )
    ]
    notes: list[str] = []
    if not force_report and current_hash == last_hash:
        notes.append("update set unchanged; reusing previous report (no model call)")
        return {"hash": current_hash, "report_id": None, "reused_report_id": last_id}
    if not reportable:
        notes.append("no reportable updates")
        _supersede_pending(repo_id)
        return {"hash": current_hash, "report_id": None, "reused_report_id": None}
    sections = []
    append_check_note(check_id, f"report: assessing {len(reportable)} update(s)...")
    for row in sorted(reportable, key=lambda r: (r.manifest_path, r.package)):
        try:
            if usage_fetch is not None:
                sites = usage_fetch(str(workdir), row.ecosystem, row.package)
            else:
                sites = gather_usage(str(workdir), row.ecosystem, row.package)
            append_check_note(
                check_id, f"report: {row.package}: {len(sites)} usage site(s)"
            )
        except (RuntimeError, TimeoutError) as exc:
            sites = []
            notes.append(f"{row.package}: usage search failed ({exc})")
        sections.append(
            build_section(
                row,
                usage_sites=sites,
                peer_ranges=peer_ranges.get(row.manifest_path, {}),
                advisories=advisories_for_finding(row.finding_id),
            )
        )
    append_check_note(check_id, "report: writing summary...")
    try:
        summary, model_backed = generate_summary(sections, model=summary_model)
    except ReportError as exc:
        notes.append(f"report step failed ({exc}); table updated, next check retries")
        return {"hash": current_hash, "report_id": None, "reused_report_id": None, "notes": notes}
    except DepsBudgetExceeded as exc:
        notes.append(f"report parked ({exc})")
        _park_rows_pending_cap(repo_id, [r.id for r in reportable])
        _notify_cap(repo_id, check_id)
        return {"hash": current_hash, "report_id": None, "reused_report_id": None, "notes": notes}
    try:
        report = create_report(
            repo_id,
            check_id,
            sections,
            summary,
            model_backed=model_backed,
            update_set_hash=current_hash,
        )
    except IntegrityError:
        # One-pending invariant (D9): a concurrent check won the report
        # slot; reuse its pending report instead of failing the check.
        notes.append("concurrent check created the pending report; reusing it")
        with session_scope() as db:
            winner = db.scalar(
                select(DependencyReport)
                .where(
                    DependencyReport.repo_id == repo_id,
                    DependencyReport.status == "pending",
                )
                .order_by(DependencyReport.id.desc())
                .limit(1)
            )
            winner_id = winner.id if winner else None
        return {
            "hash": current_hash,
            "report_id": None,
            "reused_report_id": winner_id,
            "notes": notes,
        }
    notes.append(f"combined report #{report.id} ({len(sections)} updates)")
    if any(s.get("update_class") == "major" or s.get("security") for s in sections):
        _notify_report(repo_id, check_id, report.id, sections)
    else:
        notes.append("minor/patch-only: tracked and reported, no notification (D14)")
    return {
        "hash": current_hash,
        "report_id": report.id,
        "reused_report_id": None,
        "notes": notes,
    }


def _supersede_pending(repo_id: int) -> None:
    with session_scope() as db:
        stale = list(
            db.scalars(
                select(DependencyReport).where(
                    DependencyReport.repo_id == repo_id,
                    DependencyReport.status == "pending",
                )
            )
        )
        for old in stale:
            old.status = "superseded"


def _park_rows_pending_cap(repo_id: int, dep_ids: list[int]) -> None:
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(Dependency).where(
                    Dependency.repo_id == repo_id, Dependency.id.in_(dep_ids)
                )
            )
        )
        for row in rows:
            if row.status != DependencyStatus.PROPOSED:
                row.status = DependencyStatus.REPORT_PENDING_CAP


def _notify_report(repo_id: int, check_id: int, report_id: int, sections: list[dict]) -> None:
    from security_agent.control.notifications import push_notification

    majors = sum(1 for s in sections if s.get("update_class") == "major")
    security = sum(1 for s in sections if s.get("security"))
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        name = repo.name if repo else f"repo#{repo_id}"
    push_notification(
        "deps-report",
        f"{name}: {len(sections)} updates ({majors} major, {security} security)",
        body="\n".join(
            f"- {s['package']} {s.get('installed') or '?'} -> {s.get('latest')} "
            f"({s.get('update_class') or 'unknown'})"
            + (" [security]" if s.get("security") else "")
            for s in sections[:20]
        ),
        repo_id=repo_id,
        report_id=report_id,
        check_id=check_id,
    )


def _notify_failure(repo_id: int, check_id: int, notes: list[str]) -> None:
    from security_agent.control.notifications import push_notification

    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        name = repo.name if repo else f"repo#{repo_id}"
    push_notification(
        "deps-failure",
        f"{name}: dependency check failed",
        body="; ".join(notes[-5:]),
        repo_id=repo_id,
        check_id=check_id,
    )


def _notify_cap(repo_id: int, check_id: int) -> None:
    from security_agent.control.notifications import push_notification

    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        name = repo.name if repo else f"repo#{repo_id}"
    push_notification(
        "deps-report",
        f"{name}: impact report parked (dependency budget hit)",
        body=(
            "The freshness table is up to date, but the impact report is "
            "parked at report_pending_cap. Raise the dependency budget in "
            "Settings and re-run the check to resume."
        ),
        repo_id=repo_id,
        check_id=check_id,
    )
