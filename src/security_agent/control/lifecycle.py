"""Findings lifecycle transitions (FR-12 D1, FR-3 D4).

Unified: open → proposed → resolved → closed, plus terminal unpatchable
and silent-with-reason. Rescan verdict flips drive reopen (silent/resolved
→ open) and park (open/proposed → silent).
"""

from sqlalchemy import case, delete, func, nulls_last, select

from security_agent.db.models import (
    Finding,
    FindingStatus,
    ModelUsage,
    NewsBoost,
    NewsItem,
    NewsPoll,
    Proposal,
    Role,
    ScanRun,
    SecretFinding,
    SecretStatus,
    User,
    Verdict,
)
from security_agent.db.session import session_scope

TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.OPEN: frozenset(
        {FindingStatus.PROPOSED, FindingStatus.UNPATCHABLE, FindingStatus.SILENT}
    ),
    FindingStatus.PROPOSED: frozenset(
        {
            FindingStatus.OPEN,
            FindingStatus.RESOLVED,
            FindingStatus.UNPATCHABLE,
            FindingStatus.SILENT,
        }
    ),
    FindingStatus.RESOLVED: frozenset({FindingStatus.CLOSED, FindingStatus.OPEN}),
    FindingStatus.CLOSED: frozenset(),
    FindingStatus.UNPATCHABLE: frozenset(),
    FindingStatus.SILENT: frozenset({FindingStatus.OPEN}),
}


def transition_finding(finding_id: int, to_status: FindingStatus, *, reason: str = "") -> Finding:
    """Move a finding along the lifecycle; rejects illegal jumps."""
    with session_scope() as db:
        finding = db.get(Finding, finding_id)
        if finding is None:
            raise ValueError(f"Unknown finding {finding_id}.")
        if to_status not in TRANSITIONS[finding.status]:
            raise ValueError(f"Illegal transition {finding.status} → {to_status}.")
        finding.status = to_status
        finding.silent_reason = reason if to_status == FindingStatus.SILENT else None
        db.flush()
        db.expunge(finding)
        return finding


def apply_verdict(finding_id: int, run_id: int, reachable: bool, **fields) -> Verdict:
    """Record a reachability verdict and drive the lifecycle flip (FR-3 D4).

    Reachable flips silent/resolved → open (reopen). Unreachable parks
    open/proposed → silent with the verdict's reason code.
    """
    with session_scope() as db:
        verdict = Verdict(finding_id=finding_id, run_id=run_id, reachable=reachable)
        for key in ("evidence", "reason_code"):
            if key in fields:
                setattr(verdict, key, fields[key])
        db.add(verdict)
        db.flush()
        finding = db.get(Finding, finding_id)
        if finding is not None:
            if reachable and finding.status in (
                FindingStatus.SILENT,
                FindingStatus.RESOLVED,
            ):
                finding.status = FindingStatus.OPEN
                finding.silent_reason = None
            elif not reachable and finding.status in (
                FindingStatus.OPEN,
                FindingStatus.PROPOSED,
            ):
                finding.status = FindingStatus.SILENT
                finding.silent_reason = verdict.reason_code
        db.flush()
        db.expunge(verdict)
        return verdict


def _relevant_order():
    """Most-relevant-first: KEV, severity, then newest (FR-12 D3)."""
    return (
        Finding.kev_exploited.desc(),
        nulls_last(Finding.severity_score.desc()),
        Finding.id.desc(),
    )


def count_open_findings(repo_id: int) -> int:
    """Active finding count for pagination totals."""
    with session_scope() as db:
        return (
            db.scalar(
                select(func.count())
                .select_from(Finding)
                .where(
                    Finding.repo_id == repo_id,
                    Finding.status.in_([FindingStatus.OPEN, FindingStatus.PROPOSED]),
                )
            )
            or 0
        )


def list_open_findings(
    repo_id: int, *, limit: int | None = None, offset: int = 0
) -> list[Finding]:
    """Active findings for dashboards; silent excluded from default filters."""
    with session_scope() as db:
        stmt = (
            select(Finding)
            .where(
                Finding.repo_id == repo_id,
                Finding.status.in_([FindingStatus.OPEN, FindingStatus.PROPOSED]),
            )
            .order_by(*_relevant_order())
        )
        if offset:
            stmt = stmt.offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        rows = list(db.scalars(stmt))
        for r in rows:
            db.expunge(r)
        return rows


def list_silent_findings(repo_id: int) -> list[Finding]:
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(Finding)
                .where(
                    Finding.repo_id == repo_id,
                    Finding.status == FindingStatus.SILENT,
                )
                .order_by(*_relevant_order())
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


SECRET_TRANSITIONS: dict[SecretStatus, frozenset[SecretStatus]] = {
    # Open: removal PR proposed, HEAD cleaned by hand, or dead history-only.
    SecretStatus.OPEN: frozenset(
        {
            SecretStatus.PROPOSED,
            SecretStatus.AWAITING_ROTATION,
            SecretStatus.INFORMATIONAL,
        }
    ),
    # Proposed: HEAD-clean observed, or the removal PR died unmerged.
    SecretStatus.PROPOSED: frozenset({SecretStatus.AWAITING_ROTATION, SecretStatus.OPEN}),
    # Awaiting: rotation confirmed (human or dead verdict), or secret is back.
    SecretStatus.AWAITING_ROTATION: frozenset({SecretStatus.CLOSED, SecretStatus.OPEN}),
    # Closed/informational: a fingerprint seen again at HEAD is a new
    # incident (rotation does not cover recommitted values) and reopens.
    SecretStatus.CLOSED: frozenset({SecretStatus.OPEN}),
    SecretStatus.INFORMATIONAL: frozenset({SecretStatus.OPEN}),
}


def transition_secret_finding(secret_id: int, to_status: SecretStatus) -> SecretFinding:
    """Move a secret finding along its lifecycle; rejects illegal jumps."""
    with session_scope() as db:
        row = db.get(SecretFinding, secret_id)
        if row is None:
            raise ValueError(f"Unknown secret finding {secret_id}.")
        if to_status not in SECRET_TRANSITIONS[row.status]:
            raise ValueError(f"Illegal transition {row.status} → {to_status}.")
        row.status = to_status
        db.flush()
        db.expunge(row)
        return row


def mark_secret_rotated(secret_id: int, user: User) -> SecretFinding:
    """Human rotation confirmation (FR-8 D7): awaiting-rotation only.

    Offered only after HEAD-clean, so a merged removal PR alone can never
    close a live-secret finding. Owner/Maintainer only, fully audited.
    """
    from security_agent.audit import get_shared_log

    if user.role not in (Role.OWNER, Role.MAINTAINER):
        raise PermissionError("Only an Owner or Maintainer may confirm rotation.")
    with session_scope() as db:
        row = db.get(SecretFinding, secret_id)
        if row is None:
            raise ValueError(f"Unknown secret finding {secret_id}.")
        if row.status != SecretStatus.AWAITING_ROTATION:
            raise ValueError(f"Rotation needs HEAD-clean first (finding is {row.status.value}).")
        row.status = SecretStatus.CLOSED
        row.rotated_by = user.id
        from datetime import UTC, datetime

        row.rotated_at = datetime.now(UTC)
        db.flush()
        db.expunge(row)
    get_shared_log().append(
        action_class="secret",
        decision="rotated",
        line=f"secret={secret_id} confirmer={user.id} role={user.role.value}",
    )
    return row


def list_repo_secrets(repo_id: int) -> list[SecretFinding]:
    """Needs-action first: open, proposed, awaiting, then newest-id order."""
    priority = case(
        (SecretFinding.status == SecretStatus.OPEN, 0),
        (SecretFinding.status == SecretStatus.PROPOSED, 1),
        (SecretFinding.status == SecretStatus.AWAITING_ROTATION, 2),
        (SecretFinding.status == SecretStatus.CLOSED, 3),
        else_=4,
    )
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(SecretFinding)
                .where(SecretFinding.repo_id == repo_id)
                .order_by(priority, SecretFinding.id.desc())
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


def list_open_secrets(repo_id: int) -> list[SecretFinding]:
    """Actionable secrets for dashboards; closed/informational excluded."""
    return [
        r
        for r in list_repo_secrets(repo_id)
        if r.status
        in (
            SecretStatus.OPEN,
            SecretStatus.PROPOSED,
            SecretStatus.AWAITING_ROTATION,
        )
    ]


def list_repo_proposals(repo_id: int) -> list[Proposal]:
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(Proposal).where(Proposal.repo_id == repo_id).order_by(Proposal.id.desc())
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


def list_repo_runs(repo_id: int, limit: int = 20) -> list[ScanRun]:
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(ScanRun)
                .where(ScanRun.repo_id == repo_id)
                .order_by(ScanRun.id.desc())
                .limit(limit)
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


def get_run(run_id: int) -> ScanRun | None:
    with session_scope() as db:
        row = db.get(ScanRun, run_id)
        if row is not None:
            db.expunge(row)
        return row


def list_run_findings(run_id: int) -> list[Finding]:
    """Findings first seen by this run (dedupe keeps earliest first_run_id)."""
    with session_scope() as db:
        rows = list(
            db.scalars(select(Finding).where(Finding.first_run_id == run_id).order_by(Finding.id))
        )
        for r in rows:
            db.expunge(r)
        return rows


def list_run_secrets(run_id: int) -> list[SecretFinding]:
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(SecretFinding)
                .where(SecretFinding.first_run_id == run_id)
                .order_by(SecretFinding.id)
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


def list_run_usage(run_id: int) -> list[ModelUsage]:
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(ModelUsage).where(ModelUsage.run_id == run_id).order_by(ModelUsage.id)
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


def count_run_verdicts(run_id: int) -> tuple[int, int]:
    """(reachable, total) verdicts recorded by this run."""
    with session_scope() as db:
        rows = list(db.scalars(select(Verdict.reachable).where(Verdict.run_id == run_id)))
        return sum(1 for r in rows if r), len(rows)


VERDICT_RETENTION_DAYS = 90


def purge_old_verdicts(*, older_than_days: int = VERDICT_RETENTION_DAYS) -> int:
    """Delete verdicts past retention; one row per finding per run grows forever."""
    from datetime import UTC, datetime, timedelta

    cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
    with session_scope() as db:
        stale_ids = [
            vid
            for vid, created in db.execute(select(Verdict.id, Verdict.created_at)).all()
            if (created if created.tzinfo else created.replace(tzinfo=UTC)) < cutoff
        ]
        for verdict in db.scalars(select(Verdict).where(Verdict.id.in_(stale_ids))):
            db.delete(verdict)
        return len(stale_ids)


NEWS_RETENTION_DAYS = 90


def purge_old_news(*, older_than_days: int = NEWS_RETENTION_DAYS) -> int:
    """Delete news items past retention with their legacy boosts."""
    from datetime import UTC, datetime, timedelta

    cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
    with session_scope() as db:
        # SQL-side retention (follow-up #5): cutoff applied by the database
        # against the fetched_at index; SQLite stores naive datetimes.
        from typing import Any, cast

        from sqlalchemy.engine import CursorResult

        bind = db.get_bind()
        is_sqlite = bind is not None and bind.dialect.name == "sqlite"
        sql_cutoff = cutoff.replace(tzinfo=None) if is_sqlite else cutoff
        stale_select = select(NewsItem.id).where(NewsItem.fetched_at < sql_cutoff)
        db.execute(delete(NewsBoost).where(NewsBoost.news_item_id.in_(stale_select)))
        result = db.execute(delete(NewsItem).where(NewsItem.fetched_at < sql_cutoff))
        removed = cast("CursorResult[Any]", result).rowcount
        return int(removed or 0)


def purge_old_polls(*, older_than_days: int = NEWS_RETENTION_DAYS) -> int:
    """Delete poll-log rows past retention; hourly rows grow forever otherwise."""
    from datetime import UTC, datetime, timedelta

    cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
    with session_scope() as db:
        from typing import Any, cast

        from sqlalchemy.engine import CursorResult

        bind = db.get_bind()
        is_sqlite = bind is not None and bind.dialect.name == "sqlite"
        sql_cutoff = cutoff.replace(tzinfo=None) if is_sqlite else cutoff
        result = db.execute(delete(NewsPoll).where(NewsPoll.finished_at < sql_cutoff))
        return int(cast("CursorResult[Any]", result).rowcount or 0)
