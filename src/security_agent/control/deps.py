"""Dependency-update lifecycle, cadence, and separate budget (D7/D10/D14/D15/D21/D23).

Cadence (D14/D15): install-wide interval (default 24h) in dashboard
Settings, inherited by every repo; a repo may override it, including
"never check automatically" (manual and on-connect checks still work).

Budget (D23): the dependency feature has its own budget, independent
of the vulnerability/security pipeline budget — dependency spending
never parks or starves a security scan, and vice versa. When the
dependency budget parks report generation the table still updates, the
tab shows `report_pending_cap` with a raise-budget/resume path, and a
dashboard notification fires.

Decisions (D7/D10/D21): Owner/Maintainer-only, recorded on the report
(report id, decider, reason) and audit-logged. Ticked packages go to
patching; unticked packages are `declined` for that specific version
only and rejoin when a newer version appears.
"""

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import case, func, literal, or_, select, update

from security_agent.audit import get_shared_log
from security_agent.db.models import (
    Dependency,
    DependencyCheck,
    DependencyReport,
    DependencyStatus,
    Finding,
    FindingStatus,
    NotifyState,
    Proposal,
    ProposalStatus,
    Repo,
    Role,
    User,
)
from security_agent.db.session import session_scope

log = logging.getLogger(__name__)
audit = get_shared_log()

DEFAULT_DEP_CHECK_HOURS = 24
DEFAULT_DEPS_SPEND_CAP_USD = 0.40
DEPS_SPEND_WINDOW_HOURS = 24

_DEP_HOURS_KEY = "deps.check_hours"
_DEPS_SPEND_CAP_KEY = "deps.spend_cap"
_DEPS_CAP_LEGACY_KEY = "deps.token_cap"  # pre-USD token budget, converted at price
_DEPS_NOTIFY_EMAIL_KEY = "deps.notify_email"


class DepsBudgetExceeded(Exception):
    """Dependency budget hit: table updates, report parks (D23)."""


# --- Cadence (D14/D15) ---


def get_dep_check_hours() -> int:
    """Install-wide dependency-check interval in hours (default 24)."""
    with session_scope() as db:
        row = db.get(NotifyState, _DEP_HOURS_KEY)
        if row is not None:
            try:
                return max(1, int(row.value))
            except ValueError:
                pass
        return DEFAULT_DEP_CHECK_HOURS


def set_dep_check_hours(value: int, user: User) -> int:
    """Owner/Maintainer sets the install-wide interval."""
    if user.role not in (Role.OWNER, Role.MAINTAINER):
        raise PermissionError("Only an Owner or Maintainer may change dependency cadence.")
    if value < 1:
        raise ValueError("Interval must be at least 1 hour.")
    with session_scope() as db:
        row = db.get(NotifyState, _DEP_HOURS_KEY)
        if row is None:
            db.add(NotifyState(key=_DEP_HOURS_KEY, value=str(value)))
        else:
            row.value = str(value)
    audit.append(
        action_class="deps",
        decision="cadence",
        line=f"check_hours={value} by={user.id} role={user.role.value}",
    )
    return value


def effective_dep_interval(repo: Repo) -> int | None:
    """Hours between automatic checks, or None for never (D15).

    A per-repo override wins: NULL inherits the install setting, 0
    disables automatic checks, >0 is the repo's own interval.
    """
    override = repo.dep_schedule_hours
    if override is not None:
        return override if override > 0 else None
    return get_dep_check_hours()


def set_repo_dep_interval(repo_id: int, value: int | None, user: User) -> int | None:
    """Owner/Maintainer sets a repo override: NULL inherits, 0 never, >0 hours."""
    if user.role not in (Role.OWNER, Role.MAINTAINER):
        raise PermissionError("Only an Owner or Maintainer may change dependency cadence.")
    if value is not None and value < 0:
        raise ValueError("Interval must be >= 0 (0 disables automatic checks).")
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        if repo is None:
            raise ValueError(f"Unknown repo {repo_id}.")
        repo.dep_schedule_hours = value
    audit.append(
        action_class="deps",
        decision="cadence",
        line=f"repo={repo_id} dep_hours={value} by={user.id} role={user.role.value}",
    )
    return value


# --- Separate dependency budget (D23) ---


def get_deps_spend_cap() -> float:
    """Install-wide dependency spend budget in USD per rolling 24h window.

    Zero disables the budget. A legacy pre-USD token budget converts
    at the current model price until a USD budget replaces it.
    """
    from security_agent.config import get_settings

    with session_scope() as db:
        row = db.get(NotifyState, _DEPS_SPEND_CAP_KEY)
        if row is not None:
            try:
                return max(0.0, float(row.value))
            except ValueError:
                pass
        legacy = db.get(NotifyState, _DEPS_CAP_LEGACY_KEY)
        if legacy is not None:
            try:
                price = max(0.0, get_settings().model_price_per_mtok_usd) / 1_000_000
                return max(0.0, float(legacy.value)) * price
            except ValueError:
                pass
        return DEFAULT_DEPS_SPEND_CAP_USD


def set_deps_spend_cap(value: float, user: User) -> float:
    """Owner/Maintainer raises (or lowers) the dependency budget (0 disables)."""
    if user.role not in (Role.OWNER, Role.MAINTAINER):
        raise PermissionError("Only an Owner or Maintainer may change the dependency budget.")
    if value < 0:
        raise ValueError("Budget must be at least 0 (0 disables the budget).")
    with session_scope() as db:
        row = db.get(NotifyState, _DEPS_SPEND_CAP_KEY)
        if row is None:
            db.add(NotifyState(key=_DEPS_SPEND_CAP_KEY, value=str(value)))
        else:
            row.value = str(value)
        legacy = db.get(NotifyState, _DEPS_CAP_LEGACY_KEY)
        if legacy is not None:
            db.delete(legacy)
    audit.append(
        action_class="deps",
        decision="budget",
        line=f"spend_cap_usd={value} by={user.id} role={user.role.value}",
    )
    return value


def deps_spend_window(now: datetime | None = None) -> float:
    """Dependency-ledger spend in USD inside the rolling 24h window."""
    from security_agent.db.models import ModelUsage

    now = now or datetime.now(UTC)
    cutoff = now - timedelta(hours=DEPS_SPEND_WINDOW_HOURS)
    with session_scope() as db:
        bind = db.get_bind()
        if bind is not None and bind.dialect.name == "sqlite":
            cutoff = cutoff.replace(tzinfo=None)
        return float(
            db.scalar(
                select(func.coalesce(func.sum(ModelUsage.cost_usd), 0.0)).where(
                    ModelUsage.task.like("deps-%"),
                    ModelUsage.created_at >= cutoff,
                )
            )
            or 0.0
        )


def record_deps_usage(
    task: str, prompt_tokens: int, completion_tokens: int, *, estimated: bool = False
) -> dict:
    """Ledger one dependency model call; raise when the budget is hit.

    Dependency usage rides ModelUsage with a `deps-` task prefix and a
    NULL run id, so it never touches the security pipeline's per-run
    caps or daily spend alerts (D23 independence both ways). It does
    count toward the overall monthly spend cap, which sums every
    ledgered call by design.
    """
    from security_agent.config import get_settings
    from security_agent.control.cost import check_monthly_cap_alerts, format_usd
    from security_agent.db.models import ModelUsage

    total = max(0, prompt_tokens) + max(0, completion_tokens)
    price = max(0.0, get_settings().model_price_per_mtok_usd) / 1_000_000
    with session_scope() as db:
        db.add(
            ModelUsage(
                run_id=None,
                task=f"deps-{task}"[:100],
                prompt_tokens=max(0, prompt_tokens),
                completion_tokens=max(0, completion_tokens),
                total_tokens=total,
                cost_usd=total * price,
                estimated=estimated,
            )
        )
    check_monthly_cap_alerts()
    spent = deps_spend_window()
    cap = get_deps_spend_cap()
    if cap > 0 and spent >= cap:
        raise DepsBudgetExceeded(
            f"dependency budget hit ({format_usd(spent)}/{format_usd(cap)} per 24h)"
        )
    return {"total": total, "spent": spent, "cap": cap}


def deps_budget_state() -> dict:
    """Current budget triple for the Settings page and the tab banner."""
    spent = deps_spend_window()
    cap = get_deps_spend_cap()
    return {"spent": spent, "cap": cap, "exhausted": cap > 0 and spent >= cap}


def deps_notify_outbound_enabled() -> bool:
    """Whether dependency pool entries also fan out to routed channels.

    D16: dashboard-only by default; the opt-in delivers through the
    existing severity routing, so email, Slack, webhook, and any other
    configured channel kinds all receive dependency events.
    """
    with session_scope() as db:
        row = db.get(NotifyState, _DEPS_NOTIFY_EMAIL_KEY)
        return row is not None and row.value == "on"


def deps_notify_email_enabled() -> bool:
    """Backward-compatible alias for the outbound fan-out toggle."""
    return deps_notify_outbound_enabled()


def set_deps_notify_outbound(enabled: bool, user: User) -> bool:
    """Owner-only toggle for dependency outbound fan-out (D16)."""
    return set_deps_notify_email(enabled, user)


def set_deps_notify_email(enabled: bool, user: User) -> bool:
    """Owner-only toggle for dependency email fan-out (D16)."""
    if user.role != Role.OWNER:
        raise PermissionError("Only an Owner may change notification delivery.")
    with session_scope() as db:
        row = db.get(NotifyState, _DEPS_NOTIFY_EMAIL_KEY)
        if row is None:
            db.add(NotifyState(key=_DEPS_NOTIFY_EMAIL_KEY, value="on" if enabled else ""))
        else:
            row.value = "on" if enabled else ""
    audit.append(
        action_class="deps",
        decision="notify",
        line=f"email={'on' if enabled else 'off'} by={user.id}",
    )
    return enabled


# --- Table reads ---


def list_repo_dependencies(repo_id: int) -> list[Dependency]:
    """Dependencies tab rows: grouped by manifest, then package (D11/D18).

    Bounded at 5000 rows (far above the 20-manifest tracked ceiling for
    real repos) so a pathological manifest set cannot produce an
    unbounded page render.
    """
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(Dependency)
                .where(Dependency.repo_id == repo_id)
                .order_by(Dependency.manifest_path, Dependency.package)
                .limit(5000)
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


def latest_report(repo_id: int) -> DependencyReport | None:
    """Newest combined report for the repo ("View latest report", D11)."""
    with session_scope() as db:
        row = db.scalar(
            select(DependencyReport)
            .where(DependencyReport.repo_id == repo_id)
            .order_by(DependencyReport.id.desc())
            .limit(1)
        )
        if row is not None:
            db.expunge(row)
        return row


def get_report(report_id: int) -> DependencyReport | None:
    with session_scope() as db:
        row = db.get(DependencyReport, report_id)
        if row is not None:
            db.expunge(row)
        return row


def get_check(check_id: int) -> DependencyCheck | None:
    with session_scope() as db:
        row = db.get(DependencyCheck, check_id)
        if row is not None:
            db.expunge(row)
        return row


def append_check_note(check_id: int, line: str) -> None:
    """Append one progress line to a check's worker log, committed at once.

    Mirrors lifecycle.append_run_note: stages emit as they work so the
    detail page streams progress live. Atomic UPDATE-concat, so a
    concurrent manifest-outcome write never loses a line.
    """
    if not line:
        return
    with session_scope() as db:
        db.execute(
            update(DependencyCheck)
            .where(DependencyCheck.id == check_id)
            .values(
                notes=case(
                    (
                        or_(DependencyCheck.notes.is_(None), DependencyCheck.notes == ""),
                        literal(line),
                    ),
                    else_=DependencyCheck.notes + "\n" + line,
                )
            )
        )


# --- Silences (D21): decline-this-version + ignore-package ---


def _require_approver(user: User) -> None:
    if user.role not in (Role.OWNER, Role.MAINTAINER):
        raise PermissionError("Only an Owner or Maintainer may decide dependency updates.")


def _scoped_dep(db, dep_id: int, repo_id: int | None) -> Dependency:
    row = db.get(Dependency, dep_id)
    if row is None:
        raise ValueError(f"Unknown dependency {dep_id}.")
    if repo_id is not None and row.repo_id != repo_id:
        raise ValueError(f"Dependency {dep_id} does not belong to repo {repo_id}.")
    return row


def decline_version(
    dep_id: int, user: User, *, reason: str = "", repo_id: int | None = None
) -> Dependency:
    """Silence this specific version; a newer version re-proposes (D10/D21)."""
    _require_approver(user)
    with session_scope() as db:
        row = _scoped_dep(db, dep_id, repo_id)
        row.status = DependencyStatus.DECLINED
        row.declined_version = row.latest_version
        db.flush()
        db.expunge(row)
    audit.append(
        action_class="deps",
        decision="declined",
        line=f"dep={dep_id} version={row.latest_version} by={user.id} reason={reason or '—'}",
    )
    return row


def ignore_package(
    dep_id: int, user: User, *, reason: str = "", repo_id: int | None = None
) -> Dependency:
    """Ignore a manifest+package: still checked, never reported (D21)."""
    _require_approver(user)
    with session_scope() as db:
        row = _scoped_dep(db, dep_id, repo_id)
        row.status = DependencyStatus.IGNORED
        row.ignored_by = user.id
        row.ignored_at = datetime.now(UTC)
        db.flush()
        db.expunge(row)
    audit.append(
        action_class="deps",
        decision="ignored",
        line=f"dep={dep_id} by={user.id} reason={reason or '—'}",
    )
    return row


def unignore_package(dep_id: int, user: User, *, repo_id: int | None = None) -> Dependency:
    """Rejoin the next report if an update is available (D21)."""
    _require_approver(user)
    with session_scope() as db:
        row = _scoped_dep(db, dep_id, repo_id)
        row.status = (
            DependencyStatus.UPDATE_AVAILABLE
            if row.latest_version and row.latest_version != row.installed_version
            else DependencyStatus.UP_TO_DATE
        )
        row.ignored_by = None
        row.ignored_at = None
        db.flush()
        db.expunge(row)
    audit.append(
        action_class="deps", decision="unignored", line=f"dep={dep_id} by={user.id}"
    )
    return row


# --- Combined-report decision (D7/D10) ---


def dep_key(row: Dependency) -> str:
    """Stable report key: ecosystem|manifest|package."""
    return f"{row.ecosystem}|{row.manifest_path}|{row.package}"


def decide_report(
    report_id: int,
    decider: User,
    included_keys: list[str],
    *,
    reason: str = "",
    repo_id: int | None = None,
) -> DependencyReport:
    """One decision on the combined report (D7/D10).

    Included (ticked) packages go to patching via the worker; excluded
    (unticked) packages are declined for that specific version only.
    Approving authorizes the worker to run the existing patch flow
    (D7/D8); merge still needs the FR-9 gate, unchanged.

    Only rows still awaiting a decision (or parked at the budget cap)
    transition; a row individually silenced after the report was built
    keeps its silence and stays in undecided_keys as a disclosed
    non-actionable remainder. decided/excluded record only transitions
    that actually happened.
    """
    _require_approver(decider)
    with session_scope() as db:
        # Claim the decision atomically: exactly one approver wins the
        # pending -> decided transition; a concurrent loser sees the
        # guarded UPDATE miss and gets "already decided".
        from typing import Any, cast

        from sqlalchemy import update
        from sqlalchemy.engine import CursorResult

        claimed = db.execute(
            update(DependencyReport)
            .where(
                DependencyReport.id == report_id,
                DependencyReport.status == "pending",
            )
            .values(
                status="decided",
                decided_by=decider.id,
                decided_at=datetime.now(UTC),
                decision_reason=reason or None,
            )
        )
        if cast("CursorResult[Any]", claimed).rowcount != 1:
            existing = db.get(DependencyReport, report_id)
            if existing is None:
                raise ValueError(f"Unknown report {report_id}.")
            raise ValueError(f"Report {report_id} is already {existing.status}.")
        report = db.get(DependencyReport, report_id)
        if report is None:  # pragma: no cover - claimed above
            raise ValueError(f"Unknown report {report_id}.")
        if repo_id is not None and report.repo_id != repo_id:
            raise ValueError(f"Report {report_id} does not belong to repo {repo_id}.")
        undecided = list(report.undecided_keys or [])
        undecided_set = set(undecided)
        included = [k for k in included_keys if k in undecided_set]
        included_set = set(included)
        rows = list(
            db.scalars(
                select(Dependency).where(
                    Dependency.repo_id == report.repo_id,
                    Dependency.status.in_(
                        [
                            DependencyStatus.AWAITING_DECISION,
                            DependencyStatus.REPORT_PENDING_CAP,
                        ]
                    ),
                )
            )
        )
        actual_included: list[str] = []
        actual_excluded: list[str] = []
        for row in rows:
            key = dep_key(row)
            if key in included_set:
                row.status = DependencyStatus.PROPOSED
                actual_included.append(key)
            elif key in undecided_set:
                row.status = DependencyStatus.DECLINED
                row.declined_version = row.latest_version
                actual_excluded.append(key)
        transitioned = set(actual_included) | set(actual_excluded)
        report.status = "decided"
        report.decided_keys = actual_included
        report.excluded_keys = actual_excluded
        report.undecided_keys = [k for k in undecided if k not in transitioned]
        report.decided_by = decider.id
        report.decided_at = datetime.now(UTC)
        report.decision_reason = reason or None
        db.flush()
        db.expunge(report)
    audit.append(
        action_class="deps",
        decision="report-decided",
        line=(
            f"report={report_id} by={decider.id} role={decider.role.value} "
            f"included={len(actual_included)} excluded={len(actual_excluded)} "
            f"reason={reason or '—'}"
        ),
    )
    return report


# --- Collision with vulnerability Findings (D20) ---


def package_finding_index(repo_id: int) -> dict[str, list[Finding]]:
    """Open/proposed Findings for a repo, indexed by package (batch load).

    Loaded once per check instead of two queries per tracked package.
    """
    with session_scope() as db:
        findings = list(
            db.scalars(
                select(Finding).where(
                    Finding.repo_id == repo_id,
                    Finding.status.in_([FindingStatus.OPEN, FindingStatus.PROPOSED]),
                )
            )
        )
        index: dict[str, list[Finding]] = {}
        for finding in findings:
            db.expunge(finding)
            index.setdefault(finding.package, []).append(finding)
        return index


def live_proposal_packages(
    repo_id: int, index: dict[str, list[Finding]]
) -> set[str]:
    """Packages with a live (open) Finding Proposal, from a loaded index."""
    if not index:
        return set()
    with session_scope() as db:
        proposals = list(
            db.scalars(
                select(Proposal).where(
                    Proposal.repo_id == repo_id,
                    Proposal.status == ProposalStatus.OPEN,
                )
            )
        )
    live: set[str] = set()
    by_id = {f.id: pkg for pkg, rows in index.items() for f in rows}
    for proposal in proposals:
        for fid in proposal.finding_ids or []:
            if fid in by_id:
                live.add(by_id[fid])
    return live


def security_fix_from(
    findings: list[Finding], installed: str | None, latest: str | None
) -> Finding | None:
    """Pure form of security_fix_for over a preloaded Finding list."""
    if not installed or not latest:
        return None
    from packaging.version import InvalidVersion, Version

    try:
        installed_v, latest_v = Version(installed), Version(latest)
    except InvalidVersion:
        return None
    for finding in findings:
        for fixed in finding.fixed_versions or []:
            try:
                fixed_v = Version(str(fixed))
            except InvalidVersion:
                continue
            if installed_v < fixed_v <= latest_v:
                return finding
    return None


def live_finding_proposal(repo_id: int, package: str) -> Proposal | None:
    """Live (open) Finding Proposal bumping this package, if any (D20).

    Findings carry no manifest leg, so the match is per (repo, package):
    an open Proposal whose findings include this package blocks a
    duplicate dependency PR for it in every manifest.
    """
    with session_scope() as db:
        findings = list(
            db.scalars(
                select(Finding).where(
                    Finding.repo_id == repo_id,
                    Finding.package == package,
                    Finding.status.in_([FindingStatus.OPEN, FindingStatus.PROPOSED]),
                )
            )
        )
        if not findings:
            return None
        finding_ids = {f.id for f in findings}
        proposals = list(
            db.scalars(
                select(Proposal).where(
                    Proposal.repo_id == repo_id,
                    Proposal.status == ProposalStatus.OPEN,
                )
            )
        )
        for proposal in proposals:
            try:
                linked = set(proposal.finding_ids or [])
            except (TypeError, AttributeError):
                linked = set()
            if linked & finding_ids:
                db.expunge(proposal)
                return proposal
        return None


def security_fix_for(
    repo_id: int, package: str, installed: str | None, latest: str | None
) -> Finding | None:
    """Open Finding whose fix the target version also ships (D1/D2 tag).

    The security tag applies when a fixed version exists strictly above
    installed and at or below latest: approving latest lands the fix.
    """
    if not installed or not latest:
        return None
    from packaging.version import InvalidVersion, Version

    try:
        installed_v, latest_v = Version(installed), Version(latest)
    except InvalidVersion:
        return None
    with session_scope() as db:
        findings = list(
            db.scalars(
                select(Finding).where(
                    Finding.repo_id == repo_id,
                    Finding.package == package,
                    Finding.status.in_([FindingStatus.OPEN, FindingStatus.PROPOSED]),
                )
            )
        )
        for finding in findings:
            for fixed in finding.fixed_versions or []:
                try:
                    fixed_v = Version(str(fixed))
                except InvalidVersion:
                    continue
                if installed_v < fixed_v <= latest_v:
                    db.expunge(finding)
                    return finding
        return None
