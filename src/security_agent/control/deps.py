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

from sqlalchemy import func, select

from security_agent.audit import get_shared_log
from security_agent.db.models import (
    Dependency,
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
DEFAULT_DEPS_TOKEN_CAP = 200_000
DEPS_SPEND_WINDOW_HOURS = 24

_DEP_HOURS_KEY = "deps.check_hours"
_DEPS_CAP_KEY = "deps.token_cap"
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


def get_deps_token_cap() -> int:
    """Install-wide dependency token budget per rolling 24h window."""
    with session_scope() as db:
        row = db.get(NotifyState, _DEPS_CAP_KEY)
        if row is not None:
            try:
                return max(1, int(row.value))
            except ValueError:
                pass
        return DEFAULT_DEPS_TOKEN_CAP


def set_deps_token_cap(value: int, user: User) -> int:
    """Owner/Maintainer raises (or lowers) the dependency budget."""
    if user.role not in (Role.OWNER, Role.MAINTAINER):
        raise PermissionError("Only an Owner or Maintainer may change the dependency budget.")
    if value < 1:
        raise ValueError("Budget must be at least 1 token.")
    with session_scope() as db:
        row = db.get(NotifyState, _DEPS_CAP_KEY)
        if row is None:
            db.add(NotifyState(key=_DEPS_CAP_KEY, value=str(value)))
        else:
            row.value = str(value)
    audit.append(
        action_class="deps",
        decision="budget",
        line=f"token_cap={value} by={user.id} role={user.role.value}",
    )
    return value


def deps_spend_window(now: datetime | None = None) -> int:
    """Dependency-ledger tokens inside the rolling 24h window."""
    from security_agent.db.models import ModelUsage

    now = now or datetime.now(UTC)
    cutoff = now - timedelta(hours=DEPS_SPEND_WINDOW_HOURS)
    with session_scope() as db:
        bind = db.get_bind()
        if bind is not None and bind.dialect.name == "sqlite":
            cutoff = cutoff.replace(tzinfo=None)
        return int(
            db.scalar(
                select(func.coalesce(func.sum(ModelUsage.total_tokens), 0)).where(
                    ModelUsage.task.like("deps-%"),
                    ModelUsage.created_at >= cutoff,
                )
            )
            or 0
        )


def record_deps_usage(
    task: str, prompt_tokens: int, completion_tokens: int, *, estimated: bool = False
) -> dict:
    """Ledger one dependency model call; raise when the budget is hit.

    Dependency usage rides ModelUsage with a `deps-` task prefix and a
    NULL run id, so it never touches the security pipeline's per-run
    caps or daily spend alerts (D23 independence both ways).
    """
    from security_agent.config import get_settings
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
    spent = deps_spend_window()
    cap = get_deps_token_cap()
    if spent >= cap:
        raise DepsBudgetExceeded(f"dependency budget hit ({spent}/{cap} tokens)")
    return {"total": total, "spent": spent, "cap": cap}


def deps_budget_state() -> dict:
    """Current budget triple for the Settings page and the tab banner."""
    spent = deps_spend_window()
    cap = get_deps_token_cap()
    return {"spent": spent, "cap": cap, "exhausted": spent >= cap}


def deps_notify_email_enabled() -> bool:
    """Whether dependency pool entries also fan out by email (D16 opt-in)."""
    with session_scope() as db:
        row = db.get(NotifyState, _DEPS_NOTIFY_EMAIL_KEY)
        return row is not None and row.value == "on"


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
    """Dependencies tab rows: grouped by manifest, then package (D11/D18)."""
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(Dependency)
                .where(Dependency.repo_id == repo_id)
                .order_by(Dependency.manifest_path, Dependency.package)
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


# --- Silences (D21): decline-this-version + ignore-package ---


def _require_approver(user: User) -> None:
    if user.role not in (Role.OWNER, Role.MAINTAINER):
        raise PermissionError("Only an Owner or Maintainer may decide dependency updates.")


def decline_version(dep_id: int, user: User, *, reason: str = "") -> Dependency:
    """Silence this specific version; a newer version re-proposes (D10/D21)."""
    _require_approver(user)
    with session_scope() as db:
        row = db.get(Dependency, dep_id)
        if row is None:
            raise ValueError(f"Unknown dependency {dep_id}.")
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


def ignore_package(dep_id: int, user: User, *, reason: str = "") -> Dependency:
    """Ignore a manifest+package: still checked, never reported (D21)."""
    _require_approver(user)
    with session_scope() as db:
        row = db.get(Dependency, dep_id)
        if row is None:
            raise ValueError(f"Unknown dependency {dep_id}.")
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


def unignore_package(dep_id: int, user: User) -> Dependency:
    """Rejoin the next report if an update is available (D21)."""
    _require_approver(user)
    with session_scope() as db:
        row = db.get(Dependency, dep_id)
        if row is None:
            raise ValueError(f"Unknown dependency {dep_id}.")
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
) -> DependencyReport:
    """One decision on the combined report (D7/D10).

    Included (ticked) packages go to patching via the worker; excluded
    (unticked) packages are declined for that specific version only.
    Approving authorizes the worker to run the existing patch flow
    (D7/D8); merge still needs the FR-9 gate, unchanged.
    """
    _require_approver(decider)
    with session_scope() as db:
        report = db.get(DependencyReport, report_id)
        if report is None:
            raise ValueError(f"Unknown report {report_id}.")
        if report.status != "pending":
            raise ValueError(f"Report {report_id} is already {report.status}.")
        undecided = list(report.undecided_keys or [])
        included = [k for k in included_keys if k in undecided]
        excluded = [k for k in undecided if k not in set(included)]
        report.status = "decided"
        report.decided_keys = included
        report.excluded_keys = excluded
        report.decided_by = decider.id
        report.decided_at = datetime.now(UTC)
        report.decision_reason = reason or None
        rows = list(
            db.scalars(
                select(Dependency).where(
                    Dependency.repo_id == report.repo_id,
                    Dependency.status == DependencyStatus.AWAITING_DECISION,
                )
            )
        )
        for row in rows:
            key = f"{row.ecosystem}|{row.manifest_path}|{row.package}"
            if key in set(included):
                row.status = DependencyStatus.PROPOSED
            elif key in set(excluded):
                row.status = DependencyStatus.DECLINED
                row.declined_version = row.latest_version
        db.flush()
        db.expunge(report)
    audit.append(
        action_class="deps",
        decision="report-decided",
        line=(
            f"report={report_id} by={decider.id} role={decider.role.value} "
            f"included={len(included)} excluded={len(excluded)} reason={reason or '—'}"
        ),
    )
    return report


# --- Collision with vulnerability Findings (D20) ---


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
