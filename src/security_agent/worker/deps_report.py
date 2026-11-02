"""Combined impact reports: read-only evidence + model summary (D6/D9).

Before any approval and before any code is touched, the model produces
a summary impact report for the proposed updates, and that report is
what guides the user's decision. Read-only work only:

(1) upstream evidence — version diff, update class, wanted (in-range)
    alternative, repository link when the native tooling reports one,
    breaking-change flags (a major bump is presumed breaking);
    changelogs the tooling cannot retrieve are a NAMED UNKNOWN, never
    invented;
(2) repo usage — import/require/call sites in first-party code as
    file:line, via the allowlisted ripgrep tool;
(3) a model-written summary assessment citing (1) and (2) and
    explicitly marking what could not be determined.

No bump, adaptation, or test-run happens before approval. When the
model is disabled, keyless, or misses, a deterministic evidence
template stands in (model_backed=False); when the dependency budget is
hit, report generation parks with `report_pending_cap` (D23) and the
next check retries because the update set remains unreported.
"""

import logging
import re

from sqlalchemy import select

from security_agent.db.models import (
    Dependency,
    DependencyReport,
    DependencyStatus,
    Finding,
)
from security_agent.db.session import session_scope
from security_agent.prompts import render_prompt
from security_agent.sandbox.tools import run_allowlisted

log = logging.getLogger(__name__)

MAX_USAGE_SITES = 50
MAX_SUMMARY_WORDS = 400
_SUMMARY_MAX_CHARS = 8000

_RG_GLOB_EXCLUDES = (
    "--glob",
    "!node_modules/**",
    "--glob",
    "!.venv/**",
    "--glob",
    "!venv/**",
    "--glob",
    "!.git/**",
    "--glob",
    "!package-lock.json",
    "--glob",
    "!yarn.lock",
    "--glob",
    "!pnpm-lock.yaml",
    "--glob",
    "!*.lock",
)


def npm_usage_patterns(package: str) -> list[str]:
    """Import/require call-site patterns for one npm package."""
    escaped = re.escape(package)
    return [
        rf"require\(\s*['\"]{escaped}(/|\.|['\"])",
        rf"from\s+['\"]{escaped}(/|\.|['\"])",
        rf"import\(\s*['\"]{escaped}(/|\.|['\"])",
        rf"import\s+['\"]{escaped}(/|\.|['\"])",
    ]


def pip_usage_patterns(package: str) -> list[str]:
    """Import patterns for one pip distribution (module form)."""
    module = re.escape(package.replace("-", "_").replace(".", "_").lower())
    return [
        rf"^\s*import\s+{module}(\s|,|$|\.)",
        rf"^\s*from\s+{module}(\s|\.|$)",
    ]


def gather_usage(workdir: str, ecosystem: str, package: str) -> list[str]:
    """First-party file:line usage sites, capped (D6 evidence 2).

    Ripgrep failures degrade to an empty site list with the failure
    recorded by the caller — a failing search must never fail the
    report, only narrow its evidence.
    """
    patterns = (
        npm_usage_patterns(package)
        if ecosystem == "npm"
        else pip_usage_patterns(package)
    )
    # One ripgrep container per package: all patterns as -e alternatives.
    args: list[str] = []
    for pattern in patterns:
        args.extend(["-e", pattern])
    args.append(workdir)
    args.extend(_RG_GLOB_EXCLUDES)
    try:
        out = run_allowlisted("ripgrep", args, cwd=workdir)
    except (RuntimeError, TimeoutError, ValueError) as exc:
        log.debug("usage search failed for %s: %s", package, exc)
        return []
    sites: list[str] = []
    seen: set[str] = set()
    for line in (out or "").splitlines():
        text = line.strip()
        if not text or len(sites) >= MAX_USAGE_SITES:
            break
        # rg --line-number prints path:line:match; keep path:line.
        parts = text.split(":", 2)
        if len(parts) >= 2:
            site = f"{parts[0]}:{parts[1]}"
            if site not in seen:
                seen.add(site)
                sites.append(site)
    return sites


def _segment_count(text: str) -> int:
    """Numeric release segments in a partial version (1 -> 1, 1.2.x -> 2)."""
    count = 0
    for part in text.strip().lstrip("vV").split("."):
        if part.isdigit():
            count += 1
        else:
            break
    return max(count, 1)


def satisfies_npm_range(spec: str, version: str) -> bool | None:
    """Whether an npm range admits a version; None when unknowable.

    Covers ^, ~ (including partials like ~1), exact, x-ranges, hyphen
    ranges, || unions, and simple comparator sets; tags and URLs return
    None (the report marks them undetermined).
    """
    from packaging.version import InvalidVersion, Version

    try:
        target = Version(version)
    except InvalidVersion:
        return None
    text = (spec or "").strip()
    if not text or text in ("*", "latest"):
        return True
    if text.startswith(("http", "git+", "file:", "link:", "workspace:", "npm:")):
        return None
    if "||" in text:
        verdicts = [satisfies_npm_range(part, version) for part in text.split("||")]
        if any(v is True for v in verdicts):
            return True
        if all(v is False for v in verdicts):
            return False
        return None
    if " - " in text:
        low_text, high_text = (p.strip() for p in text.split(" - ", 1))
        try:
            low = Version(low_text)
            high = Version(high_text)
        except InvalidVersion:
            return None
        if _segment_count(high_text) == 1:
            high_ok = target < Version(f"{list(high.release)[0] + 1}.0.0")
        elif _segment_count(high_text) == 2:
            rel = list(high.release) + [0]
            high_ok = target < Version(f"{rel[0]}.{rel[1] + 1}.0")
        else:
            high_ok = target <= high
        return low <= target and high_ok
    if text.startswith("^"):
        try:
            base = Version(text[1:])
        except InvalidVersion:
            return None
        release = list(base.release) + [0, 0, 0]
        if release[0] != 0:
            upper = Version(f"{release[0] + 1}.0.0")
        elif release[1] != 0:
            upper = Version(f"0.{release[1] + 1}.0")
        else:
            upper = Version(f"0.0.{release[2] + 1}")
        return base <= target < upper
    if text.startswith("~"):
        base_text = text[1:]
        try:
            base = Version(base_text)
        except InvalidVersion:
            return None
        release = list(base.release) + [0, 0]
        if _segment_count(base_text) == 1:
            upper = Version(f"{release[0] + 1}.0.0")
        else:
            upper = Version(f"{release[0]}.{release[1] + 1}.0")
        return base <= target < upper
    if "," in text:
        verdicts = [satisfies_npm_range(clause, version) for clause in text.split(",")]
        if all(v is True for v in verdicts):
            return True
        if any(v is False for v in verdicts):
            return False
        return None
    parts = text.split()
    if len(parts) == 1:
        only = parts[0]
        comparator = re.match(r"^(>=|<=|>|<)(.+)$", only)
        if comparator:
            try:
                other = Version(comparator.group(2))
            except InvalidVersion:
                return None
            return {
                ">": target > other,
                "<": target < other,
                ">=": target >= other,
                "<=": target <= other,
            }[comparator.group(1)]
        if any(seg in ("x", "X", "*") for seg in only.lstrip("=vV").split(".")):
            wanted = [
                int(seg) for seg in only.lstrip("=vV").split(".") if seg.isdigit()
            ]
            actual = list(target.release)
            return actual[: len(wanted)] == wanted
        if only and (only[0].isdigit() or only[0] in "vV="):
            try:
                return target == Version(only.lstrip("=vV"))
            except InvalidVersion:
                return None
        return None  # dist-tag or other non-version spec
    result: bool | None = True
    for part in parts:
        match = re.match(r"^(>=|<=|>|<|=)?(.+)$", part)
        if match is None:
            return None
        op, raw = match.group(1) or "=", match.group(2)
        try:
            other = Version(raw)
        except InvalidVersion:
            return None
        ok = {
            "=": target == other,
            ">": target > other,
            "<": target < other,
            ">=": target >= other,
            "<=": target <= other,
        }[op]
        result = result and ok
    return result


def build_section(
    dep: Dependency,
    *,
    usage_sites: list[str] | None = None,
    peer_ranges: dict[str, str] | None = None,
    repo_url: str | None = None,
    advisories: list[str] | None = None,
) -> dict:
    """One per-package impact section (D6 evidence 1+2, D9/D22 notes)."""
    peer_note = ""
    if peer_ranges and dep.package in peer_ranges and dep.latest_version:
        verdict = satisfies_npm_range(peer_ranges[dep.package], dep.latest_version)
        if verdict is False:
            peer_note = (
                f"peer range {peer_ranges[dep.package]!r} excludes latest "
                f"{dep.latest_version}; the peered package needs a matching bump"
            )
        elif verdict is None:
            peer_note = (
                f"peer range {peer_ranges[dep.package]!r} could not be checked "
                "against latest (UNDETERMINED)"
            )
    anchor = re.sub(
        r"[^a-z0-9]+", "-", f"{dep.manifest_path}-{dep.package}".lower()
    ).strip("-")
    breaking = ""
    if dep.update_class == "major":
        breaking = "major bump: presumed breaking until the changelog says otherwise"
    wanted_note = ""
    if dep.wanted_version and dep.wanted_version != dep.latest_version:
        wanted_note = (
            f"in-range alternative {dep.wanted_version} exists; "
            f"proposing absolute latest {dep.latest_version} (D13)"
        )
    return {
        "key": f"{dep.ecosystem}|{dep.manifest_path}|{dep.package}",
        "anchor": f"pkg-{anchor or 'update'}",
        "package": dep.package,
        "ecosystem": dep.ecosystem,
        "manifest_path": dep.manifest_path,
        "section": dep.section,
        "manifest_spec": dep.manifest_spec,
        "installed": dep.installed_version,
        "wanted": dep.wanted_version,
        "latest": dep.latest_version,
        "update_class": dep.update_class,
        "security": dep.security,
        "advisories": advisories or [],
        "usage_sites": usage_sites or [],
        "repo_url": repo_url,
        "peer_note": peer_note,
        "breaking_flag": breaking,
        "wanted_note": wanted_note,
        "changelog": "UNDETERMINED: changelog not retrieved by native tooling",
    }


MAX_PROMPT_SECTIONS = 100  # prompt stays bounded on mega-reports


def _section_prompt_text(sections: list[dict]) -> str:
    lines = []
    shown = sections[:MAX_PROMPT_SECTIONS]
    for section in shown:
        lines.append(
            "- {package} ({ecosystem}, {manifest}): {installed} -> {latest} "
            "({update_class}); wanted={wanted}; security={security} "
            "{advisories}; usage={usage}; {peer}{breaking}{wanted_note}".format(
                package=section.get("package"),
                ecosystem=section.get("ecosystem"),
                manifest=section.get("manifest_path"),
                installed=section.get("installed") or "unknown",
                latest=section.get("latest"),
                update_class=section.get("update_class") or "unknown class",
                wanted=section.get("wanted") or "none",
                security="yes" if section.get("security") else "no",
                advisories=", ".join(section.get("advisories") or []) or "no advisories",
                usage=", ".join(section.get("usage_sites") or []) or "no sites found",
                peer=f"peer: {section['peer_note']}; " if section.get("peer_note") else "",
                breaking=f"{section['breaking_flag']}; "
                if section.get("breaking_flag")
                else "",
                wanted_note=section.get("wanted_note") or "",
            )
        )
    if len(sections) > MAX_PROMPT_SECTIONS:
        lines.append(
            f"({len(sections) - MAX_PROMPT_SECTIONS} further updates omitted "
            "from this prompt for size; they are in the report sections.)"
        )
    lines.append(
        "Changelogs were NOT retrieved: mark every changelog-dependent "
        "claim UNDETERMINED. Yanked releases are invisible to pip index "
        "output: mark yanked-risk UNDETERMINED for pip packages."
    )
    return "\n".join(lines)


def fallback_summary(sections: list[dict]) -> str:
    """Deterministic evidence template when the model is unavailable."""
    lines = [
        "Dependency update impact (template fallback — no model summary was generated)."
    ]
    for section in sections:
        verdict = "likely affected" if section.get("update_class") == "major" else "likely safe"
        lines.append(
            f"- {section.get('package')} {section.get('installed') or '?'} -> "
            f"{section.get('latest')} ({section.get('update_class') or 'unknown'}): "
            f"{verdict} — {len(section.get('usage_sites') or [])} usage site(s); "
            "changelog UNDETERMINED."
        )
        if section.get("wanted_note"):
            lines.append(f"  {section['wanted_note']}")
        if section.get("peer_note"):
            lines.append(f"  {section['peer_note']}")
    lines.append("Risks and unknowns: changelogs not retrieved (UNDETERMINED).")
    return "\n".join(lines)[:_SUMMARY_MAX_CHARS]


class ReportError(RuntimeError):
    """Report step failed (model outage): table updates, next check retries (D23)."""


def generate_summary(
    sections: list[dict], *, model=None, task: str = "report"
) -> tuple[str, bool]:
    """Model-written summary (D6.3) or the deterministic fallback.

    Disabled/keyless/empty output falls back to the evidence template
    (model_backed=False) and the report still ships. A model outage
    (invoke raising) raises ReportError instead: the report step fails,
    the error is recorded, the table still updates, and the next check
    retries because the update set remains unreported (D23). Usage
    ledgers to the separate dependency budget; a hit raises
    DepsBudgetExceeded past the fallback so the caller parks the report.

    An explicitly injected model skips the enabled/key gate so tests can
    drive this deterministically.
    """
    from security_agent.brain import get_chat_model
    from security_agent.config import get_settings

    if model is None:
        settings = get_settings()
        if not settings.deps_report_model_enabled or not settings.model_api_key:
            return fallback_summary(sections), False
        bound = get_chat_model()
    else:
        bound = model
    # Pre-check: never pay for a call the budget will only park (D23).
    from security_agent.control.deps import DepsBudgetExceeded, deps_budget_state

    budget = deps_budget_state()
    if budget["exhausted"]:
        raise DepsBudgetExceeded(
            f"dependency budget hit ({budget['spent']}/{budget['cap']} tokens)"
        )
    prompt = render_prompt(
        "deps_summary",
        max_words=str(MAX_SUMMARY_WORDS),
        sections=_section_prompt_text(sections),
    )
    try:
        result = bound.invoke(prompt)
    except Exception as exc:
        raise ReportError(f"model outage: {exc}") from exc
    content = str(getattr(result, "content", "") or "").strip()
    usage = getattr(result, "usage_metadata", None) or {}
    prompt_tokens = usage.get("input_tokens") or max(1, len(prompt) // 4)
    completion_tokens = usage.get("output_tokens") or max(1, len(content) // 4)
    estimated = not usage.get("input_tokens") or not usage.get("output_tokens")
    from security_agent.control.deps import DepsBudgetExceeded, record_deps_usage

    try:
        record_deps_usage(
            task, int(prompt_tokens), int(completion_tokens), estimated=bool(estimated)
        )
    except DepsBudgetExceeded:
        raise
    except Exception as exc:  # noqa: BLE001 - ledger miss falls back, never fails
        log.warning("dependency usage ledger failed: %s", exc)
    if not content:
        return fallback_summary(sections), False
    return content[:_SUMMARY_MAX_CHARS], True


def create_report(
    repo_id: int,
    check_id: int | None,
    sections: list[dict],
    summary: str,
    *,
    model_backed: bool,
    update_set_hash: str,
) -> DependencyReport:
    """Persist the combined report; rows move to awaiting_decision (D7/D9).

    Older pending reports for the repo are superseded: the newest report
    is the single decision point (D9), and re-proposals carry fresh
    impact sections (D7/D10).
    """
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
        report = DependencyReport(
            repo_id=repo_id,
            check_id=check_id,
            status="pending",
            summary=summary,
            sections=sections,
            update_set_hash=update_set_hash,
            model_backed=model_backed,
            undecided_keys=[s["key"] for s in sections],
        )
        db.add(report)
        db.flush()
        keys = {s["key"] for s in sections}
        rows = list(
            db.scalars(
                select(Dependency).where(
                    Dependency.repo_id == repo_id,
                    Dependency.status.in_(
                        [
                            DependencyStatus.UPDATE_AVAILABLE,
                            DependencyStatus.REPORT_PENDING_CAP,
                        ]
                    ),
                )
            )
        )
        for row in rows:
            if f"{row.ecosystem}|{row.manifest_path}|{row.package}" in keys:
                row.status = DependencyStatus.AWAITING_DECISION
        db.flush()
        db.expunge(report)
        return report


def advisories_for_finding(finding_id: int | None) -> list[str]:
    """Advisory ids (canonical + aliases) for a linked Finding."""
    if finding_id is None:
        return []
    with session_scope() as db:
        finding = db.get(Finding, finding_id)
        if finding is None:
            return []
        out = [finding.advisory_id, *(finding.aliases or [])]
        db.expunge(finding)
        return [str(a) for a in out if a]
