"""Post-approval dependency patching through the existing flow (D7/D8/D20).

Approving a version rewrites the manifest spec to the approved target
(preserving existing spec style: ^1.2.3 -> ^1.9.0, exact pin ->
exact pin) and refreshes the lockfile to resolve it. Grouping is
user-initiated, agent-decided: the approver ticks single or "update
all"; the patcher decides one PR vs multiple (relatedness: same
manifest + shared lockfile/test run ride together; majors ride alone)
and discloses the grouping reason in each PR. Merge still needs the
existing FR-9 gate, unchanged.

Proposals persist as ordinary Proposal rows, so delivery (branch/PR),
the MERGE gate, and state sync are the existing machinery: delivery
never regroups dependency proposals (each rides its own PR) and keeps
their grouping disclosure. A dependency patch to a version >= a
Finding's fix supersedes that Finding's Proposal, and the rescan
resolves the Finding (D20).
"""

import json
import logging
import re
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import select

from security_agent.control.lifecycle import transition_finding
from security_agent.db.models import (
    Dependency,
    DependencyReport,
    DependencyStatus,
    Finding,
    FindingStatus,
    Proposal,
    ProposalStatus,
    Repo,
)
from security_agent.db.session import session_scope
from security_agent.sandbox import assert_host_execution_allowed, make_workdir
from security_agent.sandbox.tools import run_allowlisted
from security_agent.worker.deps_manifests import (
    DepManifest,
    load_manifest_file,
    resolve_npm_lock,
    resolve_pip_lock,
)
from security_agent.worker.patch import (
    AdaptResult,
    PatchError,
    _names_package_unsafely,
    _rewrite_pin_line,
    compare_test_runs,
    diff_files,
    diff_secret_violations,
    diff_text,
    lock_versions,
    run_python_tests,
    run_repo_tests,
)
from security_agent.worker.scan import (
    LOCKFILE_TIMEOUT_SECONDS,
    ScanError,
    clone_repo,
    normalize,
    normalize_dist_name,
    python_context,
    read_json_capped,
    read_text_capped,
    requirement_name,
    scan_lockfile,
)

log = logging.getLogger(__name__)

DEPS_GROUP_PREFIX = "deps:"

DepsAdaptHook = Callable[[Path, list[Dependency], list[str]], AdaptResult]


def null_deps_adapt(
    workdir: Path, rows: list[Dependency], failures: list[str]
) -> AdaptResult:
    """Default hook: bump-only, no code adaptation (null_adapt precedent)."""
    return AdaptResult([])


# --- Style-preserving spec bumps (D8) ---


def bump_spec_text(spec: str, target: str) -> str | None:
    """Approved-target spec preserving the existing style; None if unshaped.

    ^/~ prefixes survive, exact pins stay exact, single lower bounds
    (>=, >, ~=) move to the target, bare names pin. Multi-clause ranges
    whose upper bound excludes the target, URLs, and workspace links
    return None: the patcher reports them for a manual bump instead of
    guessing a new range.
    """
    from packaging.version import InvalidVersion, Version

    text = (spec or "").strip().strip("\"'")
    if not text or text in ("*", "latest"):
        return target  # unpinned: pin the approved target
    if text.startswith(("http:", "https:", "git+", "file:", "link:", "workspace:", "npm:")):
        return None
    if text.startswith("^"):
        return f"^{target}"
    if text.startswith("~") and not text.startswith("~="):
        return f"~{target}"
    clauses = [c.strip() for c in text.split(",") if c.strip()]
    if len(clauses) > 1:
        try:
            target_v = Version(target)
        except InvalidVersion:
            return None
        for clause in clauses:
            match = re.match(r"^(==|!=|>=|<=|>|<|~=)?\s*(.+)$", clause)
            if match is None:
                return None
            op, raw = match.group(1) or "==", match.group(2)
            try:
                other = Version(raw)
            except InvalidVersion:
                return None
            ok = {
                "==": target_v == other,
                "!=": target_v != other,
                ">": target_v > other,
                "<": target_v < other,
                ">=": target_v >= other,
                "<=": target_v <= other,
                "~=": target_v >= other,
            }[op]
            if not ok:
                return None
        return text  # complex range already admits the target: keep it
    match = re.match(r"^(==|!=|>=|<=|>|<|~=|=)?\s*(.+)$", text)
    if match is None:
        return None
    op, raw = match.group(1) or "", match.group(2)
    if op == "!=":
        return None
    if op in ("<", "<="):
        return None  # upper-bound-only specs never admit a newer target
    if op == "==":
        return f"=={target}"
    if op in ("", "="):
        return target
    return f"{op}{target}"


def apply_npm_bump_at(manifest_file: Path, package: str, target: str) -> str:
    """Rewrite one package.json spec to the target, ^/~ preserved (D8)."""
    data = read_json_capped(manifest_file)
    if data is None:
        raise PatchError(f"{manifest_file.name} unreadable, oversize, or not an object")
    for section in ("dependencies", "optionalDependencies", "devDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict) or package not in deps:
            continue
        current = str(deps[package])
        new_spec = bump_spec_text(current, target)
        if new_spec is None:
            raise PatchError(
                f"{package} uses an unbumpable spec {current!r}; upgrade manually"
            )
        deps[package] = new_spec
        manifest_file.write_text(json.dumps(data, indent=2) + "\n")
        return new_spec
    raise PatchError(f"{package} is not a direct dependency of {manifest_file.name}")


def apply_requirements_bump_at(manifest_file: Path, package: str, target: str) -> str:
    """Rewrite == pins for one requirements file (monorepo-aware, D18)."""
    from security_agent.worker.patch import _RANGE_OP_RE

    want = normalize_dist_name(package)
    text = read_text_capped(manifest_file, newline="")
    if text is None:
        raise PatchError(f"{manifest_file.name} unreadable or exceeds size cap")
    raw_lines = text.splitlines(keepends=True)
    out: list[str] = []
    dirty = False
    matched = False
    for raw in raw_lines:
        if raw.endswith("\r\n"):
            eol, line = "\r\n", raw[:-2]
        elif raw.endswith("\n"):
            eol, line = "\n", raw[:-1]
        else:
            eol, line = "", raw
        if requirement_name(line) != want:
            if _names_package_unsafely(line, want):
                raise PatchError(
                    f"{manifest_file.name}: {package} uses an unsupported declaration "
                    "(URL/editable/option); upgrade manually"
                )
            out.append(raw)
            continue
        matched = True
        new = _rewrite_pin_line(line, target)
        if new is None:
            if _RANGE_OP_RE.search(line.split("#", 1)[0]):
                raise PatchError(
                    f"{manifest_file.name}: {package} uses a version range; "
                    f"pin to =={target} manually"
                )
            raise PatchError(
                f"{manifest_file.name}: {package} line is not safely editable; "
                f"pin to =={target} manually"
            )
        out.append(new + eol)
        dirty |= new != line
    if not matched:
        raise PatchError(f"{package} is not declared in {manifest_file.name}")
    if dirty:
        try:
            manifest_file.write_text("".join(out))
        except OSError as exc:
            raise PatchError(f"{manifest_file.name} unwritable: {exc}") from exc
    return f"=={target}"


def _toml_bump_line(path: Path, package: str, target: str, kinds: tuple[str, ...]) -> str:
    """Surgical TOML bump: swap the spec substring on the package's line.

    TOML has no comment-preserving round-trip in the stdlib, so the edit
    is textual: the line naming the package keeps everything except the
    old spec text. The manifest re-parses afterwards to prove the edit.
    """
    text = read_text_capped(path, newline="")
    if text is None:
        raise PatchError(f"{path.name} unreadable or exceeds size cap")
    before = _manifest_spec_for(path, kinds, package)
    if before is None:
        raise PatchError(f"{package} is not a direct dependency of {path.name}")
    new_spec = bump_spec_text(before, target)
    if new_spec is None or new_spec == before:
        if new_spec == before:
            return before  # already admits the target
        raise PatchError(
            f"{path.name}: {package} uses an unbumpable spec {before!r}; upgrade manually"
        )
    lines = text.splitlines(keepends=True)
    swapped = False
    for i, raw in enumerate(lines):
        if package not in raw or before not in raw:
            continue
        candidate = raw.replace(before, new_spec, 1)
        trial = "".join(lines[:i] + [candidate] + lines[i + 1 :])
        import tomllib

        try:
            tomllib.loads(trial)
        except tomllib.TOMLDecodeError:
            continue
        lines[i] = candidate
        swapped = True
        break
    if not swapped:
        raise PatchError(f"{path.name}: {package} line is not safely editable")
    try:
        path.write_text("".join(lines))
    except OSError as exc:
        raise PatchError(f"{path.name} unwritable: {exc}") from exc
    after = _manifest_spec_for(path, kinds, package)
    if after != new_spec:
        raise PatchError(f"{path.name}: {package} rewrite did not take; refusing to guess")
    return new_spec


def _manifest_spec_for(path: Path, kinds: tuple[str, ...], package: str) -> str | None:
    """Current spec text for one package, re-parsed from disk."""
    _ = kinds
    manifest = load_manifest_file(path)
    if manifest is None:
        return None
    want = normalize_dist_name(package)
    for pkg in manifest.packages:
        if normalize_dist_name(pkg.name) == want:
            return pkg.spec
    return None


def apply_pyproject_bump_at(manifest_file: Path, package: str, target: str) -> str:
    """Rewrite a pyproject dependency (PEP 621, extras, or Poetry) to target."""
    return _toml_bump_line(manifest_file, package, target, ("pyproject",))


def apply_pipfile_bump_at(manifest_file: Path, package: str, target: str) -> str:
    """Rewrite a Pipfile [packages] entry to the target."""
    return _toml_bump_line(manifest_file, package, target, ("Pipfile",))


# --- Lockfile refresh ---


def refresh_npm_lockfile(manifest_dir: Path, pm: str) -> None:
    """Regenerate the Node lockfile from the bumped manifest (D8)."""
    if pm == "yarn":
        run_allowlisted(
            "yarn",
            ["install", "--ignore-scripts", "--non-interactive"],
            cwd=str(manifest_dir),
            timeout=LOCKFILE_TIMEOUT_SECONDS,
            allow_network=True,
        )
    elif pm == "pnpm":
        run_allowlisted(
            "pnpm",
            ["install", "--lockfile-only"],
            cwd=str(manifest_dir),
            timeout=LOCKFILE_TIMEOUT_SECONDS,
            allow_network=True,
        )
    else:
        run_allowlisted(
            "npm",
            ["install", "--package-lock-only", "--ignore-scripts"],
            cwd=str(manifest_dir),
            timeout=LOCKFILE_TIMEOUT_SECONDS,
            allow_network=True,
        )


def refresh_python_lockfile(manifest_dir: Path, lock_kind: str | None, manifest_kind: str) -> None:
    """Regenerate a Python lockfile with its native manager (D8/D12).

    Requirements pins ARE the manifest (no refresh step); every managed
    lock re-resolves from the bumped manifest via its pinned sandbox
    binary. Unknown lock kinds raise with manual guidance — those groups
    come back report-only, never with a half-refreshed lock.
    """
    if manifest_kind == "requirements" or lock_kind in (None, "requirements"):
        return
    commands = {
        "uv": ("uv", ["lock", "--project", str(manifest_dir)]),
        # Re-resolve the edited constraints without updating the rest.
        "poetry": ("poetry", ["lock", "--no-update", "--no-interaction"]),
        "pdm": ("pdm", ["lock"]),
        "pipfile": ("pipenv", ["lock"]),
    }
    if lock_kind not in commands:
        raise PatchError(
            f"lockfile refresh for {lock_kind} has no sandbox tool; "
            "bump the manifest and re-lock by hand"
        )
    tool, argv = commands[lock_kind]
    run_allowlisted(
        tool,
        argv,
        cwd=str(manifest_dir),
        timeout=LOCKFILE_TIMEOUT_SECONDS,
        allow_network=True,
    )


# --- Grouping (D8: agent decides, discloses why) ---


def group_approved(rows: list[Dependency]) -> list[tuple[str, list[Dependency], str]]:
    """(group_key, members, reason): same manifest rides together, majors alone.

    Relatedness for v1: one manifest means one lockfile refresh and one
    test run, so its minor/patch bumps share a PR; each major bump gets
    its own PR for isolated verification. Every PR discloses its reason.
    """
    by_manifest: dict[str, list[Dependency]] = {}
    for row in sorted(rows, key=lambda r: (r.manifest_path, r.package)):
        by_manifest.setdefault(row.manifest_path, []).append(row)
    groups: list[tuple[str, list[Dependency], str]] = []
    for manifest_path, members in sorted(by_manifest.items()):
        majors = [r for r in members if r.update_class == "major"]
        rest = [r for r in members if r.update_class != "major"]
        for major in majors:
            groups.append(
                (
                    f"{manifest_path}::major::{major.package}",
                    [major],
                    f"dependency update: {major.package} rides alone "
                    f"(major {major.installed_version}->{major.latest_version}; "
                    f"isolated verification)",
                )
            )
        if rest:
            names = ", ".join(
                f"{r.package} {r.installed_version}->{r.latest_version}" for r in rest
            )
            groups.append(
                (
                    f"{manifest_path}::updates",
                    rest,
                    f"dependency update: {names} share one PR "
                    f"(same manifest {manifest_path}, one lockfile refresh + test run)",
                )
            )
    return groups


# --- Validation (existing-patch-flow parity) ---


def _scannable_locks(workdir: Path, manifest_rel: str) -> list[Path]:
    """Lockfiles osv-scanner can rescan for this manifest's directory."""
    manifest_dir = workdir / manifest_rel
    manifest_dir = manifest_dir.parent if manifest_dir.suffix else manifest_dir
    out = []
    for name in (
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "poetry.lock",
        "Pipfile.lock",
        "pdm.lock",
        "uv.lock",
    ):
        candidate = manifest_dir / name
        try:
            if candidate.is_file():
                out.append(candidate)
        except OSError:
            continue
    return out


def _scan_keys_for(files: list[Path]) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for lock in files:
        if lock.suffix == ".txt" or lock.name in (
            "poetry.lock",
            "Pipfile.lock",
            "pdm.lock",
            "uv.lock",
        ):
            ctx = python_context([lock])
            drafts = normalize(scan_lockfile(lock), lock, set(), context=ctx)
        else:
            drafts = normalize(scan_lockfile(lock), lock, set())
        keys.update((d["package"], d["advisory_id"]) for d in drafts)
    return keys


def validate_deps_patch(
    workdir: Path,
    manifest: DepManifest,
    bumps: dict[str, str],
    allowed_extra: list[str],
    pre_keys: set[tuple[str, str]],
    fixed_keys: set[tuple[str, str]],
) -> list[str]:
    """D3-equivalent rules for dependency bumps. Returns violations."""
    violations: list[str] = []
    changed, untracked = diff_files(workdir)
    locks = {f.relative_to(workdir).as_posix() for f in _scannable_locks(workdir, manifest.rel)}
    extras = (changed | untracked) - {manifest.rel} - locks - set(allowed_extra)
    if extras:
        violations.append(f"diff touches non-dependency files: {sorted(extras)}")
    fresh = load_manifest_file(workdir / manifest.rel, workdir=workdir)
    if manifest.ecosystem == "npm" and fresh is not None:
        resolved = resolve_npm_lock(fresh)
        for package, target in bumps.items():
            if resolved.get(package) != target:
                violations.append(f"lockfile does not resolve {package}@{target}")
    elif manifest.ecosystem == "pip" and fresh is not None:
        resolved = resolve_pip_lock(fresh)
        for package, target in bumps.items():
            if manifest.kind == "requirements":
                if resolved.get(normalize_dist_name(package)) != target:
                    violations.append(f"requirements do not pin {package}=={target}")
            elif fresh.lockfile is not None:
                if resolved.get(normalize_dist_name(package)) != target:
                    violations.append(f"lockfile does not resolve {package}@{target}")
    try:
        post = _scan_keys_for(_scannable_locks(workdir, manifest.rel))
    except ScanError as exc:
        return violations + [f"rescan failed: {exc}"]
    if remaining := sorted(fixed_keys & post):
        violations.append(f"bump did not remediate {[k[1] for k in remaining]}")
    if new := sorted(post - pre_keys):
        violations.append(f"rescan introduced new advisories: {new}")
    blob = diff_text(workdir, untracked)
    violations.extend(diff_secret_violations(blob))
    return violations


# --- Approved-update execution (D7/D8) ---


@contextmanager
def _fresh_workdir(repo: Repo, source_template: Path | None):
    workdir = make_workdir("deppatch-")
    try:
        if source_template is not None:
            import shutil

            shutil.rmtree(workdir)
            shutil.copytree(source_template, workdir)
        else:
            clone_repo(repo, workdir)
        yield workdir
    finally:
        import shutil

        shutil.rmtree(workdir, ignore_errors=True)


def _pending_approved(repo_id: int, report_id: int | None) -> list[Dependency]:
    with session_scope() as db:
        query = select(Dependency).where(
            Dependency.repo_id == repo_id,
            Dependency.status == DependencyStatus.PROPOSED,
            Dependency.proposal_id.is_(None),
        )
        if report_id is not None:
            report = db.get(DependencyReport, report_id)
            keys = set((report.decided_keys or []) if report else [])
            rows = [
                r
                for r in db.scalars(query)
                if f"{r.ecosystem}|{r.manifest_path}|{r.package}" in keys
            ]
        else:
            rows = list(db.scalars(query))
        for r in rows:
            db.expunge(r)
        return rows


def _manifest_of(workdir: Path, rel: str) -> DepManifest:
    from security_agent.worker.deps_manifests import discover_dep_manifests

    manifests, _ = discover_dep_manifests(workdir)
    for manifest in manifests:
        if manifest.rel == rel:
            return manifest
    raise PatchError(f"manifest {rel} no longer present; re-run the check")


def _pm_for(lock_kind: str | None) -> str:
    return {"yarn": "yarn", "pnpm": "pnpm"}.get(lock_kind or "", "npm")


def _apply_group_bumps(
    workdir: Path, manifest: DepManifest, members: list[Dependency]
) -> dict[str, str]:
    """Bump every member; returns {package: target}."""
    bumps: dict[str, str] = {}
    manifest_file = workdir / manifest.rel
    for row in members:
        target = row.latest_version or ""
        if not target:
            raise PatchError(f"{row.package} has no latest version; re-run the check")
        if manifest.kind == "package.json":
            apply_npm_bump_at(manifest_file, row.package, target)
        elif manifest.kind == "requirements":
            apply_requirements_bump_at(manifest_file, row.package, target)
        elif manifest.kind == "pyproject":
            apply_pyproject_bump_at(manifest_file, row.package, target)
        elif manifest.kind == "Pipfile":
            apply_pipfile_bump_at(manifest_file, row.package, target)
        else:
            raise PatchError(f"unsupported manifest kind {manifest.kind}")
        bumps[row.package] = target
    if manifest.ecosystem == "npm":
        refresh_npm_lockfile(manifest_file.parent, _pm_for(manifest.lock_kind))
    else:
        refresh_python_lockfile(manifest_file.parent, manifest.lock_kind, manifest.kind)
    return bumps


def manifest_dir(workdir: Path, manifest: DepManifest) -> Path:
    return (workdir / manifest.rel).parent


def lock_for(workdir: Path, manifest: DepManifest) -> Path:
    # Manifests here are discovered in this same workdir, so the stored
    # lockfile path is already workdir-absolute when one exists.
    if manifest.lockfile is not None:
        return manifest.lockfile
    return (workdir / manifest.rel).parent / "package-lock.json"


def _persist_deps_proposal(
    repo_id: int,
    members: list[Dependency],
    bumps: dict[str, str],
    reason: str,
    verification: str,
    ignored: list[str],
    patch_text: str,
) -> int:
    with session_scope() as db:
        finding_ids: list[int] = []
        for row in members:
            if row.finding_id is not None and row.finding_id not in finding_ids:
                finding_ids.append(row.finding_id)
        summary_from = "; ".join(f"{r.package}@{r.installed_version}" for r in members)
        summary_to = "; ".join(f"{r.package}@{bumps[r.package]}" for r in members)
        proposal = Proposal(
            repo_id=repo_id,
            finding_ids=finding_ids,
            grouping_reason=f"{DEPS_GROUP_PREFIX}{reason}",
            package_from=summary_from[:100],
            package_to=summary_to[:100],
            verification_result=verification,
            ignored_tests=ignored,
            patch=patch_text,
        )
        db.add(proposal)
        db.flush()
        proposal_id = proposal.id
        for row in members:
            stored = db.get(Dependency, row.id)
            if stored is not None:
                stored.proposal_id = proposal_id
    for row in members:
        if row.finding_id is not None:
            with session_scope() as db:
                finding = db.get(Finding, row.finding_id)
                current = finding.status if finding else None
            if current == FindingStatus.OPEN:
                try:
                    transition_finding(row.finding_id, FindingStatus.PROPOSED)
                except ValueError:
                    pass  # raced with the security pipeline; the rescan owns it
    return proposal_id


def _release_group_to_available(dep_ids: list[int]) -> None:
    """Failed groups go back to update_available so the next check re-reports."""
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(Dependency).where(
                    Dependency.id.in_(dep_ids),
                    Dependency.proposal_id.is_(None),
                )
            )
        )
        for row in rows:
            row.status = DependencyStatus.UPDATE_AVAILABLE


def run_approved_updates(
    repo_id: int,
    *,
    report_id: int | None = None,
    source_dir: Path | None = None,
    adapt: DepsAdaptHook | None = None,
) -> dict:
    """Patch every approved-but-unpatched group (D7 authorizes exactly this).

    Executed by the worker after approval — never before. Each group gets
    a fresh disposable workdir: bump, lockfile refresh, adaptation hook,
    repo tests, validation, then one Proposal whose delivery rides the
    existing branch/PR + FR-9 merge gate. Groups colliding with a live
    Finding Proposal queue behind it (D20); failures release their rows
    so the next check re-reports them.
    """
    from security_agent.control.deps import live_finding_proposal

    assert_host_execution_allowed()
    hook = adapt or null_deps_adapt
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        if repo is None:
            raise ValueError(f"Unknown repo {repo_id}.")
        db.expunge(repo)
    pending = _pending_approved(repo_id, report_id)
    queued: list[str] = []
    workable: list[Dependency] = []
    for row in pending:
        if live_finding_proposal(repo_id, row.package) is not None:
            queued.append(f"{row.manifest_path}:{row.package}")
            with session_scope() as db:
                stored = db.get(Dependency, row.id)
                if stored is not None:
                    stored.status = DependencyStatus.COVERED_BY_FINDING
        else:
            workable.append(row)
    results: list[dict] = []
    for _key, members, reason in group_approved(workable):
        results.append(_patch_group(repo, members, reason, source_dir, hook))
    proposal_ids = [r["proposal_id"] for r in results if "proposal_id" in r]
    _notify_patch_result(repo_id, report_id, results, queued)
    return {"proposal_ids": proposal_ids, "results": results, "queued_behind_findings": queued}


def _patch_group(
    repo: Repo,
    members: list[Dependency],
    reason: str,
    source_template: Path | None,
    hook: DepsAdaptHook,
) -> dict:
    manifest_rel = members[0].manifest_path
    dep_ids = [r.id for r in members]
    failures: list[str] = []
    try:
        with _fresh_workdir(repo, source_template) as workdir:
            manifest = _manifest_of(workdir, manifest_rel)
            pre = _scan_keys_for(_scannable_locks(workdir, manifest_rel))
            fixed = _fixed_keys_for(members)
            baseline_proof = _baseline_tests(workdir, manifest)
            bumps = _apply_group_bumps(workdir, manifest, members)
            adapted = hook(workdir, members, list(failures))
            verification, ignored, ok = _verify_group(workdir, manifest, bumps, baseline_proof)
            if not ok:
                failures.append(verification)
                raise PatchError(verification)
            violations = validate_deps_patch(
                workdir, manifest, bumps, adapted.changed_files, pre, fixed
            )
            if violations:
                raise PatchError(f"validate: {'; '.join(violations)}")
            _changed, untracked = diff_files(workdir)
            proposal_id = _persist_deps_proposal(
                repo.id, members, bumps, reason, verification, ignored,
                diff_text(workdir, untracked),
            )
            return {
                "dep_ids": dep_ids,
                "outcome": "proposed",
                "proposal_id": proposal_id,
                "bumps": bumps,
                "grouping": reason,
            }
    except (PatchError, ScanError, RuntimeError, TimeoutError) as exc:
        failures.append(str(exc))
        _release_group_to_available(dep_ids)
        guidance = (
            f"No verified dependency patch for {manifest_rel} "
            f"({', '.join(m.package for m in members)}): {'; '.join(failures)}; "
            "upgrade manually."
        )
        log.warning("deps patch failed repo=%d: %s", repo.id, guidance)
        return {"dep_ids": dep_ids, "outcome": "failed", "reason": guidance}


def _fixed_keys_for(members: list[Dependency]) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    with session_scope() as db:
        for row in members:
            if row.finding_id is None:
                continue
            finding = db.get(Finding, row.finding_id)
            if finding is not None:
                keys.add((finding.package, finding.advisory_id))
    return keys


def _baseline_tests(workdir: Path, manifest: DepManifest):
    """Pre-bump test baseline (or None for static proof)."""
    if manifest.ecosystem == "npm":
        return run_repo_tests(manifest_dir(workdir, manifest))
    return run_python_tests(workdir)


def _verify_group(
    workdir: Path,
    manifest: DepManifest,
    bumps: dict[str, str],
    baseline: tuple[bool, str] | tuple[bool, str, str] | None,
) -> tuple[str, list[str], bool]:
    """Post-bump proof against the pre-bump baseline."""
    if manifest.ecosystem == "npm":
        if baseline is None:
            lock = lock_for(workdir, manifest)
            missing = [p for p, t in bumps.items() if t not in lock_versions(lock, p)]
            if missing:
                return f"static: lockfile lacks {missing}", [], False
            return (
                f"static analysis clean: lockfile resolves {', '.join(sorted(bumps))}",
                [],
                True,
            )
        if len(baseline) != 2:
            return "baseline shape changed mid-run", [], False
        post = run_repo_tests(manifest_dir(workdir, manifest))
        if post is None:
            return "test script vanished mid-run", [], False
        ok, ignored = compare_test_runs((baseline[0], baseline[1]), post)
        if not ok:
            return "tests failed on dependency bump", [], False
        verification = "repo tests passed"
        if ignored:
            verification += f" ({ignored[0]})"
        return verification, ignored, True
    if baseline is None:
        return f"static analysis clean: manifest pins {', '.join(sorted(bumps))}", [], True
    if len(baseline) != 3:
        return "baseline shape changed mid-run", [], False
    py_post = run_python_tests(workdir)
    if py_post is None:
        return "tests vanished mid-run", [], False
    post_ok, post_out, post_dep = py_post
    base_ok, base_out, base_dep = baseline[0], baseline[1], baseline[2]
    ok, ignored = compare_test_runs((base_ok, base_out), (post_ok, post_out))
    for note in (base_dep, post_dep):
        if note and note not in ignored:
            ignored.append(note)
    if not ok:
        return "tests failed on dependency bump", [], False
    verification = "repo tests passed"
    if ignored:
        verification += f" ({ignored[0]})"
    return verification, ignored, True


def live_dep_proposal_for_package(repo_id: int, package: str) -> Proposal | None:
    """Live (open) dependency Proposal bumping this package, if any (D20).

    The security patch flow calls this to queue behind a dependency PR
    instead of opening a second live PR for the same package.
    """
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(Dependency).where(
                    Dependency.repo_id == repo_id,
                    Dependency.package == package,
                    Dependency.proposal_id.is_not(None),
                )
            )
        )
        for row in rows:
            proposal = db.get(Proposal, row.proposal_id)
            if proposal is not None and proposal.status == ProposalStatus.OPEN:
                db.expunge(proposal)
                return proposal
        return None


def release_settled_proposals(repo_id: int) -> int:
    """Release proposed rows whose Proposal settled (merged/closed/superseded).

    Merged rows re-evaluate against the new installed version on the next
    persist (up_to_date when the clone carries the bump); closed ones go
    back to update_available for re-proposal. Runs at check start so the
    PROPOSED sticky state in persist never pins a settled row.
    """
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(Dependency).where(
                    Dependency.repo_id == repo_id,
                    Dependency.status == DependencyStatus.PROPOSED,
                    Dependency.proposal_id.is_not(None),
                )
            )
        )
        released = 0
        for row in rows:
            proposal = db.get(Proposal, row.proposal_id)
            if proposal is None or proposal.status != ProposalStatus.OPEN:
                row.status = DependencyStatus.UPDATE_AVAILABLE
                row.proposal_id = None
                released += 1
        return released


def _notify_patch_result(
    repo_id: int, report_id: int | None, results: list[dict], queued: list[str]
) -> None:
    from security_agent.control.notifications import push_notification

    if not results and not queued:
        return
    proposed = sum(1 for r in results if r.get("outcome") == "proposed")
    failed = [r for r in results if r.get("outcome") != "proposed"]
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        name = repo.name if repo else f"repo#{repo_id}"
    lines = [f"{proposed} patch group(s) proposed."]
    lines.extend(f"- failed: {r.get('reason', '')[:200]}" for r in failed)
    lines.extend(f"- queued behind Finding patch: {q}" for q in queued)
    push_notification(
        "deps-patch",
        f"{name}: approved updates patched ({proposed}/{len(results)})",
        body="\n".join(lines),
        repo_id=repo_id,
        report_id=report_id,
    )


# --- Dependency delivery (existing branch/PR + FR-9 gate) ---


def deps_branch_name(manifest_rel: str, bucket: str) -> str:
    """deps/<manifest-slug>-<bucket>-<proposal> branch (FR-5 D2 shape)."""
    from security_agent.worker.deliver import sanitize_branch_part

    slug = sanitize_branch_part(manifest_rel.replace("/", "-").removesuffix(".json"))
    return f"deps/{slug}-{sanitize_branch_part(bucket)}"


def render_deps_pr(
    bumps: list[str],
    verifications: list[str],
    grouping: str,
    ignored: list[str],
    dashboard: str,
    advisories: list[str],
) -> tuple[str, str]:
    """Deterministic dependency PR copy with the D8 grouping disclosure."""
    first = bumps[0] if bumps else "dependencies"
    title = f"[deps] {first}" + (f" (+{len(bumps) - 1} more)" if len(bumps) > 1 else "")
    lines = [f"Dependency update: {', '.join(bumps)}."]
    if advisories:
        lines.append(f"Also fixes: {', '.join(sorted(set(advisories)))}.")
    lines.extend(f"Verification: {v}" for v in verifications)
    lines.append(f"Grouping: {grouping}.")
    if ignored:
        lines.append("Ignored tests: " + "; ".join(ignored))
    lines.append(f"Dashboard: {dashboard}")
    return title, "\n".join(lines)


def run_dep_deliver(
    repo_id: int,
    *,
    source_dir: Path | None = None,
    delivery_root: Path | None = None,
) -> dict:
    """Deliver open dependency proposals (existing PR machinery, own grouping).

    Dependency proposals ride the same branch/push/PR + MERGE-gate path
    as vulnerability proposals, but delivery never regroups them: each
    patch-time group keeps its own PR and its grouping disclosure.
    """
    from security_agent.config import get_settings
    from security_agent.control.repos import get_repo_token
    from security_agent.db.models import RepoKind
    from security_agent.worker.deliver import (
        DeliverError,
        _apply_proposal_patches,
        _checkout_base,
        _commit,
        _find_pr_template,
        _provider_host,
        _push_branch,
        detect_provider,
        open_pr,
    )

    assert_host_execution_allowed()
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        if repo is None:
            raise ValueError(f"Unknown repo {repo_id}.")
        db.expunge(repo)
    root = Path(delivery_root) if delivery_root else Path("deliveries")
    dashboard = f"{get_settings().public_url}/repos/{repo_id}/dependencies"
    token = get_repo_token(repo_id) or "" if repo.kind == RepoKind.GIT else ""
    with session_scope() as db:
        pending = list(
            db.scalars(
                select(Proposal).where(
                    Proposal.repo_id == repo_id,
                    Proposal.status == ProposalStatus.OPEN,
                    Proposal.branch.is_(None),
                    Proposal.grouping_reason.like(f"{DEPS_GROUP_PREFIX}%"),
                )
            )
        )
        for p in pending:
            db.expunge(p)
    delivered: list[int] = []
    errors: list[str] = []
    notes: list[str] = []
    for proposal in pending:
        try:
            with _fresh_workdir(repo, source_dir) as workdir:
                base = _checkout_base(workdir, repo.default_branch)
                branch = f"{deps_branch_name('manifest', 'updates')}-{proposal.id}"
                run_allowlisted("git", ["checkout", "-b", branch], cwd=str(workdir))
                if not proposal.patch:
                    raise DeliverError("proposal is missing its stored patch")
                try:
                    _apply_proposal_patches(workdir, [proposal.patch])
                except RuntimeError as exc:
                    raise DeliverError(f"patch no longer applies cleanly: {exc}") from exc
                bumps = [proposal.package_to] if proposal.package_to else ["dependencies"]
                with session_scope() as db:
                    linked = list(
                        db.scalars(
                            select(Finding).where(Finding.id.in_(proposal.finding_ids or [-1]))
                        )
                    )
                    advisories = [f.advisory_id for f in linked]
                grouping = (proposal.grouping_reason or "").removeprefix(DEPS_GROUP_PREFIX)
                title, body = render_deps_pr(
                    bumps,
                    [proposal.verification_result],
                    grouping,
                    sorted(proposal.ignored_tests or []),
                    dashboard,
                    advisories,
                )
                template = _find_pr_template(workdir)
                if template:
                    _, commit_body = render_deps_pr(
                        bumps,
                        [proposal.verification_result],
                        grouping,
                        sorted(proposal.ignored_tests or []),
                        dashboard,
                        advisories,
                    )
                else:
                    commit_body = body
                signed = _commit(workdir, title, commit_body)
                if not signed:
                    notes.append(f"proposal {proposal.id} committed unsigned (no key)")
                if repo.kind == RepoKind.GIT and not token and (repo.url or "").startswith("https://"):
                    raise DeliverError("no provider token for push")
                _push_branch(workdir, branch, token)
                pr_url = ""
                provided = detect_provider(repo.url or "") if repo.kind == RepoKind.GIT else None
                if provided and token:
                    provider, slug = provided
                    pr_url = open_pr(
                        provider, slug, _provider_host(repo.url or ""), token,
                        title, body, branch, base,
                    )
                dest_dir = root / f"deps-{proposal.id}"
                dest_dir.mkdir(parents=True, exist_ok=True)
                run_allowlisted(
                    "git", ["format-patch", "-1", "HEAD", "-o", str(dest_dir)], cwd=str(workdir)
                )
                with session_scope() as db:
                    row = db.get(Proposal, proposal.id)
                    if row is not None:
                        row.branch = branch
                        row.base_branch = base
                        row.pr_url = pr_url or None
                        row.pr_state = "open" if pr_url else "branch-only"
                if pr_url:
                    from security_agent.control.gates import request_gate
                    from security_agent.db.models import GateAction

                    request_gate(
                        repo.id, GateAction.MERGE, pr_url,
                        proposal_id=proposal.id, reason="dependency update PR",
                    )
                delivered.append(proposal.id)
        except (DeliverError, RuntimeError, TimeoutError) as exc:
            errors.append(f"proposal {proposal.id}: {exc}")
    return {"proposal_ids": delivered, "errors": errors, "notes": notes}
