"""Bump-first patch generation with mechanical verification (FR-4).

Deterministic pipeline per reachable finding: version select → bump →
refresh lock → adapt hook → verify (repo tests or static) → validate
(diff scope, lockfile, rescan, secrets) → proposal. Up to 3 rounds across
adapt retries and alternate versions (FR-4 D6); exhaustion yields
report-only unpatchable with guidance (FR-4 D4).

Code adaptation is an injected hook defaulting to no-op; the model-backed
adapter plugs in here once live-model validation is available.
"""

import json
import logging
import os
import re
import shutil
import threading
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select

from security_agent.control.lifecycle import append_run_note, reopen_run, transition_finding
from security_agent.db.models import (
    Finding,
    FindingStatus,
    Proposal,
    Repo,
    ScanRun,
    Verdict,
)
from security_agent.db.session import session_scope
from security_agent.sandbox import assert_host_execution_allowed, make_workdir
from security_agent.sandbox.tools import run_allowlisted
from security_agent.worker.deps_manifests import DepManifest, resolve_npm_lock
from security_agent.worker.scan import (
    LOCKFILE_TIMEOUT_SECONDS,
    MAX_PYTHON_MANIFESTS,
    NODE_LOCK_KINDS,
    NODE_LOCK_NAMES,
    PYTHON_LOCK_NAMES,
    ScanError,
    clone_repo,
    discover_python_manifests,
    ensure_lockfile,
    ensure_python_lockfiles,
    normalize,
    normalize_dist_name,
    python_context,
    python_generation_pending,
    read_json_capped,
    read_text_capped,
    requirement_name,
    scan_lockfile,
    valid_fixed_version,
)

MAX_ROUNDS = 3
TEST_TIMEOUT = 600
_DIFF_TEXT_CAP = 200_000

log = logging.getLogger(__name__)

_DEP_SECTIONS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")

# High-precision marker backstop; the Betterleaks engine runs first when the
# binary is present (follow-up #17), markers always run as defense in depth.
_SECRET_MARKERS = (
    "AKIA",
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "ghp_",
    "gho_",
    "xoxb-",
    "xoxp-",
)


def diff_secret_violations(blob: str) -> list[str]:
    """Secret violations for a patch diff: engine + marker backstop.

    The Betterleaks engine (detection-only, no validation) runs when the
    binary is present; markers always run. Engine errors degrade to markers
    rather than failing validation — the check must never block on tooling.
    """
    from security_agent.worker import secrets as secrets_mod

    hits: list[str] = []
    if secrets_mod.betterleaks_available():
        try:
            hits.extend(f"rule:{rule}" for rule in secrets_mod.scan_diff_blob(blob))
        except Exception as exc:  # noqa: BLE001 - engine failure degrades to markers
            log.warning("diff secret engine failed, using markers: %s", exc)
    hits.extend(sorted({m for m in _SECRET_MARKERS if m in blob}))
    if hits:
        return [f"possible secret in diff: {hits}"]
    return []


class PatchError(RuntimeError):
    """Expected patch failure for one attempt: try the next round."""


@dataclass
class AdaptResult:
    changed_files: list[str]
    notes: str = ""


AdaptHook = Callable[[Path, Finding, str, list[str]], AdaptResult]


def null_adapt(workdir: Path, finding: Finding, target: str, failures: list[str]) -> AdaptResult:
    """Default hook: bump-only, no code adaptation."""
    return AdaptResult([])


def _read_manifest(workdir: Path) -> dict:
    manifest = read_json_capped(workdir / "package.json")
    if manifest is None:
        raise PatchError("package.json unreadable, oversize, or not an object")
    return manifest


def root_npm_kind(workdir: Path) -> str:
    """Lock kind at the repo root: package-lock | yarn | pnpm.

    Same preference order as scan discovery; no lock at all keeps the
    legacy npm path (package-lock.json is generated on demand).
    """
    for name in NODE_LOCK_NAMES:
        kind = NODE_LOCK_KINDS.get(name)
        if kind is None:
            continue
        try:
            if (workdir / name).is_file():
                return kind
        except OSError:
            continue
    return "package-lock"


_KIND_TO_LOCK = {
    "package-lock": "package-lock.json",
    "yarn": "yarn.lock",
    "pnpm": "pnpm-lock.yaml",
}

_YARN_BERRY_LITTER = (".yarn", ".pnp.cjs", ".pnp.loader.mjs", ".pnp.data.json")


def _yarn_major(workdir: Path) -> int:
    """Yarn major version (1 classic, else berry); PatchError when unknown."""
    out = run_allowlisted(
        "yarn",
        ["--version"],
        cwd=str(workdir),
        timeout=LOCKFILE_TIMEOUT_SECONDS,
        allow_network=True,
    )
    try:
        return int(out.strip().splitlines()[0].split(".")[0])
    except (IndexError, ValueError):
        raise PatchError(f"could not determine yarn version (output: {out[:50]!r})") from None


def apply_bump(workdir: Path, package: str, target: str, kind: str = "package-lock") -> None:
    """Rewrite the package range (^/~ preserved); transitive deps via overrides.

    Transitive bumps on yarn/pnpm refuse: npm-style `overrides` do not
    take effect there (yarn `resolutions` / pnpm `pnpm.overrides` need a
    manual entry), so attempting one would only validate a no-op patch.
    """
    manifest = _read_manifest(workdir)
    found = False
    for section in _DEP_SECTIONS:
        deps = manifest.get(section)
        if not isinstance(deps, dict) or package not in deps:
            continue
        current = str(deps[package])
        prefix = current[0] if current[:1] in ("^", "~") else ""
        deps[package] = f"{prefix}{target}"
        found = True
    if not found:
        if kind == "yarn":
            raise PatchError(
                f"{package} is transitive (or nested); yarn needs a manual "
                f"`resolutions` entry for {package}@{target}, then re-lock"
            )
        if kind == "pnpm":
            raise PatchError(
                f"{package} is transitive (or nested); pnpm needs a manual "
                f"`pnpm.overrides` entry for {package}@{target}, then re-lock"
            )
        overrides = manifest.setdefault("overrides", {})
        if not isinstance(overrides, dict):
            raise PatchError("package.json overrides is not an object")
        overrides[package] = target
    (workdir / "package.json").write_text(json.dumps(manifest, indent=2) + "\n")


def refresh_lockfile(workdir: Path, kind: str = "package-lock") -> None:
    """Re-resolve the root lockfile with its native manager, scripts disabled."""
    if kind == "pnpm":
        run_allowlisted(
            "pnpm",
            ["install", "--lockfile-only", "--ignore-scripts"],
            cwd=str(workdir),
            timeout=LOCKFILE_TIMEOUT_SECONDS,
            allow_network=True,
        )
        return
    if kind == "yarn":
        if _yarn_major(workdir) == 1:
            run_allowlisted(
                "yarn",
                ["install", "--ignore-scripts"],
                cwd=str(workdir),
                timeout=LOCKFILE_TIMEOUT_SECONDS,
                allow_network=True,
            )
            return
        had = {name for name in _YARN_BERRY_LITTER if (workdir / name).exists()}
        run_allowlisted(
            "yarn",
            ["install", "--mode", "skip-build", "--no-immutable"],
            cwd=str(workdir),
            timeout=LOCKFILE_TIMEOUT_SECONDS,
            allow_network=True,
        )
        for name in _YARN_BERRY_LITTER:
            if name in had:
                continue  # pre-existing berry state (e.g. zero-installs) stays
            candidate = workdir / name
            try:
                if candidate.is_dir() and not candidate.is_symlink():
                    shutil.rmtree(candidate)
                else:
                    candidate.unlink(missing_ok=True)
            except OSError:
                continue
        return
    run_allowlisted(
        "npm",
        ["install", "--package-lock-only", "--ignore-scripts"],
        cwd=str(workdir),
        timeout=LOCKFILE_TIMEOUT_SECONDS,
        allow_network=True,
    )


def npm_lock_resolves(lockfile: Path, kind: str, package: str, target: str) -> bool:
    """True when the lockfile resolves package at target (native parsers)."""
    if kind == "package-lock":
        return target in lock_versions(lockfile, package)
    resolved = resolve_npm_lock(
        DepManifest(
            path=lockfile,
            rel=lockfile.name,
            ecosystem="npm",
            kind="package.json",
            lockfile=lockfile,
            lock_kind=kind,
        )
    )
    return resolved.get(package) == target


def ensure_test_deps(workdir: Path) -> None:
    """Install test dependencies (clean, scripts disabled) when absent.

    Without this, `npm test` fails identically before and after the bump
    and the failure-comparison proof is vacuous.
    """
    if (workdir / "node_modules").is_dir():
        return
    if not (workdir / "package-lock.json").is_file():
        return  # nothing reproducible to install; tests run as-is
    try:
        run_allowlisted(
            "npm",
            ["ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            cwd=str(workdir),
            timeout=TEST_TIMEOUT,
            allow_network=True,
        )
    except (RuntimeError, TimeoutError) as exc:
        raise PatchError(f"test dependency install failed: {exc}") from exc


def run_repo_tests(workdir: Path) -> tuple[bool, str] | None:
    """(passed, output), or None when the repo has no test script."""
    try:
        scripts = _read_manifest(workdir).get("scripts", {})
    except PatchError:
        return None
    if not isinstance(scripts, dict) or "test" not in scripts:
        return None
    ensure_test_deps(workdir)
    out = run_allowlisted("npm", ["test"], cwd=str(workdir), timeout=TEST_TIMEOUT, check=False)
    return (not out.startswith("[exit "), out)


_VOLATILE_OUTPUT_RES = (
    (re.compile(r"\b(?:patch|reach-\d+|scan-\d+)-[A-Za-z0-9_.-]+"), "<workdir>"),
    (re.compile(r"/(?:private/)?(?:var/folders|tmp)/\S*"), "<tmp>"),
    (re.compile(r"\b\d+\.\d+s\b"), "Ns"),
)


def _normalize_test_output(out: str) -> str:
    """Scrub run-specific tokens (temp workdirs, durations) before comparison.

    Baseline and post runs execute in distinct mkdtemp workdirs, so raw
    byte-equality is near-unreachable on real pytest output; anything else
    must still match exactly, and mismatches fail loud as regressions.
    """
    for pattern, replacement in _VOLATILE_OUTPUT_RES:
        out = pattern.sub(replacement, out)
    return out


def compare_test_runs(baseline: tuple[bool, str], post: tuple[bool, str]) -> tuple[bool, list[str]]:
    """Related-failures-only, mechanically: identical failure output is pre-existing."""
    post_ok, post_out = post
    base_ok, base_out = baseline
    if post_ok:
        return True, []
    if not base_ok and _normalize_test_output(post_out) == _normalize_test_output(base_out):
        return True, ["pre-existing failures unchanged by bump (output identical)"]
    return False, []


def lock_versions(lockfile: Path, package: str) -> set[str]:
    data = read_json_capped(lockfile)
    packages = data.get("packages", {}) if data else {}
    if not isinstance(packages, dict):
        return set()
    versions: set[str] = set()
    for key, entry in packages.items():
        if not key or not isinstance(entry, dict):
            continue
        segments = [s.strip("/") for s in key.split("node_modules/") if s.strip("/")]
        if segments and segments[-1] == package and entry.get("version"):
            versions.add(str(entry["version"]))
    return versions


_DIFF_IGNORED_TOPS = frozenset({"node_modules", ".pip-deps", ".venv", "venv", ".pytest_cache"})


def diff_files(workdir: Path) -> tuple[set[str], set[str]]:
    """(tracked-changed, untracked) workdir-relative paths via git status."""
    out = run_allowlisted("git", ["status", "--porcelain=v1", "-uall", "--", "."], cwd=str(workdir))
    changed: set[str] = set()
    untracked: set[str] = set()
    for line in out.splitlines():
        if len(line) < 4:
            continue
        path = line[3:]
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        if path.split("/", 1)[0] in _DIFF_IGNORED_TOPS or "/__pycache__/" in f"/{path}":
            continue  # test-dependency installs and bytecode caches are not the patch
        (untracked if line.startswith("??") else changed).add(path)
    return changed, untracked


def diff_text(workdir: Path, untracked: set[str]) -> str:
    """Tracked diff plus untracked-file contents (capped), for delivery + secrets."""
    parts = [run_allowlisted("git", ["diff", "HEAD", "--", "."], cwd=str(workdir))]
    total = len(parts[0])
    for rel in sorted(untracked):
        candidate = workdir / rel
        try:
            if candidate.is_file() and candidate.stat().st_size < 100_000:
                chunk = f"\n--- new file: {rel} ---\n{candidate.read_text()}"
                parts.append(chunk)
                total += len(chunk)
        except OSError:
            continue
        if total >= _DIFF_TEXT_CAP:
            break
    return "".join(parts)[:_DIFF_TEXT_CAP]


def validate_patch(
    workdir: Path,
    package: str,
    target: str,
    allowed_extra: list[str],
    pre_keys: set[tuple[str, str]],
    fixed_keys: set[tuple[str, str]],
    *,
    lock_name: str = "package-lock.json",
    kind: str = "package-lock",
) -> list[str]:
    """Full D3 rule set. Returns violations (empty = clean)."""
    violations: list[str] = []
    lockfile = workdir / lock_name
    changed, untracked = diff_files(workdir)
    extras = (changed | untracked) - {"package.json", lock_name} - set(allowed_extra)
    if extras:
        violations.append(f"diff touches non-dependency files: {sorted(extras)}")
    if not npm_lock_resolves(lockfile, kind, package, target):
        violations.append(f"lockfile does not resolve {package}@{target}")
    try:
        post = {
            (d["package"], d["advisory_id"])
            for d in normalize(scan_lockfile(lockfile), lockfile, set())
        }
    except ScanError as exc:
        return violations + [f"rescan failed: {exc}"]
    if remaining := sorted(fixed_keys & post):
        violations.append(f"bump did not remediate {[k[1] for k in remaining]}")
    if new := sorted(post - pre_keys):
        violations.append(f"rescan introduced new advisories: {new}")
    blob = diff_text(workdir, untracked)
    violations.extend(diff_secret_violations(blob))
    return violations


# --- Python patch (FR-7 D4) ---

_PIN_SPLIT_RE = re.compile(r"^(\s*[A-Za-z0-9._-]+(?:\[[^\]]*\])?\s*==\s*)([^,;\s#]+)(.*)$")
_BARE_PIN_RE = re.compile(r"^(\s*[A-Za-z0-9._-]+(?:\[[^\]]*\])?)(\s*;.*)?$")
_RANGE_OP_RE = re.compile(r"[><~!]")
_TEST_WALK_SKIP = frozenset(
    {
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "node_modules",
        "dist",
        "build",
        ".tox",
        ".eggs",
        ".pip-deps",
    }
)
_PYTEST_MARKERS = ("pytest.ini", "tox.ini", "setup.cfg")
_MAX_SANITIZED_BYTES = 1_000_000
_MAX_INCLUDE_DEPTH = 5

_pytest_probe: bool | None = None
_pytest_probe_lock = threading.Lock()


def discover_requirement_files(workdir: Path) -> list[Path]:
    """Editable requirements inputs (FR-7 D4: == pins only)."""
    files, _truncated = discover_python_manifests(workdir)
    return [f for f in files if f.suffix == ".txt"]


def _preservable_spec_tail(tail: str, target: str) -> bool:
    """True when a `,!=…` tail survives a bump to target (hashes never do).

    Hashes pin the old artifact's bytes and cannot be recomputed offline;
    anything but `!=` exclusions is refused so the bump never silently
    weakens the pin the operator approved.
    """
    if "--hash" in tail or "==" in tail or re.search(r"[><~]", tail):
        return False
    for part in tail.split(","):
        part = part.strip()
        if not part:
            continue
        excluded = re.fullmatch(r"!=\s*([^,;\s]+)", part)
        if excluded is None:
            return False
        pinned = excluded.group(1)
        if pinned.endswith(".*"):
            if target == pinned[:-2] or target.startswith(pinned[:-2] + "."):
                return False
        elif target == pinned:
            return False
    return True


def _rewrite_pin_line(line: str, target: str) -> str | None:
    """Swap the == spec (or pin a bare line) for target. None if not editable."""
    if line.rstrip().endswith("\\"):
        return None
    code, hash_, comment = line.partition("#")
    if not code.strip():
        return None
    match = _PIN_SPLIT_RE.match(code)
    if match is not None:
        rest = match.group(3)
        spec, semi, marker = rest.partition(";")
        if spec.strip():
            if not _preservable_spec_tail(spec, target):
                return None
            keep = rest  # compound tail (and marker) with its spacing
        elif semi:
            keep = rest  # environment marker with its spacing
        else:
            keep = rest[len(rest.rstrip()) :]  # trailing whitespace only
        tail = f"{hash_}{comment}" if hash_ else ""
        return f"{match.group(1)}{target}{keep}{tail}"
    bare = _BARE_PIN_RE.match(code.rstrip())
    if bare is not None:
        tail = f"{hash_}{comment}" if hash_ else ""
        return f"{bare.group(1)}=={target}{bare.group(2) or ''}{tail}"
    return None


def _names_package_unsafely(line: str, want: str) -> bool:
    """True when a line we cannot edit still names our package (fail loud)."""
    egg = re.search(r"#egg=([A-Za-z0-9._-]+)", line)
    if egg is not None and normalize_dist_name(egg.group(1)) == want:
        return True
    code = line.split("#", 1)[0].strip()
    if not code or code.startswith("-"):
        return False
    head = re.split(r"[\s;@<>=!~\[]", code, maxsplit=1)[0]
    return bool(head) and normalize_dist_name(head) == want


def apply_python_bump(workdir: Path, package: str, target: str) -> list[str]:
    """Rewrite == pins for package; append a pin when transitive.

    Returns changed workdir-relative paths. Raises PatchError when the
    package is declared but not safely editable.
    """
    if not valid_fixed_version(target):
        raise PatchError(f"refusing to write malformed target version {target!r}")
    want = normalize_dist_name(package)
    changed: list[str] = []
    matched = False
    for path in discover_requirement_files(workdir):
        text = read_text_capped(path, newline="")
        if text is None:
            raise PatchError(f"{path.name} unreadable or exceeds size cap")
        raw_lines = text.splitlines(keepends=True)
        out: list[str] = []
        dirty = False
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
                        f"{path.name}: {package} uses an unsupported declaration "
                        "(URL/editable/option); upgrade manually"
                    )
                out.append(raw)
                continue
            matched = True
            new = _rewrite_pin_line(line, target)
            if new is None:
                if _RANGE_OP_RE.search(line.split("#", 1)[0]):
                    raise PatchError(
                        f"{path.name}: {package} uses a version range; pin to =={target} manually"
                    )
                raise PatchError(
                    f"{path.name}: {package} line is not safely editable; "
                    f"pin to =={target} manually"
                )
            out.append(new + eol)
            dirty |= new != line
        if dirty:
            try:
                path.write_text("".join(out))
            except OSError as exc:
                raise PatchError(f"{path.name} unwritable: {exc}") from exc
            changed.append(path.relative_to(workdir).as_posix())
    if not matched:
        req = workdir / "requirements.txt"
        if not req.exists():
            existing, eol = "", "\n"
        else:
            prior = read_text_capped(req, newline="")
            if prior is None:
                raise PatchError("requirements.txt unreadable or exceeds size cap")
            existing, eol = prior, "\r\n" if "\r\n" in prior else "\n"
        prefix = "" if not existing or existing.endswith("\n") else eol
        try:
            req.write_text(f"{existing}{prefix}{package}=={target}{eol}")
        except OSError as exc:
            raise PatchError(f"requirements.txt unwritable: {exc}") from exc
        changed.append("requirements.txt")
    return changed


def python_pin_resolves(workdir: Path, package: str, target: str) -> bool:
    """True when some requirements file pins package exactly at target."""
    want = normalize_dist_name(package)
    for path in discover_requirement_files(workdir):
        text = read_text_capped(path)
        if text is None:
            continue
        for line in text.splitlines():
            if requirement_name(line) != want:
                continue
            code = line.split("#", 1)[0]
            match = re.search(r"==\s*([^;\s#]+)", code)
            if match is not None and match.group(1).split(",")[0].strip() == target:
                return True
    return False


_HASH_OPT_RE = re.compile(r"--hash=(sha256|sha384|sha512):[0-9a-fA-F]+")


def _canonical_pin(line: str) -> str | None:
    """Canonical `name[extras]==version[ --hash=…][; marker]` for pip, else None.

    Ranges, bare names, URLs, editables, and compound specifiers are refused:
    installs must resolve to exact pins only (FR-7 D4). Well-formed --hash
    options and environment markers are preserved.
    """
    match = re.match(
        r"^\s*([A-Za-z0-9._-]+(?:\[[^\]]*\])?)\s*==\s*([^,;\s#]+)(.*)$",
        line.split("#", 1)[0],
    )
    if match is None:
        return None
    name, version, rest = match.group(1), match.group(2), match.group(3)
    if not valid_fixed_version(version):
        return None
    opts, semi, marker = rest.partition(";")
    opts = opts.strip()
    if opts and any(_HASH_OPT_RE.fullmatch(tok) is None for tok in opts.split()):
        return None
    pin = f"{name}=={version}"
    if opts:
        pin += f" {opts}"
    if semi:
        pin += f";{marker}"
    return pin


def sanitized_requirements(workdir: Path, files: list[Path]) -> tuple[str, list[str]]:
    """Pins-only requirements text for pip installs, plus skipped notes.

    -r includes resolve safely (relative, in-repo, depth-capped,
    cycle-guarded); options, editables, URLs, continuations, and anything
    but exact == pins are dropped. The output is pip input only — never
    written to the repo.
    """
    out: list[str] = []
    skipped: list[str] = []
    emitted: set[Path] = set()
    budget = _MAX_SANITIZED_BYTES

    def emit(path: Path, depth: int, stack: frozenset[Path]) -> None:
        nonlocal budget
        try:
            resolved = path.resolve()
            resolved.relative_to(workdir.resolve())
        except (OSError, ValueError):
            skipped.append(f"{path.name}: outside repo")
            return
        if resolved in stack:
            skipped.append(f"{path.name}: include cycle/depth")
            return
        if resolved in emitted:
            return  # already included via another branch: silent, not a cycle
        if depth > _MAX_INCLUDE_DEPTH:
            skipped.append(f"{path.name}: include cycle/depth")
            return
        emitted.add(resolved)
        try:
            size = resolved.stat().st_size
            if size > budget:
                skipped.append(f"{path.name}: too large")
                return
            text = resolved.read_text()
        except OSError:
            skipped.append(f"{path.name}: unreadable")
            return
        budget -= size
        branch = stack | {resolved}
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.endswith("\\"):
                skipped.append(f"{path.name}: continuation dropped")
                continue
            parts = line.split()
            if parts[0] in ("-r", "--requirement") and len(parts) > 1:
                emit(path.parent / parts[1], depth + 1, branch)
                continue
            if line.startswith("--requirement="):
                emit(path.parent / line.split("=", 1)[1].strip(), depth + 1, branch)
                continue
            if line.startswith("-"):
                skipped.append(f"{path.name}: option dropped")
                continue
            if requirement_name(line) is None or "@" in line.split(";")[0]:
                skipped.append(f"{path.name}: non-pin dropped")
                continue
            pin = _canonical_pin(line)
            if pin is None:
                skipped.append(f"{path.name}: unpinned spec dropped")
                continue
            out.append(pin)

    for top in files:
        emit(top, 0, frozenset())
    return ("\n".join(out) + "\n") if out else "", skipped


def ensure_python_test_deps(workdir: Path) -> str:
    """Best-effort test-dep install into workdir/.pip-deps.

    Returns "" when clean, else a disclosure note. Never raises for install
    problems: failure degrades to identical-output comparison (FR-7 D4).
    """
    target = workdir / ".pip-deps"
    if target.is_dir():
        return ""
    text, skipped = sanitized_requirements(workdir, discover_requirement_files(workdir))
    if not text.strip():
        return "test deps: no installable requirements"
    req_file = workdir / ".agent-requirements.txt"
    try:
        req_file.write_text(text)
        run_allowlisted(
            "pip-install",
            ["--target", str(target), "-r", str(req_file)],
            cwd=str(workdir),
            timeout=TEST_TIMEOUT,
            allow_network=True,
        )
    except (RuntimeError, TimeoutError, OSError) as exc:
        return f"test deps not installed ({exc}); compared raw outputs"
    finally:
        try:
            req_file.unlink(missing_ok=True)
        except OSError:
            pass
    if skipped:
        return f"test deps installed with {len(skipped)} dropped line(s)"
    return ""


def has_python_tests(workdir: Path) -> bool:
    """True when the repo looks test-bearing (pytest config, tests dirs/files)."""
    for marker in _PYTEST_MARKERS:
        if (workdir / marker).is_file():
            return True
    pyproject = read_text_capped(workdir / "pyproject.toml")
    if pyproject is not None and "pytest" in pyproject:
        return True
    for _root, dirs, files in os.walk(workdir, followlinks=False):
        dirs[:] = [d for d in dirs if d not in _TEST_WALK_SKIP and not d.endswith(".egg-info")]
        if "tests" in dirs or "test" in dirs:
            return True
        for name in files:
            if (
                name == "conftest.py"
                or name.endswith("_test.py")
                or (name.startswith("test_") and name.endswith(".py"))
            ):
                return True
    return False


def _pytest_available() -> bool:
    """Cached runner probe; pytest ships in dev, not in the prod image."""
    global _pytest_probe
    if _pytest_probe is not None:
        return _pytest_probe
    with _pytest_probe_lock:
        if _pytest_probe is not None:
            return _pytest_probe
        try:
            out = run_allowlisted("pytest", ["--version"], check=False)
        except (RuntimeError, TimeoutError, OSError):
            _pytest_probe = False
            return False
        _pytest_probe = "pytest" in out.lower() and "no module named" not in out.lower()
        return _pytest_probe


def run_python_tests(workdir: Path) -> tuple[bool, str, str] | None:
    """(passed, output, dep_note); None when no tests or no runner (→ static)."""
    if not has_python_tests(workdir) or not _pytest_available():
        return None
    dep_note = ensure_python_test_deps(workdir)
    env = {"PYTHONPATH": str(workdir / ".pip-deps"), "PYTHONDONTWRITEBYTECODE": "1"}
    out = run_allowlisted(
        "pytest", [], cwd=str(workdir), timeout=TEST_TIMEOUT, check=False, env=env
    )
    if out.startswith("[exit 5]"):
        return None  # collected nothing: no runnable tests
    return (not out.startswith("[exit ")), out, dep_note


def python_scan_keys(workdir: Path) -> set[tuple[str, str]]:
    """(package, advisory) over current Python manifests (rescan helper).

    Generates missing locks exactly like the scan, so verification sees
    the same inputs the scan did (generated locks are workdir-local).
    """
    files, _truncated = discover_python_manifests(workdir)
    generated, _gen_notes = ensure_python_lockfiles(workdir, files)
    files = [*files, *generated]
    ctx = python_context(files)
    keys: set[tuple[str, str]] = set()
    for manifest in files:
        for draft in normalize(scan_lockfile(manifest), manifest, set(), context=ctx):
            keys.add((draft["package"], draft["advisory_id"]))
    return keys


def validate_python_patch(
    workdir: Path,
    package: str,
    target: str,
    allowed_extra: list[str],
    pre_keys: set[tuple[str, str]],
    fixed_keys: set[tuple[str, str]],
) -> list[str]:
    """D3 rules for Python bumps. Returns violations (empty = clean)."""
    violations: list[str] = []
    changed, untracked = diff_files(workdir)
    manifests = {f.relative_to(workdir).as_posix() for f in discover_requirement_files(workdir)}
    manifests.add("requirements.txt")  # transitive pins may create it
    extras = (changed | untracked) - manifests - set(allowed_extra)
    if extras:
        violations.append(f"diff touches non-dependency files: {sorted(extras)}")
    if not python_pin_resolves(workdir, package, target):
        violations.append(f"requirements do not pin {package}=={target}")
    try:
        post = python_scan_keys(workdir)
    except ScanError as exc:
        return violations + [f"rescan failed: {exc}"]
    if remaining := sorted(fixed_keys & post):
        violations.append(f"bump did not remediate {[k[1] for k in remaining]}")
    if new := sorted(post - pre_keys):
        violations.append(f"rescan introduced new advisories: {new}")
    blob = diff_text(workdir, untracked)
    violations.extend(diff_secret_violations(blob))
    return violations


def patch_python_group(
    repo: Repo,
    findings: list[Finding],
    source_template: Path | None,
    adapt: AdaptHook,
) -> dict:
    """Repair loop for one Python package group; mirrors patch_group."""
    package = findings[0].package
    fixed_keys = {(f.package, f.advisory_id) for f in findings}
    targets = _group_targets(findings)
    if not targets:
        guidance = (
            f"No fixed version published for {package} "
            f"{sorted(a for _, a in fixed_keys)}; consider replacing the dependency."
        )
        for finding in findings:
            _mark_unpatchable(finding.id, guidance)
        return {
            "finding_ids": [f.id for f in findings],
            "outcome": "unpatchable",
            "reason": guidance,
        }
    try:
        with _fresh_workdir(repo, source_template) as clean:
            baseline = run_python_tests(clean)
            refusal = _managed_python_refusal(clean, package, targets[0])
            if refusal is not None:
                for finding in findings:
                    _mark_unpatchable(finding.id, refusal)
                return {
                    "finding_ids": [f.id for f in findings],
                    "outcome": "unpatchable",
                    "reason": refusal,
                }
            pre = python_scan_keys(clean)
    except (PatchError, ScanError, RuntimeError, TimeoutError) as exc:
        guidance = f"Pre-check failed for {package}: {exc}"
        for finding in findings:
            _mark_unpatchable(finding.id, guidance)
        return {
            "finding_ids": [f.id for f in findings],
            "outcome": "unpatchable",
            "reason": guidance,
        }
    failures: list[str] = []
    for target in targets:
        try:
            with _fresh_workdir(repo, source_template) as workdir:
                apply_python_bump(workdir, package, target)
                adapted = adapt(workdir, findings[0], target, list(failures))
                if baseline is None:
                    if not python_pin_resolves(workdir, package, target):
                        failures.append(f"static: requirements lack {package}=={target}")
                        continue
                    verification = f"static analysis clean: requirements pin {target}"
                    ignored: list[str] = []
                else:
                    post = run_python_tests(workdir)
                    if post is None:
                        failures.append("tests vanished mid-run")
                        continue
                    post_ok, post_out, post_dep = post
                    base_ok, base_out, base_dep = baseline
                    ok, ignored = compare_test_runs((base_ok, base_out), (post_ok, post_out))
                    for note in (base_dep, post_dep):
                        if note and note not in ignored:
                            ignored.append(note)
                    if not ok:
                        failures.append(f"tests failed on {target}")
                        continue
                    verification = "repo tests passed"
                    if ignored:
                        verification += f" ({ignored[0]})"
                violations = validate_python_patch(
                    workdir, package, target, adapted.changed_files, pre, fixed_keys
                )
                if violations:
                    failures.append(f"validate {target}: {'; '.join(violations)}")
                    continue
                _changed, untracked = diff_files(workdir)
                proposal_id = _persist_proposal(
                    repo.id, findings, target, verification, ignored, diff_text(workdir, untracked)
                )
                return {
                    "finding_ids": [f.id for f in findings],
                    "outcome": "proposed",
                    "proposal_id": proposal_id,
                    "target": target,
                }
        except (PatchError, ScanError, RuntimeError, TimeoutError) as exc:
            failures.append(f"{target}: {exc}")
            continue
    guidance = (
        f"No verified fix for {package} {sorted(a for _, a in fixed_keys)} "
        f"(tried {', '.join(targets)}): {'; '.join(failures)}; "
        "upgrade manually or replace the dependency."
    )
    if source_template is not None and any(
        (source_template / name).is_file() for name in PYTHON_LOCK_NAMES
    ):
        guidance += (
            " For managed lockfiles, re-lock after upgrading "
            "(poetry lock, pipenv lock, pdm lock, or uv lock)."
        )
    for finding in findings:
        _mark_unpatchable(finding.id, guidance)
    return {
        "finding_ids": [f.id for f in findings],
        "outcome": "unpatchable",
        "reason": guidance,
    }


def _node_owns(source: Path, package: str) -> bool:
    """True when package.json declares package (routing helper)."""
    manifest = read_json_capped(source / "package.json")
    if not isinstance(manifest, dict):
        return False
    for section in (*_DEP_SECTIONS, "overrides"):
        deps = manifest.get(section)
        if isinstance(deps, dict) and package in deps:
            return True
    return False


def _requirements_own(source: Path, package: str) -> bool:
    """True when some requirements file names package (routing helper)."""
    want = normalize_dist_name(package)
    for path in discover_requirement_files(source):
        text = read_text_capped(path)
        if text is None:
            continue
        for line in text.splitlines():
            if requirement_name(line) == want:
                return True
    return False


def _route_python(eco: str, source_template: Path | None, package: str) -> bool:
    """True when a finding group belongs on the Python patch path (FR-7 D2)."""
    if eco == "pypi":
        return True
    if eco == "npm":
        return False
    if source_template is not None and _requirements_own(source_template, package):
        return not _node_owns(source_template, package)
    return False


def _managed_python_refusal(workdir: Path, package: str, target: str) -> str | None:
    """Guidance when a generated input owns the fix instead of requirements.

    Refuses only when the scan would actually generate here (candidacy):
    a stray requirements.txt pin cannot fix a managed/compiled project,
    and would additionally hide its vulnerabilities from future scans by
    covering the directory. Covered dirs generate nothing, so their
    findings can only come from requirements and stay patchable.
    """
    if _requirements_own(workdir, package):
        return None
    files, truncated = discover_python_manifests(workdir)
    if truncated or len(files) >= MAX_PYTHON_MANIFESTS:
        return None  # scan generates nothing here either; verification is exact
    if not python_generation_pending(workdir):
        return None
    return (
        f"{package} is not pinned in requirements files and this repo has "
        f"managed Python manifests (pyproject.toml/Pipfile) or compilable inputs "
        f"(requirements.in/setup.py) covering it; upgrade {package} "
        f"to =={target} in the owning file and re-lock/recompile "
        "(poetry lock, pipenv lock, pdm lock, uv lock, or uv pip compile)."
    )


def patch_candidates(repo_id: int) -> list[Finding]:
    """OPEN findings whose latest verdict says reachable (FR-4: reachable only)."""
    with session_scope() as db:
        out: list[Finding] = []
        opens = list(
            db.scalars(
                select(Finding).where(
                    Finding.repo_id == repo_id, Finding.status == FindingStatus.OPEN
                )
            )
        )
        for finding in opens:
            verdict = db.scalar(
                select(Verdict)
                .where(Verdict.finding_id == finding.id)
                .order_by(Verdict.id.desc())
                .limit(1)
            )
            if verdict is not None and verdict.reachable:
                out.append(finding)
        for row in out:
            db.expunge(row)
        return out


def _group_targets(findings: list[Finding]) -> list[str]:
    """In-order union of members' fixed versions (advisory-recommended first)."""
    ordered: list[str] = []
    for finding in findings:
        for version in finding.fixed_versions or []:
            version = str(version)
            if version not in ordered:
                ordered.append(version)
    return ordered[:MAX_ROUNDS]


@contextmanager
def _fresh_workdir(repo: Repo, source_template: Path | None):
    workdir = make_workdir("patch-")
    try:
        if source_template is not None:
            shutil.rmtree(workdir)
            shutil.copytree(source_template, workdir)
        else:
            clone_repo(repo, workdir)
        yield workdir
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _mark_unpatchable(finding_id: int, guidance: str) -> None:
    with session_scope() as db:
        row = db.get(Finding, finding_id)
        if row is None:
            return
        row.guidance = guidance
        db.flush()
        db.expunge(row)
    try:
        from security_agent.control.cost import current_run_id
        from security_agent.policy.retrieve import retrieve_policy_context

        block, _ = retrieve_policy_context(
            row.repo_id,
            "unpatchable-guidance",
            f"{row.package} {row.advisory_id}",
            run_id=current_run_id(),
        )
        if block:
            with session_scope() as db:
                target = db.get(Finding, finding_id)
                if target is not None:
                    target.guidance = f"{guidance}\n\nPolicy notes:\n{block}"
    except Exception as exc:  # noqa: BLE001 - guidance never breaks patching
        log.warning("policy guidance for finding %d failed: %s", finding_id, exc)
    transition_finding(finding_id, FindingStatus.UNPATCHABLE)


def _persist_proposal(
    repo_id: int,
    findings: list[Finding],
    target: str,
    verification: str,
    ignored: list[str],
    patch_text: str,
) -> int:
    # D20 persist-time recheck: a dependency PR that appeared while this
    # group patched wins the bump; never persist a second live PR.
    from security_agent.worker.deps_patch import live_dep_proposal_for_package

    if findings and live_dep_proposal_for_package(repo_id, findings[0].package):
        raise PatchError("queued behind a live dependency PR for this package (D20)")
    with session_scope() as db:
        proposal = Proposal(
            repo_id=repo_id,
            finding_ids=[f.id for f in findings],
            package_from=findings[0].installed_version,
            package_to=target,
            verification_result=verification,
            ignored_tests=ignored,
            patch=patch_text,
        )
        db.add(proposal)
        db.flush()
        proposal_id = proposal.id
    for finding in findings:
        transition_finding(finding.id, FindingStatus.PROPOSED)
    return proposal_id


def patch_group(
    repo: Repo,
    findings: list[Finding],
    source_template: Path | None,
    adapt: AdaptHook,
) -> dict:
    """Repair loop for one package group; one proposal covers all members."""
    package = findings[0].package
    fixed_keys = {(f.package, f.advisory_id) for f in findings}
    targets = _group_targets(findings)
    if not targets:
        guidance = (
            f"No fixed version published for {package} "
            f"{sorted(a for _, a in fixed_keys)}; consider replacing the dependency."
        )
        for finding in findings:
            _mark_unpatchable(finding.id, guidance)
        return {
            "finding_ids": [f.id for f in findings],
            "outcome": "unpatchable",
            "reason": guidance,
        }
    try:
        with _fresh_workdir(repo, source_template) as clean:
            kind = root_npm_kind(clean)
            lock_name = _KIND_TO_LOCK[kind]
            if kind == "package-lock":
                lock, _ = ensure_lockfile(clean)
            else:
                lock = clean / lock_name  # native lock exists; never npm-generate here
            baseline = run_repo_tests(clean)
            pre = {
                (d["package"], d["advisory_id"])
                for d in normalize(scan_lockfile(lock), lock, set())
            }
    except (PatchError, ScanError, RuntimeError, TimeoutError) as exc:
        guidance = f"Pre-check failed for {package}: {exc}"
        for finding in findings:
            _mark_unpatchable(finding.id, guidance)
        return {
            "finding_ids": [f.id for f in findings],
            "outcome": "unpatchable",
            "reason": guidance,
        }
    failures: list[str] = []
    for target in targets:
        try:
            with _fresh_workdir(repo, source_template) as workdir:
                if kind == "package-lock":
                    ensure_lockfile(workdir)
                apply_bump(workdir, package, target, kind=kind)
                refresh_lockfile(workdir, kind)
                adapted = adapt(workdir, findings[0], target, list(failures))
                if baseline is None:
                    if not npm_lock_resolves(workdir / lock_name, kind, package, target):
                        failures.append(f"static: lockfile lacks {target}")
                        continue
                    verification = f"static analysis clean: lockfile resolves {target}"
                    ignored: list[str] = []
                else:
                    post = run_repo_tests(workdir)
                    if post is None:
                        failures.append("test script vanished mid-run")
                        continue
                    ok, ignored = compare_test_runs(baseline, post)
                    if not ok:
                        failures.append(f"tests failed on {target}")
                        continue
                    verification = "repo tests passed"
                    if ignored:
                        verification += f" ({ignored[0]})"
                violations = validate_patch(
                    workdir,
                    package,
                    target,
                    adapted.changed_files,
                    pre,
                    fixed_keys,
                    lock_name=lock_name,
                    kind=kind,
                )
                if violations:
                    failures.append(f"validate {target}: {'; '.join(violations)}")
                    continue
                _changed, untracked = diff_files(workdir)
                proposal_id = _persist_proposal(
                    repo.id, findings, target, verification, ignored, diff_text(workdir, untracked)
                )
                return {
                    "finding_ids": [f.id for f in findings],
                    "outcome": "proposed",
                    "proposal_id": proposal_id,
                    "target": target,
                }
        except (PatchError, ScanError, RuntimeError, TimeoutError) as exc:
            failures.append(f"{target}: {exc}")
            continue
    guidance = (
        f"No verified fix for {package} {sorted(a for _, a in fixed_keys)} "
        f"(tried {', '.join(targets)}): {'; '.join(failures)}; "
        "upgrade manually or replace the dependency."
    )
    for finding in findings:
        _mark_unpatchable(finding.id, guidance)
    return {
        "finding_ids": [f.id for f in findings],
        "outcome": "unpatchable",
        "reason": guidance,
    }


def patch_one(
    repo: Repo,
    finding: Finding,
    source_template: Path | None,
    adapt: AdaptHook,
) -> dict:
    """Solo repair loop (single-member group); returns the legacy outcome record."""
    result = patch_group(repo, [finding], source_template, adapt)
    result["finding_id"] = finding.id
    return result


def run_patch(
    repo_id: int,
    run_id: int,
    *,
    source_dir: Path | None = None,
    adapt: AdaptHook = null_adapt,
) -> dict:
    """Patch every reachable OPEN finding; report-only on exhaustion (FR-4 D4/D6)."""
    from security_agent.policy.enforce import park_for_policy, pre_patch_check
    from security_agent.policy.service import PolicyStoreError

    assert_host_execution_allowed()
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        run = db.get(ScanRun, run_id)
        if repo is None or run is None:
            raise ValueError(f"Unknown repo {repo_id} or run {run_id}.")
        if run.parked:
            return {"status": "parked", "results": [], "proposal_ids": []}
        db.expunge(repo)
    reopen_run(run_id)
    candidates = patch_candidates(repo_id)
    append_run_note(run_id, f"patch: {len(candidates)} candidate(s)")
    try:
        gate = pre_patch_check(repo_id, run_id, candidates)
    except PolicyStoreError as exc:
        park_for_policy(run_id, str(exc))
        return {"status": "parked", "results": [], "proposal_ids": []}
    allowed = set(gate["proceed"])
    held_out = set(gate["blocked"]) | set(gate["awaiting"])
    results: list[dict] = []
    for finding in candidates:
        if finding.id in held_out:
            results.append(
                {
                    "finding_ids": [finding.id],
                    "outcome": "blocked" if finding.id in gate["blocked"] else "awaiting-approval",
                    "reason": "policy guardrail held this finding out of patching",
                }
            )
    from security_agent.worker.deps_patch import live_dep_proposal_for_package

    groups: dict[tuple[str, str], list[Finding]] = {}
    for finding in candidates:
        if finding.id not in allowed:
            continue
        # D20, reverse direction: two live PRs bumping the same package
        # never coexist. A live dependency PR owns the bump; the finding
        # queues behind it and the rescan resolves it when that PR lands
        # at a version >= the fix.
        if live_dep_proposal_for_package(repo_id, finding.package):
            results.append(
                {
                    "finding_ids": [finding.id],
                    "outcome": "queued",
                    "reason": "queued behind a live dependency PR for this package (D20)",
                }
            )
            continue
        eco = (finding.ecosystem or "").lower() or "unknown"
        groups.setdefault((eco, finding.package), []).append(finding)
    for (eco, package), members in groups.items():
        append_run_note(run_id, f"patch: {package} ({eco}, {len(members)} finding(s))...")
        if _route_python(eco, source_dir, package):
            result = patch_python_group(repo, members, source_dir, adapt)
        else:
            result = patch_group(repo, members, source_dir, adapt)
        results.append(result)
        outcome = result.get("outcome")
        if outcome == "proposed" and result.get("proposal_id") is not None:
            append_run_note(run_id, f"patch: {package}: proposed (#{result['proposal_id']})")
        elif outcome == "unpatchable":
            reason = str(result.get("reason", ""))[:160]
            append_run_note(run_id, f"patch: {package}: unpatchable ({reason})")
        else:
            append_run_note(run_id, f"patch: {package}: {outcome}")
    proposed = sum(1 for r in results if r.get("outcome") == "proposed")
    append_run_note(run_id, f"patch: {proposed} proposed, {len(results) - proposed} report-only")
    return {
        "status": "done",
        "results": results,
        "proposal_ids": [r["proposal_id"] for r in results if "proposal_id" in r],
    }
