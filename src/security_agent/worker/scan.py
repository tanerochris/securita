"""Sandbox scan: clone, lockfile, osv-scanner, KEV join, D6 normalize (FR-2).

Runs in a per-run temp dir in dev/test. Prod refuses host execution until
the Docker sandbox lands (NFR-1 fail-closed).
"""

import ast
import configparser
import csv
import json
import logging
import re
import shutil
import threading
import time
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

import httpx
from packaging.version import InvalidVersion, Version
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from security_agent.control.lifecycle import append_run_note
from security_agent.control.repos import get_repo_token
from security_agent.db.models import (
    Finding,
    FindingScope,
    Repo,
    RepoKind,
    RunStatus,
    ScanRun,
)
from security_agent.db.session import session_scope
from security_agent.sandbox import assert_host_execution_allowed, make_workdir
from security_agent.sandbox.tools import MAX_SCANNER_OUTPUT_CHARS, run_allowlisted

_KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
_KEV_TTL = timedelta(hours=6)
_KEV_TIMEOUT_SECONDS = 30

LOCKFILE_TIMEOUT_SECONDS = 600  # fresh resolution can take minutes via proxy

log = logging.getLogger(__name__)

_kev_cache: tuple[datetime, set[str]] | None = None
_kev_lock = threading.Lock()


class ScanError(RuntimeError):
    """Expected scan failure: recorded on the run, not raised past run_scan."""


def kev_exploited_ids() -> set[str]:
    """CISA KEV CVE IDs (cached 6h). Fail-open: empty set when unreachable."""
    global _kev_cache
    now = datetime.now(UTC)
    cached = _kev_cache
    if cached and now - cached[0] < _KEV_TTL:
        return set(cached[1])
    with _kev_lock:
        cached = _kev_cache
        now = datetime.now(UTC)
        if cached and now - cached[0] < _KEV_TTL:
            return set(cached[1])
        try:
            r = httpx.get(_KEV_URL, timeout=_KEV_TIMEOUT_SECONDS)
            r.raise_for_status()
            ids = {
                row["cveID"].strip().upper()
                for row in csv.DictReader(r.text.splitlines())
                if row.get("cveID", "").strip()
            }
        except Exception as exc:  # noqa: BLE001 - enrichment fail-open by design
            log.warning("KEV unavailable, continuing without enrichment: %s", exc)
            return set()
        _kev_cache = (now, ids)
        return set(ids)  # copies: callers must not mutate the cached set


def clone_url(repo_url: str, token: str) -> str:
    """Embed an https token in-memory only; callers must redact it from logs."""
    if not token or not repo_url.startswith("https://"):
        return repo_url
    user = "oauth2" if "gitlab" in urlparse(repo_url).netloc else "x-access-token"
    return repo_url.replace("https://", f"https://{user}:{token}@", 1)


def clone_repo(repo: Repo, dest: Path, *, depth: int | None = 1) -> None:
    url = repo.url or f"file://{repo.local_path}"
    token = get_repo_token(repo.id) if repo.kind == RepoKind.GIT else ""
    full = clone_url(url, token or "")
    args = ["clone"]
    if depth is not None:
        args += ["--depth", str(depth)]
    try:
        # `--` neutralizes option injection from the stored URL.
        run_allowlisted(
            "git",
            [*args, "--no-single-branch", "--", full, dest.name],
            cwd=str(dest.parent),
            redact=(token,) if token else (),
            allow_network=True,
        )
    except (RuntimeError, TimeoutError) as exc:
        # Tool errors carry stderr, which echoes the credential-bearing URL.
        raise type(exc)(str(exc).replace(token, "***") if token else str(exc)) from exc
    if token:
        # The clone persists the credential URL in .git/config; strip it back
        # to the clean URL. Best-effort: the workdir is temp and always wiped.
        try:
            run_allowlisted("git", ["remote", "set-url", "origin", url], cwd=str(dest))
        except (RuntimeError, TimeoutError) as exc:
            log.debug("origin strip failed (workdir is temp): %s", exc)
    if not (dest / ".git").exists():
        # The clone wrote container-side but the worker sees no checkout:
        # the work volume is not shared (SANDBOX_WORK_ROOT/VOLUME
        # mismatch, or the stack was not recreated after a compose
        # change). Fail loud — every caller mixes worker-side reads
        # with container-side tools, so an invisible checkout would
        # scan as a silently empty repo ("nothing to scan").
        raise ScanError(
            f"clone finished but {dest} has no .git on the worker: the sandbox "
            "work volume is not shared between the worker and its tool "
            "containers (SANDBOX_WORK_ROOT/SANDBOX_WORK_VOLUME mismatch?). "
            "Recreate the stack with `docker compose up -d --build` so both "
            "mount the same volume."
        )


def ensure_lockfile(workdir: Path) -> tuple[Path, bool]:
    """Return (lockfile, generated). Generates with scripts disabled (FR-2 D5)."""
    lock = workdir / "package-lock.json"
    if lock.exists():
        return lock, False
    run_allowlisted(
        "npm",
        ["install", "--package-lock-only", "--ignore-scripts"],
        cwd=str(workdir),
        timeout=LOCKFILE_TIMEOUT_SECONDS,
        allow_network=True,
    )
    if not lock.exists():
        raise ScanError("lockfile generation produced no package-lock.json")
    return lock, True


def scan_lockfile(lockfile: Path) -> dict:
    try:
        out = run_allowlisted(
            "osv-scanner",
            ["--lockfile", lockfile.name, "--format", "json"],
            cwd=str(lockfile.parent),
            allow_network=True,  # OSV.dev lookup; sandbox bridge has no internal routes
            success_codes=(0, 1),  # osv-scanner exits 1 when findings exist
            max_output=MAX_SCANNER_OUTPUT_CHARS,
        )
        parsed = json.loads(out)
    except json.JSONDecodeError as exc:
        raise ScanError(f"osv-scanner returned invalid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ScanError("osv-scanner returned a non-object document")
    return parsed


def canonical_id(osv_id: str, aliases: list[str]) -> str:
    """Prefer CVE, else GHSA, else the OSV ID (FR-2 D4)."""
    candidates = [osv_id, *aliases]
    for prefix in ("CVE-", "GHSA-"):
        matches = sorted(a for a in candidates if a.startswith(prefix))
        if matches:
            return matches[0]
    return osv_id


def _severity(vuln: dict) -> tuple[float | None, str | None]:
    best: tuple[float | None, str | None] = (None, None)
    for entry in vuln.get("severity", []) or []:
        score = entry.get("score")
        if not isinstance(score, (int, float)):
            continue
        if best[0] is None or score > best[0]:
            best = (float(score), str(entry.get("type", "")))
    return best


_OSV_NAME_RE = re.compile(r"^@?[A-Za-z0-9._/-]+$")


def valid_osv_name(name: object) -> bool:
    """True when a scanner-reported package name is safe to store and match."""
    return (
        isinstance(name, str)
        and 0 < len(name) <= 500
        and _OSV_NAME_RE.match(name) is not None
        and ".." not in name
    )


def valid_fixed_version(version: object) -> bool:
    """True when a scanner-reported fixed version is safe to write into a pin."""
    if not isinstance(version, str) or not version or len(version) > 100:
        return False
    if any(char.isspace() or ord(char) < 32 for char in version):
        return False
    try:
        Version(version)
    except InvalidVersion:
        return False
    return True


def _fixed_versions(vuln: dict) -> list[str]:
    fixed: list[str] = []
    for affected in vuln.get("affected", []) or []:
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                version = event.get("fixed")
                if (
                    isinstance(version, str)
                    and version not in fixed
                    and valid_fixed_version(version)
                ):
                    fixed.append(version)
                elif version and not valid_fixed_version(version):
                    log.debug("dropping malformed fixed version: %r", version)
    return fixed


def read_text_capped(
    path: Path, limit: int | None = None, *, newline: str | None = None
) -> str | None:
    """File text, or None when oversize/unreadable (untrusted repo content).

    newline="" preserves raw line endings for surgical rewrites; the default
    translates them (universal newlines) for parsing and matching.
    """
    cap = MAX_LOCK_PARSE_BYTES if limit is None else limit
    try:
        if path.stat().st_size > cap:
            return None
        with path.open("r", encoding="utf-8", newline=newline) as handle:
            return handle.read()
    except (OSError, ValueError):
        return None


def read_json_capped(path: Path, limit: int | None = None) -> dict | None:
    """Parsed JSON object, or None when oversize/unreadable/not an object."""
    text = read_text_capped(path, limit)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


_lock_packages_cache: dict[tuple[str, int, int], dict] = {}
_LOCK_CACHE_MAX = 64
_lock_cache_lock = threading.Lock()


def load_lockfile_packages(lockfile: Path) -> dict:
    """Parse the lockfile's packages table once; {} when unreadable.

    Size-gated and cached per (path, mtime, size) so repeated normalizes
    over one run do not re-buffer hostile multi-hundred-MB lockfiles.
    """
    try:
        stat = lockfile.stat()
    except OSError:
        return {}
    if stat.st_size > MAX_LOCK_PARSE_BYTES:
        log.debug("lockfile %s exceeds %d bytes; skipping context", lockfile, MAX_LOCK_PARSE_BYTES)
        return {}
    key = (str(lockfile), stat.st_mtime_ns, stat.st_size)
    with _lock_cache_lock:
        cached = _lock_packages_cache.get(key)
        if cached is not None:
            return cached
    data = read_json_capped(lockfile)
    packages = data.get("packages", {}) if data else {}
    if not isinstance(packages, dict):
        return {}
    with _lock_cache_lock:
        if len(_lock_packages_cache) >= _LOCK_CACHE_MAX:
            _lock_packages_cache.clear()
        _lock_packages_cache[key] = packages
    return packages


def lockfile_package_index(packages: dict) -> dict[str, list[tuple[list[str], object, bool]]]:
    """name → [(segments, version, is_dev)] over all lock entries, built once."""
    index: dict[str, list[tuple[list[str], object, bool]]] = {}
    for key, entry in packages.items():
        if not key or not isinstance(entry, dict):
            continue
        segments = [s.strip("/") for s in key.split("node_modules/") if s.strip("/")]
        if not segments:
            continue
        index.setdefault(segments[-1], []).append(
            (segments, entry.get("version"), bool(entry.get("dev")))
        )
    return index


def indexed_lockfile_context(
    index: dict[str, list[tuple[list[str], object, bool]]], package: str, version: str
) -> tuple[list[str], bool]:
    """Shortest-path context from a prebuilt index (same rules as lockfile_context)."""
    best: tuple[list[str], bool] | None = None
    for segments, entry_version, is_dev in index.get(package, []):
        if version and entry_version not in (None, version):
            continue
        if best is None or len(segments) < len(best[0]):
            best = (segments, is_dev)
    return best if best is not None else ([package], False)


def lockfile_context(packages: dict, package: str, version: str) -> tuple[list[str], bool]:
    """(dependency path to direct parent, is_dev) from a parsed packages table.

    Lockfile v1 ("dependencies" tree) and unknown layouts fall back to
    ([package], prod) rather than failing the scan.
    """
    return indexed_lockfile_context(lockfile_package_index(packages), package, version)


# --- Node inputs (tracker D12/D18 parity) ---

NODE_LOCK_NAMES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")
NODE_LOCK_KINDS = {
    "package-lock.json": "package-lock",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
}
MAX_NODE_MANIFESTS = 20

_SCAN_WALK_SKIP = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".tox",
        "dist",
        "build",
        ".eggs",
    }
)


def _walk_collect(
    workdir: Path, match: Callable[[Path], bool], *, limit: int
) -> tuple[list[Path], bool]:
    """Sorted files under workdir matching match(); (files, hit_limit).

    Skips VCS/venv/build/node_modules dirs and symlinks; never raises on
    unreadable entries.
    """
    found: list[Path] = []
    hit_limit = False
    try:
        workdir.resolve()
    except OSError:
        return [], False
    stack: list[Path] = [workdir]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir() and not entry.is_symlink():
                if entry.name in _SCAN_WALK_SKIP:
                    continue
                if _inside(workdir, entry):
                    stack.append(entry)
                continue
            if not entry.is_file() or entry.is_symlink():
                continue
            if not match(entry):
                continue
            if len(found) >= limit:
                hit_limit = True
                break
            found.append(entry)
        if hit_limit:
            break
    found.sort()
    return found, hit_limit


@dataclass
class NodeScanTarget:
    """One Node scan input: a package.json dir and/or a stray lockfile."""

    manifest: Path | None  # package.json (None for stray lockfiles)
    lockfile: Path | None  # scannable lock (None: generate at root, skip nested)
    lock_kind: str | None  # package-lock | yarn | pnpm


def discover_node_manifests(workdir: Path) -> tuple[list[NodeScanTarget], bool]:
    """Node scan inputs: every package.json dir plus stray locks (D12/D18).

    Each package.json dir resolves its lock in tracker preference order
    (package-lock > yarn > pnpm); dirs without any lock come back with
    lockfile None so run_scan generates at the root and names nested
    skips. A lockfile in a dir without package.json is still scanned
    (legacy root package-lock behavior, generalized). Bounded at
    MAX_NODE_MANIFESTS targets; truncation is never silent.
    """
    files, hit_limit = _walk_collect(
        workdir,
        lambda p: p.name == "package.json" or p.name in NODE_LOCK_NAMES,
        limit=MAX_NODE_MANIFESTS * 4,
    )
    by_dir: dict[Path, list[Path]] = {}
    for lock in files:
        if lock.name != "package.json":
            by_dir.setdefault(lock.parent, []).append(lock)
    order = {name: index for index, name in enumerate(NODE_LOCK_NAMES)}

    def _preferred(dir_locks: list[Path]) -> Path:
        return sorted(dir_locks, key=lambda p: order[p.name])[0]

    manifest_dirs: set[Path] = set()
    targets: list[NodeScanTarget] = []
    for manifest in [p for p in files if p.name == "package.json"]:
        manifest_dirs.add(manifest.parent)
        dir_locks = by_dir.get(manifest.parent, [])
        if dir_locks:
            lock = _preferred(dir_locks)
            targets.append(NodeScanTarget(manifest, lock, NODE_LOCK_KINDS[lock.name]))
        else:
            targets.append(NodeScanTarget(manifest, None, None))
    for parent in sorted(by_dir):
        if parent in manifest_dirs:
            continue
        lock = _preferred(by_dir[parent])
        targets.append(NodeScanTarget(None, lock, NODE_LOCK_KINDS[lock.name]))
    targets.sort(key=lambda t: str(t.manifest or t.lockfile))
    truncated = hit_limit or len(targets) > MAX_NODE_MANIFESTS
    return targets[:MAX_NODE_MANIFESTS], truncated


def npm_dev_packages(manifest: Path | None) -> set[str]:
    """devDependencies names from one package.json (yarn/pnpm scope labels)."""
    if manifest is None:
        return set()
    data = read_json_capped(manifest)
    dev = data.get("devDependencies") if data else None
    if not isinstance(dev, dict):
        return set()
    return {name for name in dev if isinstance(name, str) and name}


def npm_context(manifest: Path | None) -> Callable[[str, str], tuple[list[str], bool]]:
    """Flat ([package], is_dev) context for non-package-lock inputs."""
    dev = npm_dev_packages(manifest)

    def _ctx(package: str, _version: str) -> tuple[list[str], bool]:
        return [package], package in dev

    return _ctx


# --- Python inputs (FR-7 D1) ---

PYTHON_LOCK_NAMES = ("poetry.lock", "Pipfile.lock", "pdm.lock", "uv.lock")
PYTHON_UNPINNED_MARKERS = ("pyproject.toml", "setup.py", "setup.cfg", "Pipfile")
MAX_PYTHON_MANIFESTS = 20
MAX_LOCK_PARSE_BYTES = 10_000_000

_DEV_NAME_RE = re.compile(r"(^|[-_.])(dev|test|tests|docs)([-_.]|$)")
_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9._-]+)(\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<|;|$)")


def normalize_dist_name(name: str) -> str:
    """PEP 503 normalized distribution name for comparisons."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _inside(workdir: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(workdir.resolve())
    except (OSError, ValueError):
        return False
    return True


_MAX_MANIFEST_INCLUDE_DEPTH = 5


def requirement_include_target(line: str) -> tuple[str, str] | None:
    """(kind, target) for -r/-c include lines, else None.

    kind is "require" (-r/--requirement) or "constraint" (-c/--constraint).
    """
    text = line.split("#", 1)[0].strip()
    if not text or text.endswith("\\"):
        return None
    parts = text.split()
    head = parts[0]
    if head in ("-r", "--requirement", "-c", "--constraint") and len(parts) > 1:
        kind = "constraint" if head in ("-c", "--constraint") else "require"
        return kind, parts[1].strip("'\"")
    if text.startswith("--requirement="):
        return "require", text.split("=", 1)[1].strip().strip("'\"")
    if text.startswith("--constraint="):
        return "constraint", text.split("=", 1)[1].strip().strip("'\"")
    return None


def _expand_requirement_includes(workdir: Path, files: list[Path]) -> list[Path]:
    """In-repo .txt files reachable via -r/-c includes (cycle/depth guarded).

    A constraint that still pins the old version must be bumped and rescanned
    with the rest, or a root pin validates while the constraint holds.
    """
    resolved_workdir = workdir.resolve()
    seen: set[Path] = set()
    for existing in files:
        try:
            seen.add(existing.resolve())
        except OSError:
            continue
    extra: list[Path] = []
    stack = [(path, 0) for path in files if path.suffix == ".txt"]
    while stack:
        path, depth = stack.pop()
        if depth >= _MAX_MANIFEST_INCLUDE_DEPTH:
            continue
        text = _lock_text(path)
        if text is None:
            continue
        for line in text.splitlines():
            found = requirement_include_target(line)
            if found is None:
                continue
            try:
                candidate = (path.parent / found[1]).resolve()
                candidate.relative_to(resolved_workdir)
            except (OSError, ValueError):
                continue  # missing, or escaping the repo
            if candidate.suffix != ".txt" or not candidate.is_file() or candidate in seen:
                continue
            seen.add(candidate)
            extra.append(candidate)
            stack.append((candidate, depth + 1))
    return extra


def _is_python_scannable(path: Path) -> bool:
    name = path.name
    if name in PYTHON_LOCK_NAMES:
        return True
    if name.startswith("requirements") and name.endswith(".txt"):
        return True
    return name.endswith(".txt") and path.parent.name == "requirements"


@dataclass
class _PythonGenPlan:
    """One executable generation: optional write_first, then tool argv."""

    tool: str
    argv: list[str]
    output: str  # expected lock/output filename
    write_first: tuple[str, str] | None = None  # (filename, content)


_PYTHON_GENERATABLE = ("pyproject.toml", "Pipfile", "requirements.in", "setup.py", "setup.cfg")


def _string_list(node: ast.AST) -> list[str] | None:
    """Literal string elements, else None (no BinOp/Call/f-string)."""
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    out = []
    for elt in node.elts:
        if not isinstance(elt, ast.Constant) or not isinstance(elt.value, str):
            return None
        out.append(elt.value)
    return out


def _clean_requirement_lines(raw: str) -> str | None:
    """Joined usable requirement lines, else None when empty/unsafe."""
    lines = []
    for line in raw.splitlines():
        code = line.split("#", 1)[0].strip()
        if not code:
            continue
        if code.startswith("-"):
            return None  # options/includes: not a plain requirement set
        lines.append(code)
    return "\n".join(lines) + "\n" if lines else None


def _setup_py_requires(text: str) -> str | None:
    """requirements.in content from setup.py's install_requires, else None.

    Static only (never executes setup.py): literal lists, plus module-level
    NAME = [...] aliases. Dynamic requirements refuse to guess.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    literals: dict[str, list[str]] = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            items = _string_list(node.value)
            if items is not None:
                literals[node.targets[0].id] = items
    for child in ast.walk(tree):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        is_setup = (isinstance(func, ast.Name) and func.id == "setup") or (
            isinstance(func, ast.Attribute) and func.attr == "setup"
        )
        if not is_setup:
            continue
        for kw in child.keywords:
            if kw.arg == "install_requires":
                reqs = _string_list(kw.value)
                if reqs is None and isinstance(kw.value, ast.Name):
                    reqs = literals.get(kw.value.id)
                if reqs is None:
                    return None  # dynamic requirements: refuse to guess
                return _clean_requirement_lines("\n".join(reqs))
    return None


def _setup_cfg_requires(text: str) -> str | None:
    """requirements.in content from setup.cfg's install_requires, else None."""
    try:
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(text)
        raw = parser.get("options", "install_requires", fallback="")
    except (configparser.Error, ValueError):
        return None
    return _clean_requirement_lines(raw)


def _setup_requires_text(manifest: Path) -> str | None:
    text = _lock_text(manifest)
    if text is None:
        return None
    if manifest.name == "setup.cfg":
        return _setup_cfg_requires(text)
    return _setup_py_requires(text)


def _has_content_lines(text: str) -> bool:
    return any(line.split("#", 1)[0].strip() for line in text.splitlines())


def _python_generation_plan(manifest: Path) -> _PythonGenPlan | None:
    """Executable generation plan for one manifest; None when nothing to do.

    Pipfile → pipenv; [tool.poetry] → poetry; [tool.pdm] → pdm; other
    [project] → uv; requirements.in → uv pip compile; setup.py/setup.cfg
    → extract to requirements.in, then compile. Tool-only configs, empty
    inputs, dynamic setup.py, and setup beside an existing requirements.in
    (declared input wins; never clobbered) yield None.
    """
    name = manifest.name
    if name == "Pipfile":
        return _PythonGenPlan("pipenv", ["lock"], "Pipfile.lock")
    if name == "requirements.in":
        text = _lock_text(manifest)
        if text is None or not _has_content_lines(text):
            return None
        return _PythonGenPlan(
            "uv",
            ["pip", "compile", "requirements.in", "-o", "requirements.txt"],
            "requirements.txt",
        )
    if name in ("setup.py", "setup.cfg"):
        if (manifest.parent / "requirements.in").is_file():
            return None
        text = _setup_requires_text(manifest)
        if text is None:
            return None
        return _PythonGenPlan(
            "uv",
            ["pip", "compile", "requirements.in", "-o", "requirements.txt"],
            "requirements.txt",
            write_first=("requirements.in", text),
        )
    if name != "pyproject.toml":
        return None
    text = _lock_text(manifest)
    if text is None:
        return None
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    tool = data.get("tool")
    if isinstance(tool, dict) and isinstance(tool.get("poetry"), dict):
        return _PythonGenPlan("poetry", ["lock", "--no-interaction"], "poetry.lock")
    if not isinstance(data.get("project"), dict):
        return None
    if isinstance(tool, dict) and isinstance(tool.get("pdm"), dict):
        return _PythonGenPlan("pdm", ["lock"], "pdm.lock")
    return _PythonGenPlan("uv", ["lock"], "uv.lock")


def _dir_has_scannable_python(directory: Path) -> bool:
    """True when the dir already holds a scannable Python input."""
    for name in ("requirements.txt", *PYTHON_LOCK_NAMES):
        try:
            if (directory / name).is_file():
                return True
        except OSError:
            continue
    try:
        return any(directory.glob("requirements-*.txt"))
    except OSError:
        return False


def _python_ancestor_owns(workdir: Path, manifest: Path) -> bool:
    """True when a strict ancestor dir holds a lockable Python manifest.

    Nested manifests under another Python project are members of it (uv
    workspaces, poetry monorepos): the ancestor's lock covers them, so
    generating a second lock would manufacture conflicting inputs.
    """
    if manifest.parent == workdir:
        return False
    try:
        rel = manifest.parent.relative_to(workdir)
    except ValueError:
        return False
    ancestor = workdir
    dirs = [workdir]
    for part in rel.parts[:-1]:
        ancestor = ancestor / part
        dirs.append(ancestor)
    for directory in dirs:
        for name in ("pyproject.toml", "Pipfile"):
            candidate = directory / name
            try:
                if not candidate.is_file():
                    continue
            except OSError:
                continue
            if _python_generation_plan(candidate) is not None:
                return True
    return False


def python_generation_pending(workdir: Path) -> bool:
    """True when the scan would generate/compile a Python input here.

    Dry-run (no tools): same walk, plans, and skip rules as ensure. The
    manifest cap is the caller's check (scan skips generation when
    discovery truncated).
    """
    manifests, _ = _walk_collect(
        workdir, lambda p: p.name in _PYTHON_GENERATABLE, limit=MAX_PYTHON_MANIFESTS
    )
    for manifest in manifests:
        if _python_generation_plan(manifest) is None:
            continue
        if _python_ancestor_owns(workdir, manifest):
            continue
        if _dir_has_scannable_python(manifest.parent):
            continue
        return True
    return False


def ensure_python_lockfiles(workdir: Path, scanned: list[Path]) -> tuple[list[Path], list[str]]:
    """Generate missing Python locks in-sandbox; (generated locks, notes).

    For every generatable manifest without a scannable input beside it,
    resolve with the native tool (poetry/pdm/uv/pipenv lock, or uv pip
    compile for requirements.in / setup.py / setup.cfg) so osv-scanner has
    pinned versions. Skips dirs that already have one and nested manifests
    owned by an ancestor project (workspace members). Bounded so the
    scanned total stays within MAX_PYTHON_MANIFESTS. Failures are named
    notes, never silent and never fatal to the run.
    """
    notes: list[str] = []
    generated: list[Path] = []
    compiled = 0
    budget = MAX_PYTHON_MANIFESTS - len(scanned)
    if budget <= 0:
        return generated, notes
    manifests, hit_limit = _walk_collect(
        workdir, lambda p: p.name in _PYTHON_GENERATABLE, limit=MAX_PYTHON_MANIFESTS
    )
    failures: list[str] = []
    compile_failures: list[str] = []
    first_error = ""
    first_compile_error = ""
    members = 0
    for manifest in manifests:
        if budget <= 0:
            break
        plan = _python_generation_plan(manifest)
        if plan is None:
            continue
        if _python_ancestor_owns(workdir, manifest):
            members += 1
            continue
        if _dir_has_scannable_python(manifest.parent):
            continue
        is_compile = plan.output not in PYTHON_LOCK_NAMES
        rel = manifest.relative_to(workdir).as_posix()
        budget -= 1
        if plan.write_first is not None:
            try:
                (manifest.parent / plan.write_first[0]).write_text(plan.write_first[1])
            except OSError as exc:
                compile_failures.append(rel)
                if not first_compile_error:
                    first_compile_error = f"cannot write {plan.write_first[0]}: {exc}"[:300]
                continue
        try:
            run_allowlisted(
                plan.tool,
                plan.argv,
                cwd=str(manifest.parent),
                timeout=LOCKFILE_TIMEOUT_SECONDS,
                allow_network=True,
            )
        except (RuntimeError, TimeoutError) as exc:
            if is_compile:
                compile_failures.append(rel)
                if not first_compile_error:
                    first_compile_error = str(exc)[:300]
            else:
                failures.append(rel)
                if not first_error:
                    first_error = str(exc)[:300]
            continue
        lock = manifest.parent / plan.output
        try:
            exists = lock.is_file()
        except OSError:
            exists = False
        if not exists:
            if is_compile:
                compile_failures.append(rel)
                if not first_compile_error:
                    first_compile_error = f"{plan.tool} produced no {plan.output}"
            else:
                failures.append(rel)
                if not first_error:
                    first_error = f"{plan.tool} produced no {plan.output}"
            continue
        generated.append(lock)
        if is_compile:
            compiled += 1
    locks = len(generated) - compiled
    if locks:
        notes.append(f"python: generated {locks} lockfile(s) in-sandbox")
    if compiled:
        notes.append(f"python: compiled {compiled} requirements file(s) in-sandbox")
    if failures:
        shown = ", ".join(sorted(failures)[:5])
        line = f"python: lockfile generation failed for {len(failures)} manifest(s) ({shown})"
        if first_error:
            line += f": {first_error}"
        notes.append(line)
    if compile_failures:
        shown = ", ".join(sorted(compile_failures)[:5])
        line = (
            f"python: requirements compile failed for {len(compile_failures)} manifest(s) ({shown})"
        )
        if first_compile_error:
            line += f": {first_compile_error}"
        notes.append(line)
    if members:
        notes.append(
            f"python: {members} nested manifest(s) under another project skipped "
            "(member of parent lock)"
        )
    if hit_limit and budget > 0:
        notes.append(f"python: lockfile generation candidates capped at {MAX_PYTHON_MANIFESTS}")
    return generated, notes


def discover_python_manifests(workdir: Path) -> tuple[list[Path], bool]:
    """Scannable Python inputs: top-level first, then a bounded nested walk.

    Legacy top-level order is preserved (requirements.txt,
    requirements-*.txt, requirements/*.txt, locks); nested matches sort
    after. The walk never descends into venvs (tracker D18 parity).
    -r/-c includes resolve to in-repo .txt files so included pins are
    scanned, bumped, and rescanned with the rest. Returns (files,
    truncated). Symlinks escaping the repo are excluded.
    """
    found: list[Path] = []
    seen: set[Path] = set()

    def consider(path: Path) -> None:
        try:
            key = path.resolve()
        except OSError:
            return
        if path.is_file() and _inside(workdir, path) and key not in seen:
            seen.add(key)
            found.append(path)

    consider(workdir / "requirements.txt")
    for path in sorted(workdir.glob("requirements-*.txt")):
        consider(path)
    req_dir = workdir / "requirements"
    if req_dir.is_dir() and _inside(workdir, req_dir):
        for path in sorted(req_dir.glob("*.txt")):
            consider(path)
    for name in PYTHON_LOCK_NAMES:
        consider(workdir / name)
    nested, nested_hit = _walk_collect(workdir, _is_python_scannable, limit=MAX_PYTHON_MANIFESTS)
    for path in nested:
        consider(path)
    for path in sorted(_expand_requirement_includes(workdir, found)):
        consider(path)
    if nested_hit or len(found) > MAX_PYTHON_MANIFESTS:
        return found[:MAX_PYTHON_MANIFESTS], True
    return found, False


def python_unpinned_note(workdir: Path, scanned: list[Path]) -> str:
    """Hint when Python exists but nothing scannable was found (FR-7 D1)."""
    if scanned:
        return ""
    markers, _ = _walk_collect(workdir, lambda p: p.name in PYTHON_UNPINNED_MARKERS, limit=10)
    if not markers:
        return ""
    rels = sorted(m.relative_to(workdir).as_posix() for m in markers)
    return (
        "python manifests without pinned lockfiles present "
        f"({', '.join(rels)}); add requirements.txt or a lockfile"
    )


def requirement_name(line: str) -> str | None:
    """Normalized package name of a requirements line, else None.

    Options (-r/-e/--*), comments, blanks, and direct URL references yield
    None; only name-plus-specifier pins are recognized.
    """
    text = line.split("#", 1)[0]
    if not text.strip() or text.lstrip()[:1] == "-":
        return None
    match = _REQ_NAME_RE.match(text)
    if match is None:
        return None
    return normalize_dist_name(match.group(1))


def _lock_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_LOCK_PARSE_BYTES:
            return None
        return path.read_text()
    except OSError:
        return None


def _requirements_names(path: Path) -> set[str]:
    text = _lock_text(path)
    if text is None:
        return set()
    names: set[str] = set()
    for line in text.splitlines():
        name = requirement_name(line)
        if name:
            names.add(name)
    return names


def python_dev_packages(files: list[Path]) -> set[str]:
    """Normalized names of dev-scoped deps (FR-2 D5 scope labels).

    Heuristic per format; unknown layouts default to prod. Scope only tunes
    priority — dev findings are never silent — so misses are low-impact.
    """
    dev: set[str] = set()
    for path in files:
        if path.suffix == ".txt":
            # Stem only: parent dirs are checkout paths (often *test* tmpdirs),
            # never a scope signal.
            if _DEV_NAME_RE.search(path.stem):
                dev.update(_requirements_names(path))
            continue
        text = _lock_text(path)
        if text is None:
            continue
        if path.name == "Pipfile.lock":
            try:
                data = json.loads(text)
            except ValueError:
                continue
            develop = data.get("develop") if isinstance(data, dict) else None
            if isinstance(develop, dict):
                dev.update(normalize_dist_name(str(n)) for n in develop)
        elif path.name == "poetry.lock":
            try:
                data = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                continue
            packages = data.get("package", [])
            if not isinstance(packages, list):
                continue
            for entry in packages:
                if not isinstance(entry, dict):
                    continue
                groups = entry.get("groups", [])
                if entry.get("category") == "dev" or (isinstance(groups, list) and "dev" in groups):
                    dev.add(normalize_dist_name(str(entry.get("name", ""))))
        elif path.name == "pdm.lock":
            try:
                data = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                continue
            packages = data.get("package", [])
            if not isinstance(packages, list):
                continue
            for entry in packages:
                if not isinstance(entry, dict):
                    continue
                groups = entry.get("groups", [])
                if isinstance(groups, list) and "dev" in groups and "default" not in groups:
                    dev.add(normalize_dist_name(str(entry.get("name", ""))))
        elif path.name == "uv.lock":
            try:
                data = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                continue
            packages = data.get("package", [])
            if not isinstance(packages, list):
                continue
            dev_reqs: set[str] = set()
            prod_reqs: set[str] = set()
            for entry in packages:
                if not isinstance(entry, dict):
                    continue
                for dep in entry.get("dev-dependencies", []) or []:
                    name = _uv_dep_name(dep)
                    if name:
                        dev_reqs.add(name)
                for dep in entry.get("dependencies", []) or []:
                    name = _uv_dep_name(dep)
                    if name:
                        prod_reqs.add(name)
            dev.update(dev_reqs - prod_reqs)
    return dev


def _uv_dep_name(dep: object) -> str | None:
    """Normalized name of a uv.lock dependency entry (string or {name = …})."""
    if isinstance(dep, str):
        return requirement_name(dep)
    if isinstance(dep, dict):
        name = dep.get("name")
        if isinstance(name, str) and name:
            return normalize_dist_name(name)
    return None


def python_context(files: list[Path]) -> Callable[[str, str], tuple[list[str], bool]]:
    """Flat ([package], is_dev) context; lock dep trees are deferred (FR-7)."""
    dev = python_dev_packages(files)

    def _ctx(package: str, _version: str) -> tuple[list[str], bool]:
        return [package], normalize_dist_name(package) in dev

    return _ctx


def merge_drafts(lists: list[list[dict]]) -> tuple[list[dict], int]:
    """Merge per-file drafts; loud on severity conflict, first-wins on dupes.

    Returns (drafts, cross_ecosystem_skipped). The same (package, advisory)
    from two ecosystems keeps the first file's draft — the unique constraint
    has no ecosystem leg, and flip-flopping would be worse.
    """
    merged: dict[tuple[str, str], dict] = {}
    skipped = 0
    for drafts in lists:
        for draft in drafts:
            key = (draft["package"], draft["advisory_id"])
            if key not in merged:
                merged[key] = draft
                continue
            prior = merged[key]
            if prior["severity_score"] != draft["severity_score"]:
                raise ScanError(
                    f"severity conflict for {key[0]} {key[1]}: "
                    f"{prior['severity_score']} vs {draft['severity_score']}"
                )
            if (prior.get("ecosystem") or "") != (draft.get("ecosystem") or ""):
                skipped += 1
            # identical dupes collapse silently (same-file and cross-file)
    return list(merged.values()), skipped


def _group_severities(pkg: dict) -> dict[str, float]:
    """osv-scanner group max_severity by OSV id and alias.

    OSV records carry CVSS *vectors* (unparseable without a CVSS library);
    the scanner's per-group numeric max is the usable severity signal.
    """
    out: dict[str, float] = {}
    for group in pkg.get("groups", []) or []:
        try:
            score = float(str(group.get("max_severity", "")))
        except (TypeError, ValueError):
            continue
        for oid in list(group.get("ids", []) or []) + list(group.get("aliases", []) or []):
            out[str(oid)] = score
    return out


def normalize(
    osv: dict,
    lockfile: Path,
    kev_ids: set[str],
    *,
    context: Callable[[str, str], tuple[list[str], bool]] | None = None,
) -> list[dict]:
    """Collapse osv-scanner JSON to D6 finding drafts. Loud on severity conflict.

    context overrides lockfile_context for non-package-lock inputs (FR-7
    python, yarn/pnpm): it maps (package, version) to (dependency path,
    is_dev).
    """
    drafts: dict[tuple[str, str], dict] = {}
    index = None
    if context is None:
        index = lockfile_package_index(load_lockfile_packages(lockfile))
    for result in osv.get("results", []) or []:
        for pkg in result.get("packages", []) or []:
            info = pkg.get("package", {}) or {}
            name = str(info.get("name", ""))
            version = str(info.get("version", ""))
            ecosystem = info.get("ecosystem")
            if not valid_osv_name(name):
                log.debug("dropping finding with malformed package name: %r", name)
                continue
            if any(char.isspace() or ord(char) < 32 for char in version):
                version = ""  # display-only; never trust scanner version bytes
            group_sev = _group_severities(pkg)
            for vuln in pkg.get("vulnerabilities", []) or []:
                osv_id = str(vuln.get("id", ""))
                aliases = [str(a) for a in (vuln.get("aliases", []) or [])]
                advisory = canonical_id(osv_id, aliases)
                score, source = _severity(vuln)
                if score is None:
                    for oid in [osv_id, *aliases]:
                        if oid in group_sev:
                            score, source = group_sev[oid], "osv-scanner-group"
                            break
                key = (name, advisory)
                if key in drafts and drafts[key]["severity_score"] != score:
                    raise ScanError(
                        f"severity conflict for {name} {advisory}: "
                        f"{drafts[key]['severity_score']} vs {score}"
                    )
                if key in drafts:
                    continue
                if context is not None:
                    dep_path, is_dev = context(name, version)
                elif index is not None:
                    dep_path, is_dev = indexed_lockfile_context(index, name, version)
                else:
                    raise ScanError("internal error: no context and no lockfile index")
                citations = [
                    str(r["url"])
                    for r in (vuln.get("references", []) or [])
                    if isinstance(r.get("url"), str)
                    and r["url"].startswith(("http://", "https://"))
                ]
                if osv_id:
                    citations.append(f"https://osv.dev/vulnerability/{osv_id}")
                drafts[key] = {
                    "package": name,
                    "installed_version": version,
                    "advisory_id": advisory,
                    "ecosystem": str(ecosystem)[:50] if ecosystem else None,
                    "aliases": aliases,
                    "severity_score": score,
                    "severity_source": source,
                    "kev_exploited": advisory.upper() in kev_ids,
                    "dep_path": dep_path,
                    "scope": (FindingScope.DEV if is_dev else FindingScope.PROD),
                    "fixed_versions": _fixed_versions(vuln),
                    "citations": citations,
                }
    return list(drafts.values())


def _apply_draft(row: Finding, draft: dict) -> None:
    for field, value in draft.items():
        setattr(row, field, value)


def persist_findings(repo_id: int, run_id: int, drafts: list[dict]) -> tuple[int, int, list[int]]:
    """Upsert by (repo, package, advisory). Status stays verdict-owned.

    Insert-first with a savepoint per draft: concurrent scans serialize
    on the unique constraint instead of crashing, and the rollback only
    discards the losing insert, never the rest of the batch.
    """
    created = updated = 0
    ids: list[int] = []
    with session_scope() as db:
        for draft in drafts:
            row = Finding(repo_id=repo_id, first_run_id=run_id, **draft)
            try:
                with db.begin_nested():
                    # add() must happen inside: begin_nested snapshots by
                    # flushing, which would run the INSERT outside the savepoint.
                    db.add(row)
                    db.flush()
            except IntegrityError:
                existing = db.scalar(
                    select(Finding).where(
                        Finding.repo_id == repo_id,
                        Finding.package == draft["package"],
                        Finding.advisory_id == draft["advisory_id"],
                    )
                )
                if existing is None:
                    raise
                row = existing
                _apply_draft(row, draft)
                updated += 1
            else:
                created += 1
            ids.append(row.id)
    return created, updated, ids


def _finish_run(run_id: int, status: RunStatus, notes: list[str]) -> None:
    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        if run is None:
            return
        run.status = status
        run.finished_at = datetime.now(UTC)
        joined = "\n".join(n for n in notes if n)
        if joined:
            prior = f"{run.notes}\n" if run.notes else ""
            run.notes = prior + joined


def run_scan(repo_id: int, run_id: int, *, source_dir: Path | None = None) -> dict:
    """Execute one scan run; failures land on the run record, not as raises."""
    assert_host_execution_allowed()
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        run = db.get(ScanRun, run_id)
        if repo is None or run is None:
            raise ValueError(f"Unknown repo {repo_id} or run {run_id}.")
        db.expunge(repo)
    workdir = source_dir
    owned = workdir is None
    try:
        if workdir is None:
            append_run_note(run_id, f"scan: cloning {repo.name}...")
            clone_started = time.monotonic()
            workdir = make_workdir(f"scan-{run_id}-")
            clone_repo(repo, workdir)
            append_run_note(run_id, f"scan: cloned in {time.monotonic() - clone_started:.1f}s")
        from security_agent.policy.readme import sync_repo_readme

        readme_note = sync_repo_readme(repo_id, workdir)
        if readme_note:
            append_run_note(run_id, readme_note)
        kev = kev_exploited_ids()
        append_run_note(run_id, f"scan: KEV catalog ready ({len(kev)} exploited ids)")
        per_file: list[list[dict]] = []
        node_targets, node_truncated = discover_node_manifests(workdir)
        if node_truncated:
            append_run_note(run_id, f"node: manifest list capped at {MAX_NODE_MANIFESTS}")
        if not node_targets:
            append_run_note(run_id, "node: no package.json or lockfiles found; skipped")
        else:
            scanned_count = 0
            skipped_manifests: list[str] = []
            for target in node_targets:
                lock = target.lockfile
                if lock is None:
                    anchor = target.manifest
                    if anchor is not None and anchor.parent == workdir:
                        lock, generated = ensure_lockfile(workdir)
                        if generated:
                            append_run_note(
                                run_id, "lockfile generated in-sandbox (scripts disabled)"
                            )
                    else:
                        skipped_manifests.append(
                            anchor.relative_to(workdir).as_posix() if anchor else "?"
                        )
                        continue
                if lock.name == "package-lock.json":
                    vulns = normalize(scan_lockfile(lock), lock, kev)
                else:
                    ctx = npm_context(target.manifest)
                    vulns = normalize(scan_lockfile(lock), lock, kev, context=ctx)
                per_file.append(vulns)
                rel = lock.relative_to(workdir).as_posix() if workdir in lock.parents else lock.name
                append_run_note(run_id, f"node: {rel}: {len(vulns)} finding(s)")
                scanned_count += 1
            if scanned_count:
                append_run_note(run_id, f"node: scanned {scanned_count} lockfile(s)")
            if skipped_manifests:
                append_run_note(
                    run_id,
                    f"node: {len(skipped_manifests)} manifest(s) without lockfile skipped "
                    f"({', '.join(sorted(skipped_manifests)[:5])})",
                )
        py_files, truncated = discover_python_manifests(workdir)
        if truncated:
            append_run_note(run_id, f"python: manifest list capped at {MAX_PYTHON_MANIFESTS}")
        if not truncated:
            gen_locks, gen_notes = ensure_python_lockfiles(workdir, py_files)
            for gen_note in gen_notes:
                append_run_note(run_id, gen_note)
            py_files = [*py_files, *gen_locks]
        unpinned = python_unpinned_note(workdir, py_files)
        if unpinned:
            append_run_note(run_id, f"python: {unpinned}")
        if py_files:
            ctx = python_context(py_files)
            for manifest in py_files:
                vulns = normalize(scan_lockfile(manifest), manifest, kev, context=ctx)
                per_file.append(vulns)
                rel = (
                    manifest.relative_to(workdir).as_posix()
                    if workdir in manifest.parents
                    else manifest.name
                )
                append_run_note(run_id, f"python: {rel}: {len(vulns)} finding(s)")
            append_run_note(run_id, f"python: scanned {len(py_files)} manifest(s)")
        # Secrets piggyback the run with or without vuln manifests — a
        # manifest-less repo can still leak secrets. Never fails the run
        # (H3 fetch_signals isolation precedent).
        from security_agent.worker.secrets import SecretError, run_secrets_stage

        append_run_note(run_id, "secrets: scanning workdir...")
        try:
            secret_notes = run_secrets_stage(repo_id, run_id, workdir)
        except (SecretError, RuntimeError, TimeoutError, OSError) as exc:
            secret_notes = [f"secrets: stage failed ({exc})"]
            log.warning("secrets stage failed for run %d: %s", run_id, exc)
            from security_agent.audit import get_shared_log

            # Loud run note + audit warning (C7); the exception text stays
            # out of the audit line.
            get_shared_log().append(
                action_class="secret",
                decision="warning",
                line=f"repo={repo_id} run={run_id} stage-failed",
            )
        if not per_file:
            if not node_targets and not py_files:
                append_run_note(run_id, "no supported manifests; nothing to scan")
            else:
                append_run_note(run_id, "no scannable lockfiles; nothing to scan")
            for secret_note in secret_notes:
                append_run_note(run_id, secret_note)
            _finish_run(run_id, RunStatus.DONE, [])
            return {"status": RunStatus.DONE.value, "created": 0, "updated": 0, "finding_ids": []}
        drafts, skipped = merge_drafts(per_file)
        if skipped:
            append_run_note(run_id, f"cross-ecosystem duplicates skipped: {skipped}")
        append_run_note(run_id, f"scan: saving {len(drafts)} finding(s)...")
        created, updated, ids = persist_findings(repo_id, run_id, drafts)
        append_run_note(run_id, f"findings: {created} new, {updated} updated")
        from security_agent.policy.enforce import apply_ingest_silence

        silenced = apply_ingest_silence(repo_id, ids)
        if silenced:
            append_run_note(run_id, f"policy: {silenced} findings silenced by guardrail")
        for secret_note in secret_notes:
            append_run_note(run_id, secret_note)
        _finish_run(run_id, RunStatus.DONE, [])
        from security_agent.worker.deliver import sync_proposal_states

        try:
            synced = sync_proposal_states(repo_id)
            _finish_run(run_id, RunStatus.DONE, [f"state sync: {synced}"])
        except Exception as exc:  # noqa: BLE001 - sync never fails the scan
            _finish_run(run_id, RunStatus.DONE, [f"state sync failed: {exc}"])
        return {
            "status": RunStatus.DONE.value,
            "created": created,
            "updated": updated,
            "finding_ids": ids,
        }
    except (ScanError, RuntimeError, TimeoutError) as exc:
        _finish_run(run_id, RunStatus.FAILED, [f"failed: {exc}"])
        return {"status": RunStatus.FAILED.value, "error": str(exc)}
    finally:
        if owned and workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)
