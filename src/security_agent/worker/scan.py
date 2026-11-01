"""Sandbox scan: clone, lockfile, osv-scanner, KEV join, D6 normalize (FR-2).

Runs in a per-run temp dir in dev/test. Prod refuses host execution until
the Docker sandbox lands (NFR-1 fail-closed).
"""

import csv
import json
import logging
import re
import shutil
import threading
import tomllib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

import httpx
from packaging.version import InvalidVersion, Version
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

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


def discover_python_manifests(workdir: Path) -> tuple[list[Path], bool]:
    """Scannable Python inputs, top-level only (never descending into venvs).

    -r/-c includes resolve to in-repo .txt files so included pins are scanned,
    bumped, and rescanned with the rest. Returns (files, truncated).
    Symlinks escaping the repo are excluded.
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
    for path in sorted(_expand_requirement_includes(workdir, found)):
        consider(path)
    if len(found) > MAX_PYTHON_MANIFESTS:
        return found[:MAX_PYTHON_MANIFESTS], True
    return found, False


def python_unpinned_note(workdir: Path, scanned: list[Path]) -> str:
    """Hint when Python exists but nothing scannable was found (FR-7 D1)."""
    if scanned:
        return ""
    markers = [n for n in PYTHON_UNPINNED_MARKERS if (workdir / n).is_file()]
    if not markers:
        return ""
    return (
        "python manifests without pinned lockfiles present "
        f"({', '.join(sorted(markers))}); add requirements.txt or a lockfile"
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

    context overrides lockfile_context for non-npm inputs (FR-7): it maps
    (package, version) to (dependency path, is_dev).
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
        prior = f"{run.notes}\n" if run.notes else ""
        run.notes = prior + "\n".join(n for n in notes if n)


def run_scan(repo_id: int, run_id: int, *, source_dir: Path | None = None) -> dict:
    """Execute one scan run; failures land on the run record, not as raises."""
    assert_host_execution_allowed()
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        run = db.get(ScanRun, run_id)
        if repo is None or run is None:
            raise ValueError(f"Unknown repo {repo_id} or run {run_id}.")
        db.expunge(repo)
    notes: list[str] = []
    workdir = source_dir
    owned = workdir is None
    try:
        if workdir is None:
            workdir = make_workdir(f"scan-{run_id}-")
            clone_repo(repo, workdir)
        kev = kev_exploited_ids()
        per_file: list[list[dict]] = []
        if (workdir / "package.json").exists() or (workdir / "package-lock.json").exists():
            lockfile, generated = ensure_lockfile(workdir)
            if generated:
                notes.append("lockfile generated in-sandbox (scripts disabled)")
            per_file.append(normalize(scan_lockfile(lockfile), lockfile, kev))
        else:
            notes.append("node: no package.json/package-lock.json; skipped")
        py_files, truncated = discover_python_manifests(workdir)
        if truncated:
            notes.append(f"python: manifest list capped at {MAX_PYTHON_MANIFESTS}")
        unpinned = python_unpinned_note(workdir, py_files)
        if unpinned:
            notes.append(f"python: {unpinned}")
        if py_files:
            ctx = python_context(py_files)
            for manifest in py_files:
                per_file.append(normalize(scan_lockfile(manifest), manifest, kev, context=ctx))
            notes.append(f"python: scanned {len(py_files)} manifest(s)")
        # Secrets piggyback the run with or without vuln manifests — a
        # manifest-less repo can still leak secrets. Never fails the run
        # (H3 fetch_signals isolation precedent).
        from security_agent.worker.secrets import SecretError, run_secrets_stage

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
            notes.append("no supported manifests; nothing to scan")
            notes.extend(secret_notes)
            _finish_run(run_id, RunStatus.DONE, notes)
            return {"status": RunStatus.DONE.value, "created": 0, "updated": 0, "finding_ids": []}
        drafts, skipped = merge_drafts(per_file)
        if skipped:
            notes.append(f"cross-ecosystem duplicates skipped: {skipped}")
        created, updated, ids = persist_findings(repo_id, run_id, drafts)
        notes.append(f"findings: {created} new, {updated} updated")
        notes.extend(secret_notes)
        _finish_run(run_id, RunStatus.DONE, notes)
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
        notes.append(f"failed: {exc}")
        _finish_run(run_id, RunStatus.FAILED, notes)
        return {"status": RunStatus.FAILED.value, "error": str(exc)}
    finally:
        if owned and workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)
