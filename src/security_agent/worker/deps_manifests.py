"""Direct-production manifest discovery + parsing + lockfile resolution (D12/D18/D22).

The tracked set is only direct production packages declared in the
manifest (D3); transitive packages stay with the vulnerability Finding
pipeline. Each manifest resolves installed versions from its own
lockfile (D18); without a lockfile the manifest spec is the fallback
source of truth (D3).

Production-section boundary (D22): Node tracks `dependencies` +
`optionalDependencies` (optional labelled), never `devDependencies`;
`peerDependencies` are not rows but a peer range excluding the latest
is noted in the report. Python tracks `project.dependencies` + every
`project.optional-dependencies` extra (labelled by extra); Poetry dev
groups, `dependency-groups`, `Pipfile` develop, and dev-named
requirements files are excluded.
"""

import logging
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from security_agent.worker.scan import (
    _DEV_NAME_RE,
    normalize_dist_name,
    read_json_capped,
    read_text_capped,
    requirement_include_target,
    requirement_name,
)

log = logging.getLogger(__name__)

MAX_DEP_MANIFESTS = 20  # D18 safety cap (precedent: MAX_PYTHON_MANIFESTS)

_WALK_SKIP = frozenset(
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

_NPM_LOCK_NAMES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")
_PY_LOCK_NAMES = ("poetry.lock", "Pipfile.lock", "pdm.lock", "uv.lock")

_NPM_EXACT_RE = re.compile(r"^[=v]?\d")
_YARN_VERSION_RE = re.compile(r'^\s+version\s*:?\s+"?([^"\s]+)"?\s*$')
_REQ_PIN_RE = re.compile(r"==\s*([^,;\s#]+)")
_PY_SPEC_RE = re.compile(r"^\s*([A-Za-z0-9._-]+(?:\[[^\]]*\])?)\s*(.*)$")
_NPM_RANGE_PREFIX_RE = re.compile(r"^(\^|~|>=?|<=?|=|v)?(.+)$")


@dataclass
class TrackedPackage:
    """One direct production package declared in a manifest."""

    name: str
    spec: str  # manifest spec text, e.g. ^1.2.3 / ==1.2.3 / >=1.0
    section: str  # D22 label: dependencies | optional | extra:<name> | requirements | ...


@dataclass
class DepManifest:
    """One discovered manifest with its parsed production set."""

    path: Path  # absolute
    rel: str  # repo-relative posix (Dependency key leg)
    ecosystem: str  # npm | pip
    kind: str  # package.json | pyproject | requirements | Pipfile
    packages: list[TrackedPackage] = field(default_factory=list)
    failed: bool = False  # freshness failed; rows sit at last-known values (D19)
    lockfile: Path | None = None
    lock_kind: str | None = None  # package-lock | yarn | pnpm | requirements | pipfile | uv ...
    peer_ranges: dict[str, str] = field(default_factory=dict)  # npm peers (D22 note)
    python_locks: list[Path] = field(default_factory=list)  # extra resolved sources
    extra_files: list[Path] = field(default_factory=list)  # -r/-c includes (requirements)


def _inside(workdir: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(workdir.resolve())
    except (OSError, ValueError):
        return False
    return True


def discover_dep_manifests(workdir: Path) -> tuple[list[DepManifest], bool]:
    """Walk the repo for D12 manifests (D18 monorepo walk).

    Skips node_modules/.venv/VCS dirs; bounds the walk at
    MAX_DEP_MANIFESTS. Returns (manifests, truncated): hitting the cap is
    reported by callers on the Dependencies tab, never silent.
    """
    found: list[Path] = []
    truncated = False
    try:
        resolved_root = workdir.resolve()
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
            name = entry.name
            if entry.is_dir() and not entry.is_symlink():
                if name in _WALK_SKIP or name.startswith(".") and name in (
                    ".git",
                    ".hg",
                    ".svn",
                ):
                    continue
                if _inside(workdir, entry):
                    stack.append(entry)
                continue
            if not entry.is_file() or entry.is_symlink():
                continue
            if not _is_manifest_name(entry):
                continue
            if len(found) >= MAX_DEP_MANIFESTS:
                truncated = True
                break
            found.append(entry)
        if truncated:
            break
    found.sort()
    manifests = [_load_manifest(workdir, resolved_root, path) for path in found]
    return [m for m in manifests if m is not None], truncated


def _is_manifest_name(path: Path) -> bool:
    name = path.name
    if name in ("package.json", "pyproject.toml", "Pipfile"):
        return True
    if name.startswith("requirements") and name.endswith(".txt"):
        return True
    # Common layout: requirements/base.txt, requirements/prod.txt, ...
    if name.endswith(".txt") and path.parent.name == "requirements":
        return True
    return False


def load_manifest_file(path: Path, *, workdir: Path | None = None) -> DepManifest | None:
    """Parse one manifest file by path (patch-time re-parse verification)."""
    name = path.name
    rel = path.name
    if name == "package.json":
        return _load_package_json(path, rel)
    if name == "pyproject.toml":
        return _load_pyproject(path, rel)
    if name == "Pipfile":
        return _load_pipfile(path, rel)
    if workdir is not None:
        return _load_requirements(path, rel, workdir)
    return None


def _load_manifest(workdir: Path, resolved_root: Path, path: Path) -> DepManifest | None:
    try:
        rel = path.resolve().relative_to(resolved_root).as_posix()
    except (OSError, ValueError):
        return None
    name = path.name
    if name == "package.json":
        return _load_package_json(path, rel)
    if name == "pyproject.toml":
        return _load_pyproject(path, rel)
    if name == "Pipfile":
        return _load_pipfile(path, rel)
    return _load_requirements(path, rel, workdir)


# --- npm ---


def _load_package_json(path: Path, rel: str) -> DepManifest | None:
    data = read_json_capped(path)
    if data is None:
        log.debug("dependencies: %s unreadable or not an object; skipped", rel)
        return DepManifest(path=path, rel=rel, ecosystem="npm", kind="package.json")
    manifest = DepManifest(path=path, rel=rel, ecosystem="npm", kind="package.json")
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        for pkg, spec in deps.items():
            if isinstance(pkg, str) and isinstance(spec, str) and pkg:
                manifest.packages.append(
                    TrackedPackage(name=pkg, spec=spec, section="dependencies")
                )
    optional = data.get("optionalDependencies")
    if isinstance(optional, dict):
        seen = {p.name for p in manifest.packages}
        for pkg, spec in optional.items():
            if isinstance(pkg, str) and isinstance(spec, str) and pkg and pkg not in seen:
                manifest.packages.append(
                    TrackedPackage(name=pkg, spec=spec, section="optional")
                )
    peers = data.get("peerDependencies")
    if isinstance(peers, dict):
        for pkg, spec in peers.items():
            if isinstance(pkg, str) and isinstance(spec, str) and pkg:
                manifest.peer_ranges[pkg] = spec
    for lock_name, lock_kind in (
        ("package-lock.json", "package-lock"),
        ("yarn.lock", "yarn"),
        ("pnpm-lock.yaml", "pnpm"),
    ):
        candidate = path.parent / lock_name
        try:
            if candidate.is_file():
                manifest.lockfile = candidate
                manifest.lock_kind = lock_kind
                break
        except OSError:
            continue
    return manifest


def npm_spec_base(spec: str) -> str:
    """Base version of an npm spec (^1.2.3 -> 1.2.3); ranges keep their text."""
    text = (spec or "").strip()
    if text.startswith(("http:", "https:", "git+", "file:", "link:", "workspace:")):
        return ""
    match = _NPM_RANGE_PREFIX_RE.match(text)
    if match is None:
        return text
    return match.group(2).strip().split(" ")[0]


def npm_spec_exact(spec: str) -> str | None:
    """Exact version when the spec pins one (1.2.3, =1.2.3, v1.2.3), else None."""
    text = (spec or "").strip()
    if not text or text[0] in "^~<>*| " or " " in text or text.startswith(
        ("http:", "https:", "git+", "file:", "link:", "workspace:", "npm:")
    ):
        return None
    if text.startswith("="):
        text = text[1:]
    text = text.removeprefix("v").removeprefix("V")
    if not text or not text[0].isdigit():
        return None
    return text


def resolve_npm_lock(manifest: DepManifest) -> dict[str, str]:
    """name -> installed version from the manifest's own lockfile (D3/D18)."""
    if manifest.lockfile is None or manifest.lock_kind is None:
        return {}
    try:
        if manifest.lock_kind == "package-lock":
            return _resolve_package_lock(manifest.lockfile)
        if manifest.lock_kind == "yarn":
            return _resolve_yarn_lock(manifest.lockfile)
        if manifest.lock_kind == "pnpm":
            return _resolve_pnpm_lock(manifest.lockfile)
    except OSError:
        return {}
    return {}


def _resolve_package_lock(lockfile: Path) -> dict[str, str]:
    data = read_json_capped(lockfile)
    packages = data.get("packages", {}) if data else {}
    if not isinstance(packages, dict):
        return {}
    out: dict[str, str] = {}
    for key, entry in packages.items():
        if not key or not isinstance(entry, dict):
            continue
        # Direct deps resolve at node_modules/<name> (no nested node_modules).
        segments = [s.strip("/") for s in key.split("node_modules/") if s.strip("/")]
        if len(segments) != 1:
            continue
        version = entry.get("version")
        if isinstance(version, str) and version:
            out.setdefault(segments[0], version)
    # Lockfile v1 ("dependencies" tree) fallback for direct deps.
    if not out and isinstance(data, dict):
        deps = data.get("dependencies")
        if isinstance(deps, dict):
            for pkg, entry in deps.items():
                if isinstance(entry, dict) and isinstance(entry.get("version"), str):
                    out[pkg] = str(entry["version"])
    return out


def _yarn_descriptor_package(descriptor: str) -> str | None:
    """Package name from one Yarn descriptor (`@scope/pkg@npm:^1`, `a@^1`)."""
    text = descriptor.strip().strip("\"'").strip()
    if not text:
        return None
    if text.startswith("@"):
        slash = text.find("/")
        if slash < 0:
            return None
        at = text.find("@", slash)
        return text[:at] if at > slash else text
    at = text.find("@")
    return text[:at] if at > 0 else text


def _resolve_yarn_lock(lockfile: Path) -> dict[str, str]:
    """Classic + Berry yarn.lock: descriptor blocks, then a version line.

    Classic: `a@^1.0.0:` + `  version "1.2.3"`.
    Berry: `"a@npm:^1.0.0", "a@npm:^1.1.0":` + `  version: 1.2.3`.
    """
    text = read_text_capped(lockfile)
    if text is None:
        return {}
    out: dict[str, str] = {}
    current: list[str] = []
    for line in text.splitlines():
        if not line.startswith((" ", "\t")) and line.rstrip().endswith(":"):
            header = line.strip().removesuffix(":")
            current = []
            for descriptor in header.split(","):
                package = _yarn_descriptor_package(descriptor)
                if package:
                    current.append(package)
            continue
        if not current:
            continue
        match = _YARN_VERSION_RE.match(line)
        if match:
            for package in current:
                out.setdefault(package, match.group(1))
            current = []
    return out


def _resolve_pnpm_lock(lockfile: Path) -> dict[str, str]:
    """pnpm-lock package keys across v6/v8 (`/name@ver`) and v9 (`name@ver`)."""
    text = read_text_capped(lockfile)
    if text is None:
        return {}
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line.startswith("  ") or line.startswith("   "):
            continue
        key = line.strip()
        if key.endswith(": {}"):
            key = key[:-4]
        elif key.endswith(":"):
            key = key[:-1]
        else:
            continue
        if "@" not in key:
            continue
        key = key.strip().strip("\"'").removeprefix("/")
        key = key.split("(", 1)[0]  # peer suffix: name@ver(peer@x)
        at = key.rfind("@", 1)
        if at <= 0:
            continue
        package, version = key[:at], key[at + 1 :]
        if not package or not version or " " in package or " " in version:
            continue
        if not (version[0].isdigit() or version[0] in "vV"):
            continue
        out.setdefault(package, version)
    return out


# --- Python ---


def _load_pyproject(path: Path, rel: str) -> DepManifest:
    manifest = DepManifest(path=path, rel=rel, ecosystem="pip", kind="pyproject")
    text = read_text_capped(path)
    if text is None:
        return manifest
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return manifest
    if not isinstance(data, dict):
        return manifest
    seen: set[str] = set()

    def _add(name: str, spec: str, section: str) -> None:
        # One row per (manifest, package): the Dependency key has no
        # section leg, so the first (primary) declaration wins and later
        # extras/groups for the same package do not flip its label.
        key = normalize_dist_name(name)
        if key in seen:
            return
        seen.add(key)
        manifest.packages.append(TrackedPackage(name=name, spec=spec, section=section))

    project = data.get("project")
    if isinstance(project, dict):
        deps = project.get("dependencies")
        if isinstance(deps, list):
            for entry in deps:
                parsed = _parse_pep508(entry)
                if parsed:
                    _add(parsed[0], parsed[1], "dependencies")
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for extra, entries in optional.items():
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    parsed = _parse_pep508(entry)
                    if parsed:
                        _add(parsed[0], parsed[1], f"extra:{extra}")
    poetry = data.get("tool", {}).get("poetry") if isinstance(data.get("tool"), dict) else None
    if isinstance(poetry, dict):
        deps = poetry.get("dependencies")
        if isinstance(deps, dict):
            for pkg, spec in deps.items():
                if pkg == "python":
                    continue
                _add(str(pkg), _poetry_spec(spec), "poetry")
        group = poetry.get("group")
        if isinstance(group, dict):
            for group_name, group_data in group.items():
                if group_name == "dev" or not isinstance(group_data, dict):
                    continue  # D22: Poetry dev groups excluded
                deps = group_data.get("dependencies")
                if isinstance(deps, dict):
                    for pkg, spec in deps.items():
                        _add(str(pkg), _poetry_spec(spec), f"poetry:{group_name}")
    for lock_name, lock_kind in (
        ("poetry.lock", "poetry"),
        ("pdm.lock", "pdm"),
        ("uv.lock", "uv"),
    ):
        candidate = path.parent / lock_name
        try:
            if candidate.is_file():
                if manifest.lockfile is None:
                    manifest.lockfile = candidate
                    manifest.lock_kind = lock_kind
                else:
                    manifest.python_locks.append(candidate)
        except OSError:
            continue
    return manifest


def _parse_pep508(entry: object) -> tuple[str, str] | None:
    """(name, spec) from a PEP 508 string; None for URLs/editables we cannot track."""
    if not isinstance(entry, str) or not entry.strip():
        return None
    text = entry.strip()
    if "://" in text or text.startswith(("-e", "--", ".")):
        return None
    match = _PY_SPEC_RE.match(text.split(";")[0])
    if match is None:
        return None
    name = match.group(1).strip().split("[", 1)[0].strip()  # extras are not identity
    spec = match.group(2).strip() or "*"
    if not name or "/" in name or "@" in name.split(",")[0]:
        return None
    return name, spec


def _poetry_spec(spec: object) -> str:
    """Spec text from a Poetry dependency value (string or {version = …} table)."""
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        version = spec.get("version")
        if isinstance(version, str) and version:
            return version
        git = spec.get("git")
        if isinstance(git, str):
            return f"git+{git}"
    return "*"


def _load_requirements(path: Path, rel: str, workdir: Path) -> DepManifest:
    manifest = DepManifest(
        path=path, rel=rel, ecosystem="pip", kind="requirements", lock_kind="requirements"
    )
    if _DEV_NAME_RE.search(path.stem):
        return manifest  # D22: dev-named requirements files excluded
    manifest.extra_files = _expand_dep_includes(workdir, path)
    files = [path, *manifest.extra_files]
    seen: set[str] = set()
    for req_file in files:
        if _DEV_NAME_RE.search(req_file.stem):
            continue
        text = read_text_capped(req_file)
        if text is None:
            continue
        for line in text.splitlines():
            name = requirement_name(line)
            if name is None or name in seen:
                continue
            seen.add(name)
            code = line.split("#", 1)[0]
            spec = _requirements_spec(code, name)
            manifest.packages.append(
                TrackedPackage(name=name, spec=spec, section="requirements")
            )
    return manifest


def _expand_dep_includes(workdir: Path, path: Path) -> list[Path]:
    """In-repo .txt files reachable via -r includes (depth/cycle guarded).

    -c constraint files bound versions; they are not declarations, so
    their pins never become tracked direct dependencies (D3).
    """
    try:
        resolved_workdir = workdir.resolve()
    except OSError:
        return []
    seen = {path}
    extra: list[Path] = []
    stack = [(path, 0)]
    while stack:
        current, depth = stack.pop()
        if depth >= 5:
            continue
        text = read_text_capped(current)
        if text is None:
            continue
        for line in text.splitlines():
            found = requirement_include_target(line)
            if found is None or found[0] != "require":
                continue
            try:
                candidate = (current.parent / found[1]).resolve()
                candidate.relative_to(resolved_workdir)
            except (OSError, ValueError):
                continue
            if candidate.suffix != ".txt" or not candidate.is_file() or candidate in seen:
                continue
            seen.add(candidate)
            extra.append(candidate)
            stack.append((candidate, depth + 1))
    return extra


def _requirements_spec(code: str, name: str) -> str:
    """Spec text after the package name (==1.2.3, >=1.0, or * for bare)."""
    match = re.match(r"^\s*[A-Za-z0-9._-]+(?:\[[^\]]*\])?\s*(.*)$", code)
    if match is None:
        return "*"
    rest = match.group(1).split(";")[0].strip()
    return rest or "*"


def _load_pipfile(path: Path, rel: str) -> DepManifest:
    manifest = DepManifest(path=path, rel=rel, ecosystem="pip", kind="Pipfile")
    text = read_text_capped(path)
    if text is None:
        return manifest
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return manifest
    if not isinstance(data, dict):
        return manifest
    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg, spec in packages.items():
            manifest.packages.append(
                TrackedPackage(name=str(pkg), spec=_pipfile_spec(spec), section="packages")
            )
    # D22: [dev-packages] excluded.
    lock = path.parent / "Pipfile.lock"
    try:
        if lock.is_file():
            manifest.lockfile = lock
            manifest.lock_kind = "pipfile"
    except OSError:
        pass
    return manifest


def _pipfile_spec(spec: object) -> str:
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        version = spec.get("version")
        if isinstance(version, str) and version and version != "*":
            return version
    return "*"


def pip_spec_base(spec: str) -> str | None:
    """Base version of a pip spec (>=1.0 -> 1.0, ~=1.2 -> 1.2), else None."""
    text = (spec or "").strip().strip("\"'")
    if not text or "://" in text:
        return None
    match = re.search(r"(?:==|>=|<=|~=|>|<|=)?\s*v?(\d+(?:\.\d+)*)", text.split(";")[0])
    return match.group(1) if match else None


def pip_spec_exact(spec: str) -> str | None:
    """Exact version when a pip spec pins one (==1.2.3), else None."""
    text = (spec or "").strip().strip("\"'")
    if "==" not in text:
        return None
    match = _REQ_PIN_RE.search(text.split(";")[0])
    if match is None:
        return None
    pinned = match.group(1).strip()
    if "," in pinned or " " in pinned or not pinned or "*" in pinned:
        return None
    return pinned


def resolve_pip_lock(manifest: DepManifest) -> dict[str, str]:
    """Normalized name -> installed version from the manifest's lock sources."""
    out: dict[str, str] = {}
    if manifest.kind == "requirements":
        for req_file in [manifest.path, *manifest.extra_files]:
            text = read_text_capped(req_file)
            if not text:
                continue
            for line in text.splitlines():
                name = requirement_name(line)
                if name is None:
                    continue
                match = _REQ_PIN_RE.search(line.split("#", 1)[0])
                if match:
                    out.setdefault(name, match.group(1).strip())
        return out
    locks = ([manifest.lockfile] if manifest.lockfile else []) + manifest.python_locks
    for lock in locks:
        if lock is None:
            continue
        resolved = _resolve_python_lock_file(lock)
        for name, version in resolved.items():
            out.setdefault(name, version)
    return out


def _resolve_python_lock_file(lock: Path) -> dict[str, str]:
    try:
        if lock.name == "Pipfile.lock":
            data = read_json_capped(lock)
            if not isinstance(data, dict):
                return {}
            out: dict[str, str] = {}
            for section in ("default", "develop"):
                entries = data.get(section)
                if isinstance(entries, dict):
                    for pkg, meta in entries.items():
                        if isinstance(meta, dict) and isinstance(
                            meta.get("version"), str
                        ):
                            out.setdefault(
                                normalize_dist_name(str(pkg)),
                                str(meta["version"]).lstrip("="),
                            )
            return out
        text = read_text_capped(lock)
        if text is None:
            return {}
        data = tomllib.loads(text)
    except (OSError, tomllib.TOMLDecodeError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    packages = data.get("package", [])
    if not isinstance(packages, list):
        return {}
    out = {}
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name, version = entry.get("name"), entry.get("version")
        if isinstance(name, str) and isinstance(version, str) and name and version:
            out.setdefault(normalize_dist_name(name), version)
    return out


def resolved_versions(manifest: DepManifest) -> dict[str, str]:
    """Whole lockfile resolution for one manifest (parse once, reuse)."""
    if manifest.ecosystem == "npm":
        return resolve_npm_lock(manifest)
    return resolve_pip_lock(manifest)


def installed_for(manifest: DepManifest, package: str) -> str | None:
    """Lockfile-resolved version for one tracked package (D3), else None."""
    resolved = resolved_versions(manifest)
    if manifest.ecosystem == "npm":
        return resolved.get(package)
    return resolved.get(normalize_dist_name(package))
