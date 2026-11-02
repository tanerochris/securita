"""Reachability: import-graph verdicts with chain evidence (FR-3).

Static import/require graph from first-party code, transitive over relative
files. Unresolvable dynamic imports fail open to reachable; test-only
imports count as reachable. Verdict flips drive the lifecycle (FR-3 D4).
"""

import ast
import json
import os
import shutil
import sys
import time
import tokenize
import warnings
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from security_agent.control.lifecycle import append_run_note, apply_verdict, reopen_run
from security_agent.db.models import Finding, FindingStatus, Repo, RunStatus, ScanRun
from security_agent.db.session import session_scope
from security_agent.sandbox import assert_host_execution_allowed, make_workdir
from security_agent.worker.scan import clone_repo, normalize_dist_name

_EXTENSIONS = (
    ".js",
    ".mjs",
    ".cjs",
    ".jsx",
    ".ts",
    ".mts",
    ".cts",
    ".tsx",
)
_SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage"}

# Untrusted repo content: files past this size are not parsed; they fail open
# to reachable (missing an import silences a vuln, the dangerous direction).
MAX_FILE_BYTES = 1_000_000

# Graphs past this many files fail open wholesale (truncated flag): a
# partial graph would falsely silence imports in the dropped files.
MAX_GRAPH_FILES = 50_000


@dataclass
class ImportSite:
    file: str  # workdir-relative posix path
    line: int
    specifier: str
    dynamic_unresolved: bool = False


class ReachError(RuntimeError):
    """Expected reachability failure: recorded, not raised past run_reachability."""


def first_party_files(workdir: Path) -> list[Path]:
    """Source files, pruning skipped dirs (never descending into node_modules)."""
    workdir = workdir.resolve()
    found: list[Path] = []
    for root, dirs, files in os.walk(workdir, followlinks=False):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            if not name.endswith(_EXTENSIONS):
                continue
            path = Path(root) / name
            if not path.is_file():
                continue
            try:
                path.resolve().relative_to(workdir)
            except ValueError:
                continue  # symlink escaping the repo is not first-party code
            found.append(path)
    return sorted(found)


# JS/TS imports are extracted with tree-sitter (follow-up #4): comments,
# strings, and regex literals can no longer forge sites, and no-space or
# concatenated forms can no longer hide them. Unresolvable dynamics fail
# open to reachable (documented, spec-directed).

_PARSERS: dict[str, object] = {}


def _parser_for(rel: str):
    """Cached tree-sitter parser for the file's grammar (JS/TS/TSX)."""
    lower = rel.lower()
    kind = (
        "tsx"
        if lower.endswith(".tsx")
        else "ts"
        if lower.endswith((".ts", ".mts", ".cts"))
        else "js"
    )
    if kind not in _PARSERS:
        from tree_sitter import Language, Parser

        if kind == "js":
            import tree_sitter_javascript as js_grammar

            language = Language(js_grammar.language())
        else:
            import tree_sitter_typescript as ts_grammar

            factory = ts_grammar.language_tsx if kind == "tsx" else ts_grammar.language_typescript
            language = Language(factory())
        _PARSERS[kind] = Parser(language)
    return _PARSERS[kind]


def _node_text(source_b: bytes, node) -> str:
    return source_b[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _string_value(source_b: bytes, node) -> str | None:
    """Decoded value of a string/template node; None when it has substitutions."""
    if node.type == "string":
        parts: list[str] = []
        for child in node.children:
            if child.type == "string_fragment":
                parts.append(_node_text(source_b, child))
            elif child.type == "escape_sequence":
                raw = _node_text(source_b, child)
                try:
                    parts.append(raw.encode().decode("unicode_escape"))
                except (UnicodeDecodeError, ValueError):
                    parts.append(raw)
        return "".join(parts)
    if node.type == "template_string":
        if any(c.type == "template_substitution" for c in node.children):
            return None
        return "".join(
            _node_text(source_b, c) for c in node.children if c.type == "string_fragment"
        )
    return None


def _static_prefix(source_b: bytes, node) -> str:
    """Leading literal text of a dynamic specifier expression ('' if none)."""
    if node.type in ("string", "template_string"):
        value = _string_value(source_b, node)
        if value is not None:
            return value
        for child in node.children:
            if child.type == "string_fragment":
                return _node_text(source_b, child)
            if child.type == "template_substitution":
                return ""
        return ""
    if node.type == "binary_expression":
        left = node.child_by_field_name("left")
        return _static_prefix(source_b, left) if left is not None else ""
    return ""


def _is_relative_prefix(prefix: str) -> bool:
    return prefix.startswith(("./", "../", "/"))


def parse_imports(source: str, rel: str) -> list[ImportSite]:
    """Tree-sitter JS/TS parser. Unknown dynamics fail open (spec-directed).

    Raises ValueError on unparseable input so analyze() can fail the file
    open, mirroring parse_python_imports.
    """
    source_b = source.encode()
    tree = _parser_for(rel).parse(source_b)
    if tree.root_node.has_error:
        raise ValueError(f"{rel}: unparseable JS/TS; failing open")
    sites: list[ImportSite] = []
    seen: set[tuple[int, str, bool]] = set()

    def add(line: int, specifier: str, unresolved: bool = False) -> None:
        key = (line, specifier, unresolved)
        if key in seen:
            return
        seen.add(key)
        sites.append(ImportSite(rel, line, specifier, unresolved))

    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(reversed(node.children))
        line = node.start_point[0] + 1
        if node.type in ("import_statement", "export_statement"):
            src = node.child_by_field_name("source")
            if src is not None:
                value = _string_value(source_b, src)
                if value is not None:
                    add(line, value)
            continue
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        if func is None:
            continue
        is_import = func.type == "import"
        is_require = func.type == "identifier" and _node_text(source_b, func) == "require"
        is_resolve = (
            func.type == "member_expression"
            and (obj := func.child_by_field_name("object")) is not None
            and obj.type == "identifier"
            and _node_text(source_b, obj) == "require"
            and (prop := func.child_by_field_name("property")) is not None
            and _node_text(source_b, prop) == "resolve"
        )
        if not (is_import or is_require or is_resolve):
            continue
        args = node.child_by_field_name("arguments")
        first = next((c for c in (args.children if args else []) if c.is_named), None)
        if first is None:
            if is_import or is_require:
                add(line, "", unresolved=True)
            continue
        value = (
            _string_value(source_b, first) if first.type in ("string", "template_string") else None
        )
        if value is not None:
            add(line, value)
        elif _is_relative_prefix(_static_prefix(source_b, first)):
            continue  # relative dynamic: no bare package implicated
        else:
            add(line, "", unresolved=True)
    return sorted(sites, key=lambda s: s.line)


def package_of(specifier: str) -> str | None:
    """Bare specifier → package name; relative/builtin → None (file edge)."""
    if not specifier or specifier.startswith((".", "/", "node:")):
        return None
    parts = specifier.split("/")
    if specifier.startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    return parts[0]


def resolve_relative(workdir: Path, from_file: Path, specifier: str) -> Path | None:
    base = (from_file.parent / specifier).resolve()
    try:
        base.relative_to(workdir.resolve())
    except ValueError:
        return None  # escapes the repo
    candidates = [base, *[(base / f"index{e}") for e in _EXTENSIONS]]
    if base.suffix == "":
        candidates[0:0] = [base.with_suffix(e) for e in _EXTENSIONS]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _is_test_file(rel: str) -> bool:
    lower = rel.lower()
    return (
        "/test/" in lower
        or "/tests/" in lower
        or "/__tests__/" in lower
        or lower.startswith(("test/", "tests/"))
        or ".test." in lower
        or ".spec." in lower
    )


def entry_files(workdir: Path) -> list[Path]:
    """package.json main/exports/bin targets; [] when none resolve."""
    manifest_path = workdir / "package.json"
    try:
        if manifest_path.stat().st_size > MAX_FILE_BYTES:
            return []
        manifest = json.loads(manifest_path.read_text())
    except (OSError, ValueError):
        return []
    targets: list[str] = []
    for key in ("main", "bin"):
        value = manifest.get(key)
        if isinstance(value, str):
            targets.append(value)
        elif isinstance(value, dict):
            targets.extend(v for v in value.values() if isinstance(v, str))
    exports = manifest.get("exports")
    stack = [exports]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            targets.append(node)
        elif isinstance(node, dict):
            stack.extend(node.values())
    resolved: list[Path] = []
    for target in targets:
        candidate = (workdir / target).resolve()
        if candidate.is_file():
            resolved.append(candidate)
            continue
        for ext in _EXTENSIONS:
            with_ext = candidate.with_suffix(ext) if candidate.suffix == "" else None
            if with_ext and with_ext.is_file():
                resolved.append(with_ext)
                break
    return sorted(set(resolved))


def analyze(workdir: Path) -> dict:
    """Build the import graph. Returns roots, edges, sites, fail-open markers."""
    workdir = workdir.resolve()  # mkdtemp paths are unresolved (/var -> /private/var)
    files = first_party_files(workdir)
    truncated = len(files) > MAX_GRAPH_FILES
    files = files[:MAX_GRAPH_FILES]
    rel_of = {p: p.relative_to(workdir).as_posix() for p in files}
    sites_by_file: dict[str, list[ImportSite]] = {}
    fail_open_files: list[str] = []
    for path in files:
        rel = rel_of[path]
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError(f"{rel} exceeds {MAX_FILE_BYTES} bytes; failing open")
            source_text = path.read_text()
        except (OSError, ValueError):
            # Unparseable content fails open to reachable: the site implicates
            # every package, so verdicts treat it as a dynamic import.
            sites_by_file[rel] = [ImportSite(rel, 1, "", True)]
            fail_open_files.append(rel)
            continue
        try:
            sites_by_file[rel] = parse_imports(source_text, rel)
        except ValueError:
            sites_by_file[rel] = [ImportSite(rel, 1, "", True)]
            fail_open_files.append(rel)
    edges: dict[str, dict[str, str]] = {}  # file -> {specifier: target rel}
    for path in files:
        rel = rel_of[path]
        for site in sites_by_file.get(rel, []):
            if site.dynamic_unresolved or package_of(site.specifier) is not None:
                continue
            target = resolve_relative(workdir, path, site.specifier)
            if target is not None and target in rel_of:
                edges.setdefault(rel, {})[site.specifier] = rel_of[target]
    entries = {p.relative_to(workdir).as_posix() for p in entry_files(workdir)}
    entries &= set(rel_of.values())
    if entries:
        roots = set(entries)
        roots.update(r for r in rel_of.values() if _is_test_file(r))
    else:
        roots = set(rel_of.values())  # no entries: fail open to all files
    return {
        "roots": roots,
        "edges": edges,
        "sites": sites_by_file,
        "fail_open_files": fail_open_files,
        "truncated": truncated,
    }


def _bfs_parents(graph: dict) -> dict[str, str | None]:
    """Root→file parent map, computed once per graph (not once per hit)."""
    cached = graph.get("_bfs_parents")
    if cached is not None:
        return cached
    parents: dict[str, str | None] = {r: None for r in graph["roots"]}
    queue: deque[str] = deque(graph["roots"])
    while queue:
        current = queue.popleft()
        for nxt in graph["edges"].get(current, {}).values():
            if nxt not in parents:
                parents[nxt] = current
                queue.append(nxt)
    graph["_bfs_parents"] = parents
    return parents


def _bfs_chain(graph: dict, roots: set[str], target_file: str) -> list[str] | None:
    """Shortest root→file hop path, or None when outside the reachable set."""
    if target_file in roots:
        return [target_file]
    parents = _bfs_parents(graph)
    if target_file not in parents:
        return None
    chain = [target_file]
    while True:
        parent = parents[chain[0]]
        if parent is None:
            break
        chain.insert(0, parent)
    return chain


def _reachability_index(graph: dict) -> tuple[set[str], tuple[str, int] | None]:
    """Reachable file set + first reachable dynamic site, computed once per graph."""
    cached = graph.get("_reachability_index")
    if cached is not None:
        return cached
    roots: set[str] = graph["roots"]
    reachable = set(roots)
    queue: deque[str] = deque(roots)
    while queue:
        for nxt in graph["edges"].get(queue.popleft(), {}).values():
            if nxt not in reachable:
                reachable.add(nxt)
                queue.append(nxt)
    dynamic: tuple[str, int] | None = None
    for rel, file_sites in graph["sites"].items():
        if rel not in reachable:
            continue
        for site in file_sites:
            if site.dynamic_unresolved:
                dynamic = (rel, site.line)
                break
        if dynamic is not None:
            break
    graph["_reachability_index"] = (reachable, dynamic)
    return reachable, dynamic


def _verdict_for(
    graph: dict, match: Callable[[str], str | None], target: str
) -> tuple[bool, dict, str | None]:
    """(reachable, evidence, reason_code); match maps specifier → package key."""
    if graph.get("truncated"):
        return True, {"fail_open": "graph-truncated"}, None
    sites: dict[str, list[ImportSite]] = graph["sites"]
    _reachable, dynamic = _reachability_index(graph)
    if dynamic is not None:
        rel, line = dynamic
        return True, {"fail_open": "dynamic-import", "at": f"{rel}:{line}"}, None
    match_name = getattr(match, "__name__", "?")
    memo: dict[tuple[str, str, str], str | None] = graph.setdefault("_spec_match_memo", {})
    hits: list[tuple[str, ImportSite]] = []
    for rel, file_sites in sites.items():
        for site in file_sites:
            if site.dynamic_unresolved:
                continue
            key = (match_name, target, site.specifier)
            if key not in memo:
                memo[key] = match(site.specifier)
            if memo[key] == target:
                hits.append((rel, site))
    if not hits:
        return False, {}, "no-import-chain"
    for rel, site in sorted(hits, key=lambda h: (h[0], h[1].line)):
        chain = _bfs_chain(graph, graph["roots"], rel)
        if chain is not None:
            hops = []
            for i, hop_file in enumerate(chain):
                if i < len(chain) - 1:
                    spec = next(s for s, t in graph["edges"][hop_file].items() if t == chain[i + 1])
                    line = next(
                        st.line
                        for st in sites[hop_file]
                        if st.specifier == spec and not st.dynamic_unresolved
                    )
                else:
                    spec, line = site.specifier, site.line
                hops.append({"file": hop_file, "line": line, "specifier": spec})
            return True, {"chain": hops}, None
    return (
        False,
        {
            "excluded_imports": [
                {"file": rel, "line": site.line}
                for rel, site in sorted(hits, key=lambda h: (h[0], h[1].line))
            ]
        },
        "entry-point-excluded",
    )


def verdict_for_package(graph: dict, package: str) -> tuple[bool, dict, str | None]:
    """(reachable, evidence, reason_code) for one npm package in this graph."""
    return _verdict_for(graph, package_of, package)


# --- Python imports (FR-7 D3) ---

_PY_SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".tox",
    ".eggs",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".pip-deps",
}

# import top-level (lowercased) → normalized distro, for renames only.
# Everything else matches by PEP 503 normalization.
_PY_IMPORT_ALIASES = {
    "pil": "pillow",
    "yaml": "pyyaml",
    "sklearn": "scikit-learn",
    "skimage": "scikit-image",
    "bs4": "beautifulsoup4",
    "cv2": "opencv-python",
    "dateutil": "python-dateutil",
    "openssl": "pyopenssl",
    "jwt": "pyjwt",
    "serial": "pyserial",
    "usb": "pyusb",
    "crypto": "pycryptodome",
    "cryptodome": "pycryptodome",
    "gi": "pygobject",
    "attr": "attrs",
    "dotenv": "python-dotenv",
    "bio": "biopython",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "odf": "odfpy",
    "magic": "python-magic",
    "memcache": "python-memcached",
    "mysqldb": "mysqlclient",
    "zmq": "pyzmq",
    "wx": "wxpython",
    "cairo": "pycairo",
    "socks": "pysocks",
}

_STDLIB = frozenset(m.lower() for m in sys.stdlib_module_names)

_DYNAMIC_IMPORT_NAMES = frozenset({"__import__", "import_module"})


def first_party_python_files(workdir: Path) -> list[Path]:
    """First-party .py files, resolved; venv/build/cache dirs never descended."""
    workdir = workdir.resolve()
    found: list[Path] = []
    for root, dirs, files in os.walk(workdir, followlinks=False):
        dirs[:] = [d for d in dirs if d not in _PY_SKIP_DIRS and not d.endswith(".egg-info")]
        for name in files:
            if not name.endswith(".py"):
                continue
            try:
                resolved = (Path(root) / name).resolve()
                resolved.relative_to(workdir)
            except (OSError, ValueError):
                continue  # missing mid-walk, or symlink escaping the repo
            if resolved.is_file():
                found.append(resolved)
    return sorted(found)


def _is_dotted_module(name: str) -> bool:
    return bool(name) and all(part.isidentifier() for part in name.split("."))


def _dynamic_import_aliases(tree: ast.AST) -> tuple[set[str], set[tuple[str, str]]]:
    """Bare names and (base, attr) pairs that call the dynamic importers.

    Tracks `import importlib as il` / `from importlib import import_module
    as im` (and the builtins `__import__` equivalents) so aliased dynamics
    are still recognized; unknown names stay blanket-dynamic, never silent.
    """
    names = set(_DYNAMIC_IMPORT_NAMES)
    attrs = {("importlib", "import_module")}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib" and alias.asname:
                    attrs.add((alias.asname, "import_module"))
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            if node.module == "importlib":
                for alias in node.names:
                    if alias.name == "import_module":
                        names.add(alias.asname or alias.name)
            elif node.module == "builtins":
                for alias in node.names:
                    if alias.name == "__import__":
                        names.add(alias.asname or alias.name)
    return names, attrs


def _is_dynamic_import_call(node: ast.Call, names: set[str], attrs: set[tuple[str, str]]) -> bool:
    func = node.func
    if isinstance(func, ast.Name) and func.id in names:
        return True
    return (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and (func.value.id, func.attr) in attrs
    )


def parse_python_imports(source: str, rel: str) -> list[ImportSite]:
    """AST import sites. Never imports repo code; unparseable input raises.

    From-imports emit both the module and module.name sites so submodule
    imports resolve whether the name is a member or a module.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)  # old code, noisy escapes
            tree = ast.parse(source)
    except (SyntaxError, RecursionError, ValueError) as exc:
        raise ValueError(f"{rel}: unparseable python ({type(exc).__name__})") from exc
    sites: list[ImportSite] = []
    seen: set[tuple[int, str]] = set()
    dynamic_names, dynamic_attrs = _dynamic_import_aliases(tree)

    def add(lineno: int, specifier: str, unresolved: bool = False) -> None:
        key = (lineno, specifier)
        if key in seen:
            return
        seen.add(key)
        sites.append(ImportSite(rel, lineno, specifier, unresolved))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                add(node.lineno, parts[0])
                if len(parts) > 1:
                    add(node.lineno, alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                dots = "." * node.level
                if node.module:
                    prefix = dots + node.module
                    add(node.lineno, prefix)
                    for alias in node.names:
                        if alias.name != "*":
                            add(node.lineno, f"{prefix}.{alias.name}")
                else:
                    add(node.lineno, dots)
                    for alias in node.names:
                        if alias.name != "*":
                            add(node.lineno, f"{dots}{alias.name}")
            elif node.module:
                add(node.lineno, node.module)
                for alias in node.names:
                    if alias.name != "*":
                        add(node.lineno, f"{node.module}.{alias.name}")
        elif isinstance(node, ast.Call) and _is_dynamic_import_call(
            node, dynamic_names, dynamic_attrs
        ):
            arg = node.args[0] if node.args else None
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                name = arg.value.strip()
                if name.startswith(".") and _is_dotted_module(name.lstrip(".")):
                    add(node.lineno, name)  # relative dynamic: resolved as relative
                elif _is_dotted_module(name):
                    add(node.lineno, name)
                else:
                    add(node.lineno, "", True)
            else:
                add(node.lineno, "", True)
    return sorted(sites, key=lambda s: s.line)


def python_src_roots(workdir: Path) -> list[Path]:
    roots = [workdir]
    src = workdir / "src"
    if src.is_dir():
        roots.append(src)
    return roots


def first_party_tops(workdir: Path) -> set[str]:
    """Top-level first-party names: regular packages + root modules.

    Namespace-only dirs (no __init__.py) are deliberately excluded: treating
    them as third-party fails toward reachable, the safe direction.
    """
    tops: set[str] = set()
    for root in python_src_roots(workdir):
        try:
            entries = list(root.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir():
                    if (entry / "__init__.py").is_file():
                        tops.add(entry.name)
                elif entry.suffix == ".py" and entry.name != "__init__.py":
                    tops.add(entry.stem)
            except OSError:
                continue
    return tops


def package_of_python(
    specifier: str, first_party_tops: set[str], candidates: set[str] | None = None
) -> str | None:
    """Dotted import → normalized distro; relative/first-party/stdlib → None.

    With candidates (normalized distro names under verdict), progressively
    longer dotted prefixes are tried so `import google.cloud.storage`
    resolves to `google-cloud-storage`, not `google`. Without candidates
    the legacy top-segment mapping applies.
    """
    if not specifier or specifier.startswith("."):
        return None
    top = specifier.split(".", 1)[0]
    if not top or not top.isidentifier():
        return None
    if top in first_party_tops:  # first-party shadowing wins over stdlib
        return None
    lowered = top.lower()
    if lowered in _STDLIB:
        return None
    alias = _PY_IMPORT_ALIASES.get(lowered)
    if alias is not None:
        return alias
    if candidates:
        parts = specifier.split(".")
        for width in range(len(parts), 0, -1):
            candidate = normalize_dist_name("-".join(parts[:width]))
            if candidate in candidates:
                return candidate
        return None
    return normalize_dist_name(top)


def analyze_python(workdir: Path) -> dict:
    """Python import graph. Roots = all files v1 (fail open, FR-7 D3).

    With all-files roots every chain is single-hop, so no file edges are
    built; edges arrive with entry-point narrowing (follow-up).
    """
    workdir = workdir.resolve()
    files = first_party_python_files(workdir)
    truncated = len(files) > MAX_GRAPH_FILES
    files = files[:MAX_GRAPH_FILES]
    rel_of = {p: p.relative_to(workdir).as_posix() for p in files}
    sites_by_file: dict[str, list[ImportSite]] = {}
    fail_open_files: list[str] = []
    for path in files:
        rel = rel_of[path]
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError(f"{rel} exceeds {MAX_FILE_BYTES} bytes; failing open")
            with tokenize.open(path) as handle:  # honors encoding cookies + BOM
                source = handle.read()
            sites_by_file[rel] = parse_python_imports(source, rel)
        except (OSError, ValueError, SyntaxError, RecursionError):
            sites_by_file[rel] = [ImportSite(rel, 1, "", True)]
            fail_open_files.append(rel)
    return {
        "roots": set(rel_of.values()),
        "edges": {},
        "sites": sites_by_file,
        "fail_open_files": fail_open_files,
        "truncated": truncated,
        "py_tops": first_party_tops(workdir),
    }


def verdict_for_package_python(graph: dict, package: str) -> tuple[bool, dict, str | None]:
    """(reachable, evidence, reason_code) for one PyPI distro in this graph."""
    tops: set[str] = graph.get("py_tops", set())
    target = normalize_dist_name(package)

    def match_python_spec(spec: str) -> str | None:
        return package_of_python(spec, tops, {target})

    return _verdict_for(graph, match_python_spec, target)


def _union_verdict(node_graph: dict, py_graph: dict, package: str) -> tuple[bool, dict, str | None]:
    """Unknown-ecosystem verdict: reachable in either graph counts (fail open)."""
    ok_node, evidence_node, reason_node = verdict_for_package(node_graph, package)
    ok_py, evidence_py, _ = verdict_for_package_python(py_graph, package)
    if ok_node:
        return True, evidence_node, None
    if ok_py:
        return True, evidence_py, None
    return False, {}, reason_node


def _repo_findings(repo_id: int) -> list[Finding]:
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(Finding).where(
                    Finding.repo_id == repo_id,
                    Finding.status.in_(
                        [
                            FindingStatus.OPEN,
                            FindingStatus.PROPOSED,
                            FindingStatus.SILENT,
                            FindingStatus.RESOLVED,
                        ]
                    ),
                )
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


def _fail_run(run_id: int, error: str) -> None:
    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        if run is None:
            return
        run.status = RunStatus.FAILED
        run.finished_at = datetime.now(UTC)
        prior = f"{run.notes}\n" if run.notes else ""
        run.notes = prior + f"reachability failed: {error}"


def run_reachability(repo_id: int, run_id: int, *, source_dir: Path | None = None) -> dict:
    """Verdict every non-terminal finding; flips drive the lifecycle (FR-3 D4)."""
    assert_host_execution_allowed()
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        run = db.get(ScanRun, run_id)
        if repo is None or run is None:
            raise ValueError(f"Unknown repo {repo_id} or run {run_id}.")
        db.expunge(repo)
    reopen_run(run_id)
    workdir = source_dir
    owned = workdir is None
    try:
        if workdir is None:
            append_run_note(run_id, "reachability: cloning...")
            clone_started = time.monotonic()
            workdir = make_workdir(f"reach-{run_id}-")
            clone_repo(repo, workdir)
            append_run_note(
                run_id, f"reachability: cloned in {time.monotonic() - clone_started:.1f}s"
            )
        append_run_note(run_id, "reachability: building call graphs...")
        node_graph = analyze(workdir)
        py_graph = analyze_python(workdir)
        append_run_note(
            run_id,
            f"reachability: graphs built "
            f"({len(node_graph['roots'])} node files, {len(py_graph['roots'])} python files)",
        )
        findings = _repo_findings(repo_id)
        append_run_note(run_id, f"reachability: scoring {len(findings)} finding(s)...")
        reachable = unreachable = 0
        verdict_ids: list[int] = []
        for index, finding in enumerate(findings, start=1):
            eco = (finding.ecosystem or "").lower()
            if eco == "pypi":
                outcome = verdict_for_package_python(py_graph, finding.package)
            elif eco in ("npm", ""):
                outcome = verdict_for_package(node_graph, finding.package)
            else:
                outcome = _union_verdict(node_graph, py_graph, finding.package)
            is_reach, evidence, reason = outcome
            verdict = apply_verdict(
                finding.id, run_id, is_reach, evidence=evidence, reason_code=reason
            )
            verdict_ids.append(verdict.id)
            reachable += is_reach
            unreachable += not is_reach
            if index % 50 == 0:
                append_run_note(run_id, f"reachability: scored {index}/{len(findings)}...")
        append_run_note(run_id, f"reachability: {reachable} reachable, {unreachable} silent")
        if node_graph.get("truncated") or py_graph.get("truncated"):
            append_run_note(
                run_id, "reachability: file count exceeded cap; verdicts fail open"
            )
        if node_graph.get("fail_open_files"):
            append_run_note(
                run_id, f"reachability unparsed files: {node_graph['fail_open_files']}"
            )
        if py_graph.get("fail_open_files"):
            append_run_note(
                run_id, f"python reachability unparsed files: {py_graph['fail_open_files']}"
            )
        return {
            "status": "done",
            "reachable": reachable,
            "unreachable": unreachable,
            "verdict_ids": verdict_ids,
        }
    except (ReachError, RuntimeError, TimeoutError) as exc:
        _fail_run(run_id, str(exc))
        return {"status": "failed", "error": str(exc)}
    finally:
        if owned and workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)
