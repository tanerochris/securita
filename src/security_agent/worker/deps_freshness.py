"""Freshness via native ecosystem tooling in the sandbox (D4/D13).

No registry HTTP from the host/worker: Node freshness comes from the
package manager CLI (`npm outdated --json`, per-package `npm view`
fallbacks, yarn/pnpm equivalents) and Python freshness from
`pip index versions`. Every tool call runs through the allowlisted
runner with network egress, inside the check's disposable sandbox.

Latest (D13) is the absolute latest stable release even when the
manifest range forbids it; pre-releases count only when the installed
version is itself a pre-release; yanked/withdrawn releases never count
(npm dist-tags exclude them; pip index output cannot mark them, which
the report discloses). When an in-range update also exists, the report
names both but proposes the absolute latest.

All fetchers take an injectable `run` callable so tests drive them
without network or a sandbox.
"""

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from packaging.version import InvalidVersion, Version

from security_agent.sandbox.tools import run_allowlisted

log = logging.getLogger(__name__)

RunFn = Callable[..., str]

_PIP_AVAILABLE_RE = re.compile(r"^Available versions:\s*(.+)$", re.IGNORECASE)
_PIP_LATEST_RE = re.compile(r"^\s*LATEST:\s*(\S+)", re.IGNORECASE)


@dataclass
class Freshness:
    """Freshness outcome for one tracked package."""

    package: str
    installed: str | None
    wanted: str | None  # in-range update, when the tool reports one
    latest: str | None  # absolute latest stable (D13)
    update_class: str | None  # major | minor | patch
    error: str | None = None  # named tool failure (D19)


def _parse_version(text: str | None) -> Version | None:
    if not text:
        return None
    try:
        return Version(text.strip().removeprefix("v").removeprefix("V"))
    except InvalidVersion:
        return None


def is_prerelease(text: str | None) -> bool:
    parsed = _parse_version(text)
    return bool(parsed is not None and parsed.is_prerelease)


def classify_update(installed: str | None, latest: str | None) -> str | None:
    """major|minor|patch when latest is newer than installed, else None.

    Compares release segments; a newer pre-release of the same release
    counts as a patch. Unparseable versions compare unequal-but-unknown:
    None unless the strings differ, in which case "patch" would lie, so
    still None — callers treat unknown-class updates as plain available.
    """
    current, target = _parse_version(installed), _parse_version(latest)
    if current is None or target is None:
        return None
    if target <= current:
        return None
    cur_rel, tgt_rel = list(current.release), list(target.release)
    while len(cur_rel) < 3:
        cur_rel.append(0)
    while len(tgt_rel) < 3:
        tgt_rel.append(0)
    if tgt_rel[0] != cur_rel[0]:
        return "major"
    if tgt_rel[1] != cur_rel[1]:
        return "minor"
    return "patch"


def select_latest(versions: list[str], installed: str | None) -> str | None:
    """Absolute latest stable (D13), newest-first input not assumed.

    Pre-releases are ignored unless the installed version is itself a
    pre-release. Yanked/withdrawn filtering happens at the source: npm
    dist-tags exclude them; pip callers pass through with a disclosure.
    """
    parsed: list[tuple[Version, str]] = []
    for raw in versions:
        try:
            parsed.append((Version(raw), raw))
        except InvalidVersion:
            continue
    if not parsed:
        return None
    installed_pre = is_prerelease(installed)
    candidates = [p for p in parsed if installed_pre or not p[0].is_prerelease]
    if not candidates:
        candidates = parsed
    candidates.sort(key=lambda p: p[0])
    return candidates[-1][1]


def npm_outdated(
    manifest_dir: Path,
    *,
    pm: str = "npm",
    run: RunFn = run_allowlisted,
    timeout: int = 300,
) -> dict[str, dict[str, str]]:
    """{package: {current, wanted, latest}} from `<pm> outdated`.

    npm exits 1 when outdated rows exist; yarn/pnpm JSON shapes differ,
    so each parses defensively and an unparseable blob raises ValueError
    for the caller to record as a named tool failure (D19).
    """
    tool = pm if pm in ("npm", "yarn", "pnpm") else "npm"
    if tool == "npm":
        out = run(
            "npm",
            ["outdated", "--json", "--all"],
            cwd=str(manifest_dir),
            timeout=timeout,
            allow_network=True,
            success_codes=(0, 1),
        )
        return _parse_npm_outdated(out)
    if tool == "pnpm":
        out = run(
            "pnpm",
            ["outdated", "--format", "json"],
            cwd=str(manifest_dir),
            timeout=timeout,
            allow_network=True,
            success_codes=(0, 1),
        )
        return _parse_pnpm_outdated(out)
    out = run(
        "yarn",
        ["outdated", "--json"],
        cwd=str(manifest_dir),
        timeout=timeout,
        allow_network=True,
        success_codes=(0, 1),
    )
    return _parse_yarn_outdated(out)


def _parse_npm_outdated(out: str) -> dict[str, dict[str, str]]:
    try:
        data = json.loads(out or "{}")
    except ValueError as exc:
        raise ValueError(f"npm outdated returned invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("npm outdated returned a non-object document")
    rows: dict[str, dict[str, str]] = {}
    for package, entry in data.items():
        if not isinstance(entry, dict):
            continue
        rows[str(package)] = {
            key: str(entry[key])
            for key in ("current", "wanted", "latest")
            if entry.get(key) not in (None, "")
        }
    return rows


def _parse_pnpm_outdated(out: str) -> dict[str, dict[str, str]]:
    # pnpm --format json: {"package": {"current": .., "wanted": .., "latest": ..}}
    try:
        data = json.loads(out or "{}")
    except ValueError as exc:
        raise ValueError(f"pnpm outdated returned invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("pnpm outdated returned a non-object document")
    rows: dict[str, dict[str, str]] = {}
    for package, entry in data.items():
        if not isinstance(entry, dict):
            continue
        rows[str(package)] = {
            key: str(entry[key])
            for key in ("current", "wanted", "latest")
            if entry.get(key) not in (None, "")
        }
    return rows


def _parse_yarn_outdated(out: str) -> dict[str, dict[str, str]]:
    # yarn classic --json streams {"type":"table","data":{...}} lines; yarn
    # berry prints a table (non-JSON) — both handled best-effort.
    rows: dict[str, dict[str, str]] = {}
    text = (out or "").strip()
    if not text:
        return rows
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict) or event.get("type") != "table":
            continue
        data = event.get("data") or {}
        head, body = data.get("head", []), data.get("body", [])
        if not isinstance(body, list):
            continue
        idx = {str(h).lower(): i for i, h in enumerate(head) if isinstance(h, str)}
        for row in body:
            if not isinstance(row, list) or not row:
                continue
            package = str(row[idx.get("package", 0)])
            rows[package] = {}
            for key in ("current", "wanted", "latest"):
                if key in idx and idx[key] < len(row) and row[idx[key]]:
                    rows[package][key] = str(row[idx[key]])
    return rows


def npm_latest(
    package: str,
    *,
    manifest_dir: Path | None = None,
    run: RunFn = run_allowlisted,
    timeout: int = 120,
) -> str | None:
    """Absolute latest stable via `npm view <pkg> version` (dist-tag latest)."""
    out = run(
        "npm",
        ["view", package, "version", "--json"],
        cwd=str(manifest_dir) if manifest_dir else None,
        timeout=timeout,
        allow_network=True,
    )
    try:
        data = json.loads(out or "null")
    except ValueError:
        return out.strip().strip("\"'") or None
    if isinstance(data, str):
        return data.strip() or None
    if isinstance(data, list) and data and isinstance(data[-1], str):
        return data[-1].strip() or None
    return None


def pip_available_versions(
    package: str,
    *,
    run: RunFn = run_allowlisted,
    timeout: int = 120,
) -> list[str]:
    """All published versions from `pip index versions <pkg>` (newest first)."""
    out = run("pip-index", [package], timeout=timeout, allow_network=True)
    versions: list[str] = []
    for line in (out or "").splitlines():
        match = _PIP_AVAILABLE_RE.match(line.strip())
        if match:
            versions.extend(v.strip() for v in match.group(1).split(",") if v.strip())
    if not versions:
        for line in (out or "").splitlines():
            match = _PIP_LATEST_RE.match(line)
            if match:
                versions.append(match.group(1).strip())
    return versions


def check_npm_manifest(
    manifest_dir: Path,
    specs: dict[str, tuple[str | None, str]],
    *,
    pm: str = "npm",
    run: RunFn = run_allowlisted,
) -> dict[str, Freshness]:
    """Freshness for one Node manifest: outdated sweep + per-package latest.

    `specs` maps package -> (installed_version, manifest_spec). The
    outdated sweep supplies wanted/in-range answers; per-package `npm
    view` confirms the absolute latest (D13) for anything the sweep
    missed. Tool failures are per-package named errors (D19), never
    whole-manifest failures.
    """
    try:
        rows = npm_outdated(manifest_dir, pm=pm, run=run)
    except (RuntimeError, TimeoutError, ValueError) as exc:
        log.warning("npm outdated failed in %s: %s", manifest_dir, exc)
        rows = {}
        sweep_error = str(exc)
    else:
        sweep_error = ""
    out: dict[str, Freshness] = {}
    for package, (installed, _spec) in specs.items():
        row = rows.get(package, {})
        wanted = row.get("wanted")
        latest = row.get("latest")
        error = None
        if latest is None:
            try:
                latest = npm_latest(package, manifest_dir=manifest_dir, run=run)
            except (RuntimeError, TimeoutError) as exc:
                error = f"latest lookup failed: {exc}"
                latest = None
        if latest is None and sweep_error and error is None:
            error = f"outdated sweep failed: {sweep_error}"
        out[package] = Freshness(
            package=package,
            installed=installed or row.get("current"),
            wanted=wanted,
            latest=latest,
            update_class=classify_update(installed or row.get("current"), latest),
            error=error,
        )
    return out


def check_pip_packages(
    specs: dict[str, tuple[str | None, str]],
    *,
    run: RunFn = run_allowlisted,
) -> dict[str, Freshness]:
    """Freshness for Python packages via `pip index versions` each.

    Latest is the absolute latest stable per D13; `wanted` stays None
    (pip reports no in-range answer) and the report proposes latest.
    Yanked releases cannot be told apart in pip index output — callers
    disclose this once per report.
    """
    out: dict[str, Freshness] = {}
    for package, (installed, _spec) in specs.items():
        try:
            versions = pip_available_versions(package, run=run)
        except (RuntimeError, TimeoutError) as exc:
            out[package] = Freshness(
                package=package,
                installed=installed,
                wanted=None,
                latest=None,
                update_class=None,
                error=f"index lookup failed: {exc}",
            )
            continue
        latest = select_latest(versions, installed)
        out[package] = Freshness(
            package=package,
            installed=installed,
            wanted=None,
            latest=latest,
            update_class=classify_update(installed, latest),
            error=None if latest else "no published versions found",
        )
    return out
