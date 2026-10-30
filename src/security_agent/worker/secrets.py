"""Secrets loop: Betterleaks detection, baseline, removal, closure (FR-8).

Runs inside the FR-2 scan (same sandbox run, same triggers, D6): the first
secrets run per repo scans full history once (baseline), later runs scan the
HEAD worktree and report new fingerprints only. Secret VALUES are handled
memory-only and never persisted — only rule/path/line/fingerprint/liveness
reach the database, run notes, or the audit log.
"""

import json
import logging
import re
import shutil
from pathlib import Path

from security_agent.sandbox.tools import MAX_SCANNER_OUTPUT_CHARS, run_allowlisted

log = logging.getLogger(__name__)

SECRETS_SCAN_TIMEOUT_SECONDS = 600  # full-history scans walk every commit

_FINGERPRINT_RE = re.compile(r"^(?:hmac-sha256:)?[0-9a-f]{64}$")
_KNOWN_STATUSES = frozenset({"valid", "needs_validation", "invalid", "revoked", "unknown"})

LIVE_STATUSES = frozenset({"valid"})
DEAD_STATUSES = frozenset({"invalid", "revoked"})


class SecretError(RuntimeError):
    """Expected secrets failure: noted on the run, never raised past the stage.

    `reason` carries a machine-readable code for dispatch that must not
    depend on message wording (delivery supersede checks `gone`).
    """

    def __init__(self, message: str = "", *, reason: str = "") -> None:
        super().__init__(message)
        self.reason = reason


def betterleaks_available() -> bool:
    """True when Betterleaks can run: on PATH (host) or in the sandbox image."""
    from security_agent.sandbox import resolve_backend

    if resolve_backend() == "docker":
        return True  # image contract; a missing binary fails loud at scan time
    return shutil.which("betterleaks") is not None


def _config_args() -> list[str]:
    """Explicit `--config` when the install sets one (default rules otherwise)."""
    from security_agent.config import get_settings

    configured = get_settings().secrets_config_path.strip()
    return ["--config", configured] if configured else []


def _run_betterleaks(args: list[str], workdir: Path) -> dict:
    """Invoke Betterleaks and parse its JSON report (sensitive: memory-only).

    Exit 1 can mean "findings present" (scanner convention); validity is
    decided by parsing stdout as a report, not by the exit code. Anything
    unparseable fails loud — a partial read must never pass as clean.
    """
    out = run_allowlisted(
        "betterleaks",
        [*args, "--output", "-", *_config_args()],
        cwd=str(workdir),
        timeout=SECRETS_SCAN_TIMEOUT_SECONDS,
        success_codes=(0, 1),
        max_output=MAX_SCANNER_OUTPUT_CHARS,
    )
    try:
        report = json.loads(out)
    except ValueError as exc:
        raise SecretError(f"betterleaks returned invalid JSON: {exc}") from exc
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise SecretError("betterleaks returned a non-report document")
    scan = report.get("scan", {})
    if isinstance(scan, dict) and scan.get("state") not in (None, "complete"):
        raise SecretError(f"betterleaks scan incomplete: {scan.get('state')!r}")
    return report


def scan_worktree(workdir: Path) -> dict:
    """HEAD worktree scan with liveness validation (analysis off, D8)."""
    return _run_betterleaks(["fs", str(workdir), "--validate"], workdir)


def scan_history(workdir: Path) -> dict:
    """Full-history scan for the connect-time baseline (FR-8 D5)."""
    return _run_betterleaks(["git", str(workdir), "--validate"], workdir)


def scan_diff_blob(blob: str) -> list[str]:
    """Rule IDs flagged in a patch diff (detection only, redacted output).

    No `--validate`: candidate secrets in a proposed diff must never be
    transmitted to providers. Only rule IDs leave this function; matched
    values stay memory-only inside the parsed report.
    """
    out = run_allowlisted(
        "betterleaks",
        ["stdin", "--redact", "--output", "-"],
        timeout=SECRETS_SCAN_TIMEOUT_SECONDS,
        success_codes=(0, 1),
        max_output=MAX_SCANNER_OUTPUT_CHARS,
        stdin_data=blob,
    )
    try:
        report = json.loads(out)
    except ValueError as exc:
        raise SecretError(f"betterleaks returned invalid JSON: {exc}") from exc
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise SecretError("betterleaks returned a non-report document")
    rules = {
        str(item.get("rule_id"))
        for item in report["findings"]
        if isinstance(item, dict) and item.get("rule_id")
    }
    return sorted(rules)


def valid_fingerprint(value: object) -> bool:
    """True for a scanner fingerprint usable as a stable dedup key."""
    return bool(isinstance(value, str) and _FINGERPRINT_RE.match(value))


def liveness_of(status: object) -> str:
    """live/dead/unknown from a Betterleaks analysis status (D8).

    Unknown covers rules without validation support, validation errors,
    and absent analysis — and is treated as live for alerting (fail open).
    """
    if not isinstance(status, str) or status not in _KNOWN_STATUSES:
        return "unknown"
    if status in LIVE_STATUSES:
        return "live"
    if status in DEAD_STATUSES:
        return "dead"
    return "unknown"


def normalize_report(report: dict) -> tuple[list[dict], str | None, int]:
    """Collapse a report to storable drafts + config hash.

    Returns (drafts, config_hash, dropped). Drafts carry no secret bytes:
    rule, path, line, fingerprint, commit, and liveness only. Entries with
    malformed identity fields are dropped and counted, never stored half.
    """
    drafts: list[dict] = []
    dropped = 0
    for item in report.get("findings", []):
        if not isinstance(item, dict):
            dropped += 1
            continue
        rule = item.get("rule_id")
        match = item.get("match") or {}
        location = item.get("location") or {}
        fingerprint = match.get("fingerprint") if isinstance(match, dict) else None
        path = location.get("path") if isinstance(location, dict) else None
        if (
            not isinstance(rule, str)
            or not rule
            or len(rule) > 200
            or not isinstance(path, str)
            or not path
            or len(path) > 2000
            or not valid_fingerprint(fingerprint)
        ):
            dropped += 1
            log.debug("dropping malformed secret finding (rule=%r path=%r)", rule, path)
            continue
        line = location.get("start_line") if isinstance(location, dict) else None
        if not isinstance(line, int) or line < 0:
            line = None
        attributes = item.get("attributes")
        sha = attributes.get("git.sha") if isinstance(attributes, dict) else None
        analysis = item.get("analysis")
        status = analysis.get("status") if isinstance(analysis, dict) else None
        drafts.append(
            {
                "rule_id": rule,
                "path": path,
                "start_line": line,
                "fingerprint": fingerprint,
                "commit_sha": str(sha)[:100] if sha else None,
                "liveness": liveness_of(status),
            }
        )
    scan = report.get("scan")
    config_hash = None
    if isinstance(scan, dict):
        raw_hash = scan.get("config_hash")
        config_hash = str(raw_hash)[:200] if raw_hash else None
    return drafts, config_hash, dropped


# --- Rotation guidance (FR-8 D4: guidance + alert for everything in v1) ---

_GUIDANCE_FAMILIES = (
    (
        "github",
        "Revoke the token at GitHub Settings → Developer settings → tokens.",
    ),
    ("gitlab", "Revoke the token at GitLab User Settings → Access Tokens."),
    ("aws", "Deactivate the key in IAM → Users → Security credentials."),
    ("slack", "Revoke the token at api.slack.com/apps → OAuth & Permissions."),
    ("openai", "Revoke the key at platform.openai.com/api-keys."),
)


def rotation_guidance(rule_id: str, path: str) -> str:
    """Provider-specific rotation steps; history purge is out of v1 (D5)."""
    needle = rule_id.lower()
    family = next((text for key, text in _GUIDANCE_FAMILIES if key in needle), None)
    steps = family or "Revoke the credential at its provider, then mint a replacement."
    return (
        f"Secret {rule_id!r} in {path} must be rotated by hand. {steps} "
        "Export the replacement via environment (never commit it), redeploy, "
        "then confirm rotation in the dashboard. History rewrite/purge is out "
        "of scope: rotation kills the value instead."
    )


def notify_secret_alert(repo_id: int, run_id: int, secret_id: int, rule_id: str, path: str) -> None:
    """Record the alert (audit + OPEN finding) and fan out to channels.

    Callers emit after commit so a rollback never sends a phantom alert.
    """
    from security_agent.audit import get_shared_log
    from security_agent.notify import notify_event

    safe_rule = re.sub(r"[^\w:.-]", "?", rule_id)[:200]
    safe_path = re.sub(r"\s", "?", path)[:300]
    get_shared_log().append(
        action_class="secret",
        decision="alert",
        line=f"repo={repo_id} run={run_id} secret={secret_id} rule={safe_rule} path={safe_path}",
    )
    notify_event(
        "critical",
        f"live secret: {safe_rule} in {safe_path}",
        f"Repo {repo_id} run {run_id}: rule {safe_rule} flagged {safe_path}. "
        "Rotate the credential by hand, then confirm rotation in the dashboard.",
        link=f"/repos/{repo_id}",
        kind="secret-alert",
    )


# --- Baseline + new-only + closure engine (FR-8 D5/D7) ---

SecretKey = tuple[str, str, str]  # (rule_id, path, fingerprint)


def _draft_key(draft: dict) -> SecretKey:
    return (draft["rule_id"], draft["path"], draft["fingerprint"])


def _head_sha(workdir: Path) -> str | None:
    try:
        return run_allowlisted("git", ["rev-parse", "HEAD"], cwd=str(workdir)).strip()
    except (RuntimeError, TimeoutError):
        return None


def _ensure_full_history(workdir: Path, token: str = "") -> None:
    """Unshallow a depth-1 clone so the baseline covers all commits.

    No-op on complete clones (fixture source_dirs, re-fetched workdirs).
    The clone's credentials were stripped after cloning, so the token is
    re-attached for the fetch exactly like the delivery push does.
    """
    try:
        shallow = run_allowlisted(
            "git", ["rev-parse", "--is-shallow-repository"], cwd=str(workdir)
        ).strip()
    except (RuntimeError, TimeoutError) as exc:
        raise SecretError(f"history probe failed: {exc}") from exc
    if shallow != "true":
        return
    clean = ""
    needs_auth = False
    if token:
        try:
            clean = run_allowlisted(
                "git", ["remote", "get-url", "origin"], cwd=str(workdir)
            ).strip()
        except (RuntimeError, TimeoutError):
            clean = ""
        needs_auth = clean.startswith("https://")
        if needs_auth:
            from security_agent.worker.scan import clone_url

            run_allowlisted(
                "git",
                ["remote", "set-url", "origin", clone_url(clean, token)],
                cwd=str(workdir),
                redact=(token,),
            )
    try:
        run_allowlisted(
            "git",
            ["fetch", "--unshallow"],
            allow_network=True,
            cwd=str(workdir),
            timeout=SECRETS_SCAN_TIMEOUT_SECONDS,
            redact=(token,) if token else (),
        )
    except (RuntimeError, TimeoutError) as exc:
        # Fetch stderr echoes the remote URL; never persist the credential.
        detail = str(exc).replace(token, "***") if token else str(exc)
        raise SecretError(f"history unshallow failed: {detail}") from exc
    finally:
        if needs_auth:
            try:
                run_allowlisted("git", ["remote", "set-url", "origin", clean], cwd=str(workdir))
            except (RuntimeError, TimeoutError):
                pass  # workdir is temp and always wiped


def reconcile(
    repo_id: int,
    run_id: int,
    fs_drafts: list[dict],
    hist_drafts: list[dict],
    alerts: list[tuple[int, str, str]] | None = None,
) -> dict:
    """Merge scanner drafts into findings; drive flips and closure.

    New HEAD secrets open + alert; history-only live secrets await rotation
    (HEAD already clean); history-only dead go informational with no alert.
    OPEN/PROPOSED rows absent from HEAD move to awaiting-rotation;
    awaiting rows whose secret is back reopen; awaiting rows with a sticky
    dead verdict close (scheduled re-validation showed dead). A CLOSED or
    INFORMATIONAL fingerprint seen at HEAD reopens as a new incident with
    a fresh alert. Known history hits refresh validation state silently.

    When `alerts` is given, new-alert notifications are collected there as
    (secret_id, rule_id, path) for the caller to emit after commit; with
    None they are emitted inline (direct-call behavior).
    """
    from sqlalchemy import select
    from sqlalchemy.exc import IntegrityError

    from security_agent.control.lifecycle import SECRET_TRANSITIONS
    from security_agent.db.models import SecretFinding, SecretStatus
    from security_agent.db.session import session_scope

    def _alert(secret_id: int, rule_id: str, path: str) -> None:
        if alerts is not None:
            alerts.append((secret_id, rule_id, path))
        else:
            notify_secret_alert(repo_id, run_id, secret_id, rule_id, path)

    def _flip(row: SecretFinding, to: SecretStatus) -> None:
        """Status change through the checked transition table, never direct."""
        if to not in SECRET_TRANSITIONS[row.status]:
            raise ValueError(f"Illegal secret transition {row.status} → {to}.")
        row.status = to

    fs_map = {_draft_key(d): d for d in fs_drafts}
    hist_map = {_draft_key(d): d for d in hist_drafts}
    stats = {"new": 0, "reopened": 0, "awaiting": 0, "closed": 0, "informational": 0}
    with session_scope() as db:
        existing = {
            (r.rule_id, r.path, r.fingerprint): r
            for r in db.scalars(select(SecretFinding).where(SecretFinding.repo_id == repo_id))
        }

        def _insert(
            draft: dict, status: SecretStatus, *, from_history: bool
        ) -> SecretFinding | None:
            hist = hist_map.get(_draft_key(draft))
            row = SecretFinding(
                repo_id=repo_id,
                rule_id=draft["rule_id"],
                path=draft["path"],
                start_line=draft["start_line"],
                fingerprint=draft["fingerprint"],
                commit_sha=(hist or draft).get("commit_sha"),
                status=status,
                liveness=draft["liveness"],
                dead_verdict=draft["liveness"] == "dead",
                from_history=from_history,
                guidance=rotation_guidance(draft["rule_id"], draft["path"]),
                first_run_id=run_id,
            )
            try:
                with db.begin_nested():
                    db.add(row)
                    db.flush()
            except IntegrityError:
                return None  # lost a cross-process race; the winner owns it
            return row

        for key, draft in fs_map.items():
            row = existing.get(key)
            if row is None:
                created = _insert(draft, SecretStatus.OPEN, from_history=key in hist_map)
                if created is None:
                    continue
                existing[key] = created
                stats["new"] += 1
                _alert(created.id, created.rule_id, created.path)
                continue
            row.liveness = draft["liveness"]
            row.start_line = draft["start_line"]
            row.dead_verdict = row.dead_verdict or draft["liveness"] == "dead"
            if key in hist_map and not row.from_history:
                row.from_history = True
                if hist_map[key].get("commit_sha"):
                    row.commit_sha = hist_map[key]["commit_sha"]
            if row.status in (SecretStatus.CLOSED, SecretStatus.INFORMATIONAL):
                _flip(row, SecretStatus.OPEN)  # recommitted value: new incident
                stats["reopened"] += 1
                _alert(row.id, row.rule_id, row.path)
            elif row.status == SecretStatus.AWAITING_ROTATION:
                _flip(row, SecretStatus.OPEN)  # secret is back at HEAD: reopen
                stats["reopened"] += 1
        for key, draft in hist_map.items():
            if key in fs_map:
                continue  # HEAD-present handled above
            known = existing.get(key)
            if known is not None:
                # Known hit: refresh validation state silently, never re-alert.
                known.liveness = draft["liveness"]
                known.dead_verdict = known.dead_verdict or draft["liveness"] == "dead"
                if not known.from_history:
                    known.from_history = True
                    if draft.get("commit_sha"):
                        known.commit_sha = draft["commit_sha"]
                continue
            if draft["liveness"] == "dead":
                created = _insert(draft, SecretStatus.INFORMATIONAL, from_history=True)
                if created is not None:
                    existing[key] = created
                    stats["informational"] += 1
                continue
            created = _insert(draft, SecretStatus.AWAITING_ROTATION, from_history=True)
            if created is None:
                continue
            existing[key] = created
            stats["new"] += 1
            _alert(created.id, created.rule_id, created.path)
        for key, row in existing.items():
            if row.status in (SecretStatus.OPEN, SecretStatus.PROPOSED) and key not in fs_map:
                _flip(row, SecretStatus.AWAITING_ROTATION)  # HEAD rescans clean
                stats["awaiting"] += 1
        for row in existing.values():
            if row.status == SecretStatus.AWAITING_ROTATION and row.dead_verdict:
                _flip(row, SecretStatus.CLOSED)  # re-validation showed dead
                stats["closed"] += 1
        db.flush()
    return stats


def _needs_baseline(repo_id: int, config_hash: str | None) -> bool:
    """True on first run or when the rule config changed (D5/D6)."""
    from security_agent.db.models import SecretBaseline
    from security_agent.db.session import session_scope

    with session_scope() as db:
        row = db.get(SecretBaseline, repo_id)
        if row is None:
            return True
        return (row.config_hash or None) != (config_hash or None)


def _record_baseline(repo_id: int, sha: str, config_hash: str | None) -> None:
    """Upsert the baseline; insert-first so concurrent runs serialize."""
    from datetime import UTC, datetime

    from sqlalchemy.exc import IntegrityError

    from security_agent.db.models import SecretBaseline
    from security_agent.db.session import session_scope

    with session_scope() as db:
        try:
            with db.begin_nested():
                db.add(
                    SecretBaseline(
                        repo_id=repo_id,
                        baseline_sha=sha,
                        config_hash=config_hash,
                        baseline_at=datetime.now(UTC),
                    )
                )
                db.flush()
        except IntegrityError:
            row = db.get(SecretBaseline, repo_id)
            if row is None:
                raise
            row.baseline_sha = sha
            row.config_hash = config_hash
            row.baseline_at = datetime.now(UTC)


def run_secrets_stage(repo_id: int, run_id: int, workdir: Path) -> list[str]:
    """Detect + reconcile secrets in the scan workdir; returns run notes.

    Raises SecretError (or tool errors) on HEAD-scanner failure — the caller
    notes it and continues, so secrets never fail the vuln run (C7).
    History failures are isolated the same way: HEAD results still land.
    Skips with a note + audit warning when the binary is absent.
    """
    from security_agent.audit import get_shared_log

    notes: list[str] = []
    if not betterleaks_available():
        notes.append("secrets: skipped (betterleaks not on PATH)")
        get_shared_log().append(
            action_class="secret",
            decision="warning",
            line=f"repo={repo_id} run={run_id} skipped=no-binary",
        )
        return notes
    fs_report = scan_worktree(workdir)
    fs_drafts, config_hash, dropped = normalize_report(fs_report)
    if dropped:
        notes.append(f"secrets: dropped {dropped} malformed report entries")
    hist_drafts: list[dict] = []
    if _needs_baseline(repo_id, config_hash):
        from security_agent.control.repos import get_repo_token

        try:
            _ensure_full_history(workdir, get_repo_token(repo_id) or "")
        except SecretError as exc:
            notes.append(f"secrets: baseline deferred ({exc})")
            get_shared_log().append(
                action_class="secret", decision="deferred", line=f"repo={repo_id} run={run_id}"
            )
        else:
            try:
                hist_report = scan_history(workdir)
            except (SecretError, RuntimeError, TimeoutError, OSError) as exc:
                notes.append(f"secrets: baseline deferred ({exc})")
                get_shared_log().append(
                    action_class="secret",
                    decision="deferred",
                    line=f"repo={repo_id} run={run_id}",
                )
            else:
                hist_drafts, _, hist_dropped = normalize_report(hist_report)
                if hist_dropped:
                    notes.append(f"secrets: dropped {hist_dropped} malformed history entries")
                sha = _head_sha(workdir)
                if sha:
                    # Canonical hash is the fs report's — the same value
                    # _needs_baseline compares, so one baseline sticks.
                    _record_baseline(repo_id, sha, config_hash)
                    notes.append(f"secrets: history baseline recorded at {sha[:12]}")
                else:
                    notes.append("secrets: baseline deferred (HEAD unreadable)")
    pending: list[tuple[int, str, str]] = []
    stats = reconcile(repo_id, run_id, fs_drafts, hist_drafts, pending)
    # Alerts fire after reconcile commits, never for rolled-back rows.
    for secret_id, rule_id, path in pending:
        notify_secret_alert(repo_id, run_id, secret_id, rule_id, path)
    notes.append(
        "secrets: "
        f"{stats['new']} new, {stats['reopened']} reopened, "
        f"{stats['awaiting']} awaiting rotation, {stats['closed']} closed, "
        f"{stats['informational']} informational"
    )
    removal = run_secrets_removal(repo_id, run_id, workdir, fs_report)
    if removal["proposal_ids"]:
        notes.append(f"secrets: {len(removal['proposal_ids'])} removal PR(s) proposed")
    for sid, reason in sorted(removal["skipped"].items()):
        notes.append(f"secrets: removal skipped for finding {sid} ({reason})")
    return notes


# --- Removal PRs (FR-8 D1: redact, replace with env reference) ---

_KV_RE = re.compile(r"^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)(\s*[:=]\s*)(.*)$")
_MAX_REMOVAL_FILE_BYTES = 1_000_000


def redact_line(line: str, secret: str) -> str | None:
    """Redact the secret span: env reference on KEY=value lines, else removed.

    Returns None when the secret bytes are absent (stale scanner location).
    The trailing line ending is the caller's to reattach.
    """
    if not secret or secret not in line:
        return None
    kv = _KV_RE.match(line)
    if kv is not None and secret in kv.group(4):
        return f"{kv.group(1)}{kv.group(2)}{kv.group(3)}" + kv.group(4).replace(
            secret, "${" + kv.group(2) + "}"
        )
    return line.replace(secret, "***REMOVED***")


# File → [(start, end, value, fingerprint)]; values are memory-only and are
# never persisted — the applier emits redacted text, the rescan drops them.
RemovalPlan = dict[str, list[tuple[int, int, str, str]]]


def plan_removal(report: dict, fingerprints: set[str]) -> RemovalPlan:
    """Line ranges holding OPEN secrets, with the bytes to redact in memory.

    Findings whose value is missing (path-only rules) yield no plan entry
    and are skipped downstream with a reason.
    """
    plan: RemovalPlan = {}
    for item in report.get("findings", []):
        if not isinstance(item, dict):
            continue
        match = item.get("match") or {}
        if not isinstance(match, dict):
            continue
        fingerprint = match.get("fingerprint")
        if fingerprint not in fingerprints:
            continue
        value = match.get("value")
        location = item.get("location") or {}
        path = location.get("path") if isinstance(location, dict) else None
        start = location.get("start_line") if isinstance(location, dict) else None
        if not value or not isinstance(value, str) or not path or not isinstance(start, int):
            continue
        end = location.get("end_line")
        if not isinstance(end, int) or end < start:
            end = start
        plan.setdefault(path, []).append((start, end, value, fingerprint))
    return plan


def _split_lines(text: str) -> list[tuple[str, str]]:
    """(content, ending) pairs, preserving CRLF/LF exactly."""
    return [
        (m.group(1), m.group(2))
        for m in re.finditer(r"(.*?)(\r\n|\n|\r|$)", text)
        if m.group(1) or m.group(2)
    ]


def apply_removal(
    workdir: Path, plan: RemovalPlan
) -> tuple[dict[str, list[int]], dict[str, str], set[str]]:
    """Apply a removal plan; returns (touched_lines, skipped, redacted_fps).

    touched_lines maps file → redacted 1-based lines; skipped maps file →
    reason (untracked, oversize, unreadable, stale locations); redacted_fps
    are the fingerprints with at least one redacted line. Only tracked
    files are touched: an untracked secret has no HEAD diff to propose.
    Symlink escapes are refused.
    """
    from security_agent.worker.scan import read_text_capped

    # -z disables path quoting: names with spaces would otherwise miss the
    # tracked set and their removals would silently never happen.
    tracked = {
        entry
        for entry in run_allowlisted("git", ["ls-files", "-z", "--", "."], cwd=str(workdir)).split(
            "\x00"
        )
        if entry
    }
    touched: dict[str, list[int]] = {}
    skipped: dict[str, str] = {}
    redacted_fps: set[str] = set()
    resolved_root = workdir.resolve()
    for path, spans in plan.items():
        if path not in tracked:
            skipped[path] = "file not tracked in git"
            continue
        candidate = workdir / path
        try:
            candidate.resolve().relative_to(resolved_root)
        except (OSError, ValueError):
            skipped[path] = "path escapes the workdir"
            continue
        text = read_text_capped(candidate, _MAX_REMOVAL_FILE_BYTES, newline="")
        if text is None:
            skipped[path] = "file oversize or unreadable"
            continue
        lines = _split_lines(text)
        changed: list[int] = []
        stale = False
        for start, end, secret, fingerprint in spans:
            hit = False
            for lineno in range(start, min(end, len(lines)) + 1):
                content, _ = lines[lineno - 1]
                redacted = redact_line(content, secret)
                if redacted is None:
                    continue
                lines[lineno - 1] = (redacted, lines[lineno - 1][1])
                changed.append(lineno)
                hit = True
            if hit:
                redacted_fps.add(fingerprint)
            else:
                stale = True
        if stale and not changed:
            skipped[path] = "stale scanner location"
            continue
        if not changed:
            skipped[path] = "no redactable lines"
            continue
        candidate.write_text("".join(c + e for c, e in lines), newline="")
        touched[path] = sorted(set(changed))
    return touched, skipped, redacted_fps


def validate_removal(
    workdir: Path, touched: dict[str, list[int]], fingerprints: set[str]
) -> list[str]:
    """Diff scope + rescan-verify. Returns violations (empty = clean)."""
    violations: list[str] = []
    out = run_allowlisted("git", ["diff", "--numstat", "HEAD", "--", "."], cwd=str(workdir))
    changed_files = {line.split("\t", 2)[2] for line in out.splitlines() if line.count("\t") >= 2}
    if changed_files - set(touched):
        violations.append(f"diff touches non-secret files: {sorted(changed_files - set(touched))}")
    out = run_allowlisted("git", ["diff", "-U0", "HEAD", "--", "."], cwd=str(workdir))
    current: str | None = None
    for line in out.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
        elif line.startswith("@@"):
            match = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if match and current:
                start, count = int(match.group(1)), int(match.group(2) or 1)
                allowed = set(touched.get(current, []))
                if any(n not in allowed for n in range(start, start + count)):
                    violations.append(f"diff touches non-secret lines in {current}")
                    break
    if changed_files:
        verify_report = scan_worktree(workdir)
        verify_drafts, _, _ = normalize_report(verify_report)
        remaining = fingerprints & {d["fingerprint"] for d in verify_drafts}
        if remaining:
            violations.append(f"rescan still flags {len(remaining)} secret(s)")
    return violations


def _snapshot_plan_files(workdir: Path, plan: RemovalPlan) -> dict[str, bytes]:
    """Original bytes of in-workdir plan files, so proof redaction is reversible."""
    resolved_root = workdir.resolve()
    snapshots: dict[str, bytes] = {}
    for path in plan:
        candidate = workdir / path
        try:
            candidate.resolve().relative_to(resolved_root)
            snapshots[path] = candidate.read_bytes()
        except (OSError, ValueError):
            continue  # apply_removal will skip with a reason
    return snapshots


def run_secrets_removal(repo_id: int, run_id: int, workdir: Path, fs_report: dict) -> dict:
    """Propose removal PRs for OPEN secrets; returns proposal ids + skips."""
    from sqlalchemy import select
    from sqlalchemy.exc import IntegrityError

    from security_agent.db.models import Proposal, SecretFinding, SecretStatus
    from security_agent.db.session import session_scope

    with session_scope() as db:
        rows = list(
            db.scalars(
                select(SecretFinding).where(
                    SecretFinding.repo_id == repo_id,
                    SecretFinding.status == SecretStatus.OPEN,
                )
            )
        )
        for r in rows:
            db.expunge(r)
    if not rows:
        return {"proposal_ids": [], "skipped": {}}
    by_fp = {r.fingerprint: r for r in rows}
    plan = plan_removal(fs_report, set(by_fp))
    snapshots = _snapshot_plan_files(workdir, plan)
    touched: dict[str, list[int]] = {}
    try:
        touched, skipped_files, redacted_fps = apply_removal(workdir, plan)
        if redacted_fps:
            violations = validate_removal(workdir, touched, redacted_fps)
        else:
            violations = []
    finally:
        # The scan workdir is proof-only (delivery re-derives from HEAD):
        # restore every file we touched so source_dir callers never see a
        # redacted checkout.
        for path, data in snapshots.items():
            if path in touched:
                try:
                    (workdir / path).write_bytes(data)
                except OSError as exc:
                    log.warning("secrets: failed to restore %s after proof: %s", path, exc)
    skipped: dict[int, str] = {}
    for path, reason in skipped_files.items():
        for row in rows:
            if row.path == path:
                skipped[row.id] = reason
    for row in rows:
        if row.fingerprint not in redacted_fps:
            skipped.setdefault(row.id, "no redactable lines in report")
    if violations:
        for row in rows:
            if row.fingerprint in redacted_fps:
                skipped[row.id] = "; ".join(violations)
        return {"proposal_ids": [], "skipped": skipped}
    proposal_ids: list[int] = []
    with session_scope() as db:
        for row in rows:
            if row.fingerprint not in redacted_fps:
                continue  # skipped above with a reason
            # No stored diff: a unified diff would rest the secret bytes in
            # the DB via its `-` lines. Delivery re-derives the removal
            # from current HEAD instead (no stale patches, no stored values).
            proposal = Proposal(
                repo_id=repo_id,
                finding_ids=[],
                package_from=row.rule_id,
                package_to="redacted",
                verification_result=(
                    f"removal verified at scan: {row.path}; "
                    "rescan: fingerprint absent; diff scoped to secret lines"
                ),
                patch=None,
                secret_finding_id=row.id,
            )
            try:
                with db.begin_nested():
                    db.add(proposal)
                    db.flush()
            except IntegrityError:
                skipped[row.id] = "proposal already exists (concurrent run)"
                continue
            live = db.get(SecretFinding, row.id)
            if live is not None and live.status == SecretStatus.OPEN:
                live.status = SecretStatus.PROPOSED
                live.proposal_id = proposal.id
            proposal_ids.append(proposal.id)
    return {"proposal_ids": proposal_ids, "skipped": skipped}


def apply_secret_removal(workdir: Path, secret_id: int) -> dict[str, list[int]]:
    """Re-derive one removal in a delivery workdir; returns touched lines.

    Raises SecretError when the secret is gone (supersede the proposal),
    unlocatable, or fails scope/rescan validation (leave for retry).
    """
    from security_agent.db.models import SecretFinding, SecretStatus
    from security_agent.db.session import session_scope

    with session_scope() as db:
        row = db.get(SecretFinding, secret_id)
        if row is None:
            raise SecretError(f"secret finding {secret_id} is gone")
        if row.status != SecretStatus.PROPOSED:
            raise SecretError(f"secret finding {secret_id} is {row.status.value}")
        fingerprint = row.fingerprint
        db.expunge(row)
    report = scan_worktree(workdir)
    plan = plan_removal(report, {fingerprint})
    if not plan:
        raise SecretError("secret no longer present at HEAD", reason="gone")
    touched, skipped, redacted = apply_removal(workdir, plan)
    if fingerprint not in redacted:
        reason = next(iter(skipped.values()), "no redactable lines")
        raise SecretError(f"removal not applicable: {reason}")
    violations = validate_removal(workdir, touched, {fingerprint})
    if violations:
        raise SecretError(f"removal invalid: {'; '.join(violations)}")
    return touched
