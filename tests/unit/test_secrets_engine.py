"""H5 Slice C: reconcile — new-only, history-once, flips, closure, baseline."""

from unittest import mock

from sqlalchemy import select

from security_agent.control import repos as repo_svc
from security_agent.db.models import RepoKind, ScanRun, SecretBaseline, SecretFinding
from security_agent.db.session import session_scope
from security_agent.worker import secrets as secrets_mod
from security_agent.worker.secrets import reconcile

_FP_A = "aa" * 32
_FP_B = "bb" * 32
_FP_C = "cc" * 32


def _draft(rule="github-pat", path=".env", fp=_FP_A, live="live", line=3):
    return {
        "rule_id": rule,
        "path": path,
        "start_line": line,
        "fingerprint": fp,
        "commit_sha": None,
        "liveness": live,
    }


def _repo_run(tag):
    repo = repo_svc.connect_repo(tag, RepoKind.GIT, url=f"https://example.com/{tag}.git")
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        assert run is not None
        return repo.id, run.id


def _rows(repo_id):
    with session_scope() as db:
        rows = list(db.scalars(select(SecretFinding).where(SecretFinding.repo_id == repo_id)))
        for r in rows:
            db.expunge(r)
        return rows


def test_new_head_secrets_open_and_alert_once():
    repo_id, run_id = _repo_run("sec-eng-a")
    stats = reconcile(repo_id, run_id, [_draft()], [])
    assert stats["new"] == 1
    rows = _rows(repo_id)
    assert len(rows) == 1
    assert rows[0].status.value == "open"
    assert "rotate" in (rows[0].guidance or "").lower()
    assert rows[0].liveness == "live"
    # Second identical run: known hits never re-alert.
    stats = reconcile(repo_id, run_id, [_draft()], [])
    assert stats == {"new": 0, "reopened": 0, "awaiting": 0, "closed": 0, "informational": 0}


def test_history_only_live_awaits_dead_is_informational():
    repo_id, run_id = _repo_run("sec-eng-b")
    live_hist = _draft(path="old/deploy.sh", fp=_FP_B, live="live")
    live_hist["commit_sha"] = "abc123"
    dead_hist = _draft(rule="slack-bot-token", path="old/bot.py", fp=_FP_C, live="dead")
    stats = reconcile(repo_id, run_id, [], [live_hist, dead_hist])
    assert stats["new"] == 1 and stats["informational"] == 1
    by_fp = {r.fingerprint: r for r in _rows(repo_id)}
    assert by_fp[_FP_B].status.value == "awaiting_rotation"
    assert by_fp[_FP_B].from_history is True
    assert by_fp[_FP_C].status.value == "informational"
    # Re-baseline replays history: still never re-alerts.
    stats = reconcile(repo_id, run_id, [], [live_hist, dead_hist])
    assert stats["new"] == 0 and stats["informational"] == 0


def test_head_clean_reopen_and_dead_closure():
    repo_id, run_id = _repo_run("sec-eng-c")
    reconcile(repo_id, run_id, [_draft()], [])
    stats = reconcile(repo_id, run_id, [], [])  # HEAD rescans clean
    assert stats["awaiting"] == 1
    assert _rows(repo_id)[0].status.value == "awaiting_rotation"
    stats = reconcile(repo_id, run_id, [_draft()], [])  # secret is back
    assert stats["reopened"] == 1
    assert _rows(repo_id)[0].status.value == "open"


def test_dead_head_secret_closes_when_clean():
    repo_id, run_id = _repo_run("sec-eng-d")
    reconcile(repo_id, run_id, [_draft(live="dead")], [])
    assert _rows(repo_id)[0].status.value == "open"  # still present: removal PR hygiene
    stats = reconcile(repo_id, run_id, [], [])
    assert stats["awaiting"] == 1 and stats["closed"] == 1
    assert _rows(repo_id)[0].status.value == "closed"


def test_liveness_refresh_is_sticky_dead():
    repo_id, run_id = _repo_run("sec-eng-e")
    reconcile(repo_id, run_id, [_draft(live="unknown")], [])
    reconcile(repo_id, run_id, [_draft(live="dead")], [])
    row = _rows(repo_id)[0]
    assert row.liveness == "dead" and row.dead_verdict is True
    reconcile(repo_id, run_id, [_draft(live="unknown")], [])  # flapping validation
    row = _rows(repo_id)[0]
    assert row.dead_verdict is True  # sticky: dead once observed


def test_baseline_lifecycle_and_rebaseline_on_config_change(tmp_path):
    repo_id, run_id = _repo_run("sec-eng-f")
    assert secrets_mod._needs_baseline(repo_id, "cfg-1") is True
    fs_report = {"findings": [], "scan": {"state": "complete", "config_hash": "cfg-1"}}
    hist_report = {"findings": [], "scan": {"state": "complete", "config_hash": "cfg-1"}}
    with (
        mock.patch.object(secrets_mod, "betterleaks_available", return_value=True),
        mock.patch.object(secrets_mod, "scan_worktree", return_value=fs_report),
        mock.patch.object(secrets_mod, "scan_history", return_value=hist_report) as hist,
        mock.patch.object(secrets_mod, "_ensure_full_history", return_value=None),
        mock.patch.object(secrets_mod, "_head_sha", return_value="deadbeef" * 5),
    ):
        notes = secrets_mod.run_secrets_stage(repo_id, run_id, tmp_path)
        assert hist.call_count == 1  # first run baselines
        assert any("baseline recorded" in n for n in notes)
        assert secrets_mod._needs_baseline(repo_id, "cfg-1") is False
        notes = secrets_mod.run_secrets_stage(repo_id, run_id, tmp_path)
        assert hist.call_count == 1  # same config: no re-baseline
        assert not any("baseline recorded" in n for n in notes)
    with (
        mock.patch.object(secrets_mod, "betterleaks_available", return_value=True),
        mock.patch.object(
            secrets_mod,
            "scan_worktree",
            return_value={"findings": [], "scan": {"state": "complete", "config_hash": "cfg-2"}},
        ),
        mock.patch.object(secrets_mod, "scan_history", return_value=hist_report) as hist2,
        mock.patch.object(secrets_mod, "_ensure_full_history", return_value=None),
        mock.patch.object(secrets_mod, "_head_sha", return_value="beefdead" * 5),
    ):
        secrets_mod.run_secrets_stage(repo_id, run_id, tmp_path)
        assert hist2.call_count == 1  # rule update triggers a one-off re-baseline
    with session_scope() as db:
        row = db.get(SecretBaseline, repo_id)
        # The fs hash is canonical — the same value _needs_baseline compares
        # (H5 G4); a differing history hash must not re-trigger baselines.
        assert row is not None and row.config_hash == "cfg-2"
        assert row.baseline_sha == "beefdead" * 5


def test_stage_skips_cleanly_without_binary(tmp_path):
    repo_id, run_id = _repo_run("sec-eng-g")
    with mock.patch.object(secrets_mod, "betterleaks_available", return_value=False):
        notes = secrets_mod.run_secrets_stage(repo_id, run_id, tmp_path)
    assert notes == ["secrets: skipped (betterleaks not on PATH)"]
    assert _rows(repo_id) == []


def test_stage_never_fails_run_scan(tmp_path, monkeypatch):
    """Scanner errors land as notes; the vuln run still finishes DONE."""
    import security_agent.worker.scan as scan_mod

    monkeypatch.chdir(tmp_path)
    repo = repo_svc.connect_repo("sec-eng-h", RepoKind.LOCAL, local_path=str(tmp_path))
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        assert run is not None
        run_id = run.id
    with mock.patch.object(
        secrets_mod, "run_secrets_stage", side_effect=secrets_mod.SecretError("boom")
    ):
        result = scan_mod.run_scan(repo.id, run_id, source_dir=tmp_path)
    assert result["status"] == "done"
    with session_scope() as db:
        assert "secrets: stage failed (boom)" in (db.get(ScanRun, run_id).notes or "")


def test_closed_secret_reopens_with_alert_at_head():
    """A rotated value recommitted to HEAD is a new incident (H5 G1)."""
    from security_agent.audit import get_shared_log

    repo_id, run_id = _repo_run("sec-eng-j")
    reconcile(repo_id, run_id, [_draft(live="dead")], [])
    reconcile(repo_id, run_id, [], [])  # HEAD clean + sticky dead → closed
    assert _rows(repo_id)[0].status.value == "closed"
    before = len(get_shared_log().query(action_class="secret"))
    stats = reconcile(repo_id, run_id, [_draft(live="live")], [])
    assert stats["reopened"] == 1
    row = _rows(repo_id)[0]
    assert row.status.value == "open" and row.liveness == "live"
    assert len(get_shared_log().query(action_class="secret")) == before + 1


def test_informational_secret_reopens_at_head():
    """A baseline-dead fingerprint committed live reopens (H5 G1)."""
    repo_id, run_id = _repo_run("sec-eng-k")
    reconcile(repo_id, run_id, [], [_draft(live="dead")])
    assert _rows(repo_id)[0].status.value == "informational"
    stats = reconcile(repo_id, run_id, [_draft(live="live")], [])
    assert stats["reopened"] == 1
    assert _rows(repo_id)[0].status.value == "open"


def test_history_dead_refresh_closes_awaiting():
    """A later dead history verdict closes history-only secrets (H5 G6)."""
    repo_id, run_id = _repo_run("sec-eng-l")
    live = _draft(path="old/deploy.sh", live="live")
    live["commit_sha"] = "abc123"
    reconcile(repo_id, run_id, [], [live])
    assert _rows(repo_id)[0].status.value == "awaiting_rotation"
    dead = dict(live, liveness="dead")
    stats = reconcile(repo_id, run_id, [], [dead])
    assert stats["new"] == 0  # refresh never re-alerts
    assert stats["closed"] == 1
    row = _rows(repo_id)[0]
    assert row.status.value == "closed" and row.dead_verdict is True


def test_baseline_sticks_when_hashes_differ(tmp_path):
    """The recorded hash is the compared hash: no perpetual re-baseline (H5 G4)."""
    repo_id, run_id = _repo_run("sec-eng-i")
    fs_report = {"findings": [], "scan": {"state": "complete", "config_hash": "fs-hash"}}
    hist_report = {"findings": [], "scan": {"state": "complete", "config_hash": "hist-hash"}}
    with (
        mock.patch.object(secrets_mod, "betterleaks_available", return_value=True),
        mock.patch.object(secrets_mod, "scan_worktree", return_value=fs_report),
        mock.patch.object(secrets_mod, "scan_history", return_value=hist_report) as hist,
        mock.patch.object(secrets_mod, "_ensure_full_history", return_value=None),
        mock.patch.object(secrets_mod, "_head_sha", return_value="ab" * 20),
    ):
        secrets_mod.run_secrets_stage(repo_id, run_id, tmp_path)
        secrets_mod.run_secrets_stage(repo_id, run_id, tmp_path)
        assert hist.call_count == 1


def test_history_failure_keeps_head_results(tmp_path):
    """A broken history scan defers the baseline; HEAD still lands (H5 G7)."""
    repo_id, run_id = _repo_run("sec-eng-m")
    fs_report = {
        "findings": [
            {
                "rule_id": "github-pat",
                "match": {"value": "S3CR3T", "fingerprint": _FP_A},
                "location": {"path": ".env", "start_line": 1},
                "analysis": {"status": "valid"},
            }
        ],
        "scan": {"state": "complete", "config_hash": "cfg-1"},
    }
    with (
        mock.patch.object(secrets_mod, "betterleaks_available", return_value=True),
        mock.patch.object(secrets_mod, "scan_worktree", return_value=fs_report),
        mock.patch.object(
            secrets_mod, "scan_history", side_effect=secrets_mod.SecretError("hist boom")
        ),
        mock.patch.object(secrets_mod, "_ensure_full_history", return_value=None),
        mock.patch.object(
            secrets_mod,
            "run_secrets_removal",
            return_value={"proposal_ids": [], "skipped": {}},
        ),
    ):
        notes = secrets_mod.run_secrets_stage(repo_id, run_id, tmp_path)
    assert any("baseline deferred (hist boom)" in n for n in notes)
    rows = _rows(repo_id)
    assert len(rows) == 1 and rows[0].status.value == "open"


def test_alerts_collect_for_after_commit_emit():
    """With an alerts list, reconcile collects instead of emitting (H5 G8)."""
    from security_agent.audit import get_shared_log

    repo_id, run_id = _repo_run("sec-eng-n")
    before = len(get_shared_log().query(action_class="secret"))
    collected: list[tuple[int, str, str]] = []
    stats = reconcile(repo_id, run_id, [_draft()], [], collected)
    assert stats["new"] == 1 and len(collected) == 1
    assert len(get_shared_log().query(action_class="secret")) == before
    secrets_mod.notify_secret_alert(repo_id, run_id, *collected[0])
    assert len(get_shared_log().query(action_class="secret")) == before + 1


def test_skip_path_emits_audit_warning(tmp_path):
    """Missing binary: loud note + audit warning (H5 G8/C7)."""
    from security_agent.audit import get_shared_log

    repo_id, run_id = _repo_run("sec-eng-o")
    with mock.patch.object(secrets_mod, "betterleaks_available", return_value=False):
        notes = secrets_mod.run_secrets_stage(repo_id, run_id, tmp_path)
    assert notes == ["secrets: skipped (betterleaks not on PATH)"]
    warnings = [
        e for e in get_shared_log().query(action_class="secret") if e["decision"] == "warning"
    ]
    assert any(f"run={run_id}" in e["line"] for e in warnings)


def test_stage_failure_emits_audit_warning(tmp_path, monkeypatch):
    """Stage errors: loud note + audit warning, vuln run still DONE (H5 G8)."""
    import security_agent.worker.scan as scan_mod
    from security_agent.audit import get_shared_log

    monkeypatch.chdir(tmp_path)
    repo = repo_svc.connect_repo("sec-eng-p", RepoKind.LOCAL, local_path=str(tmp_path))
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        assert run is not None
        run_id = run.id
    with mock.patch.object(
        secrets_mod, "run_secrets_stage", side_effect=secrets_mod.SecretError("boom")
    ):
        result = scan_mod.run_scan(repo.id, run_id, source_dir=tmp_path)
    assert result["status"] == "done"
    warnings = [
        e for e in get_shared_log().query(action_class="secret") if e["decision"] == "warning"
    ]
    assert any(f"run={run_id}" in e["line"] and "stage-failed" in e["line"] for e in warnings)


def test_unshallow_reattaches_token(tmp_path):
    """Private origins get credentials for the fetch, stripped after (H5 S3)."""
    calls: list[tuple[str, list[str]]] = []

    def fake(name: str, args: list[str], **kwargs):
        calls.append((name, list(args)))
        if args[:2] == ["rev-parse", "--is-shallow-repository"]:
            return "true\n"
        if args[:2] == ["remote", "get-url"]:
            return "https://example.com/r.git\n"
        return ""

    with mock.patch.object(secrets_mod, "run_allowlisted", side_effect=fake):
        secrets_mod._ensure_full_history(tmp_path, "tok-123")
    set_urls = [a for _, a in calls if a[:2] == ["remote", "set-url"]]
    assert len(set_urls) == 2
    assert "tok-123" in set_urls[0][3]  # attached for the fetch
    assert set_urls[1][3] == "https://example.com/r.git"  # stripped after
    assert any(a[:2] == ["fetch", "--unshallow"] for _, a in calls)
