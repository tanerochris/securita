"""Slice F: H5 end-to-end validation (secrets loop).

Offline: Betterleaks is faked statefully from workdir content (fs) plus a
recorded history report, so the scan runs against the secret-app fixture
with real git workdirs. Proves: live secret alerts + removal PR; merged PR
alone never closes; closure needs HEAD-clean + rotation confirmed.
"""

import shutil
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from sqlalchemy import select

from security_agent.app import accounts as accounts_svc
from security_agent.control import lifecycle
from security_agent.control import repos as repo_svc
from security_agent.db.models import (
    Proposal,
    RepoKind,
    Role,
    RunStatus,
    RunTrigger,
    ScanRun,
    SecretBaseline,
    SecretFinding,
)
from security_agent.db.session import session_scope
from security_agent.sandbox import tools
from security_agent.worker import deliver as deliver_mod
from security_agent.worker import scan as scan_mod
from security_agent.worker import secrets as secrets_mod

FIXTURES = Path(__file__).parent / "fixtures"

_VALUE = "ghp_E2EFAKESECRET000000000000000001"
_HIST_LIVE_VALUE = "ghp_E2EHISTORYLIVE00000000000000002"
_FP_LIVE = "e2" * 32
_FP_HIST_LIVE = "e3" * 32
_FP_HIST_DEAD = "e4" * 32

_GIT_IDENTITY = ["-c", "user.email=t@t", "-c", "user.name=t"]


def _git(args: list[str], cwd: Path) -> str:
    return tools.run_allowlisted("git", args, cwd=str(cwd))


def _fixture_repo(tmp_path: Path) -> Path:
    dest = tmp_path / "secret-app"
    shutil.copytree(FIXTURES / "secret-app", dest)
    _git(["init", "-b", "main", str(dest)], dest)
    _git(["-C", str(dest), "add", "."], dest)
    _git(["-C", str(dest), *_GIT_IDENTITY, "commit", "-m", "fixture"], dest)
    return dest


def _connect_fixture(tag: str, path: Path):
    return repo_svc.connect_repo(tag, RepoKind.LOCAL, local_path=str(path))


def _manual_run(repo_id: int) -> int:
    from datetime import UTC, datetime

    from security_agent.worker.scheduler import enqueue_scan

    with session_scope() as db:
        for run in db.scalars(select(ScanRun).where(ScanRun.repo_id == repo_id)):
            run.status = RunStatus.DONE
            run.finished_at = datetime.now(UTC)
    return enqueue_scan(repo_id, RunTrigger.MANUAL).id


def _stateful_fs(scan_dir) -> dict:
    """Betterleaks fs fake: reports the fake token wherever files hold it."""
    hits = []
    root = Path(scan_dir)
    for rel in (".env", "README.md"):
        try:
            text = (root / rel).read_text()
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if _VALUE in line:
                hits.append(
                    {
                        "rule_id": "github-pat",
                        "match": {"value": _VALUE, "fingerprint": _FP_LIVE},
                        "location": {"path": rel, "start_line": lineno},
                        "analysis": {"status": "valid"},
                    }
                )
    return {"findings": hits, "scan": {"state": "complete", "config_hash": "cfg-e2e"}}


def _recorded_history(*_args) -> dict:
    return {
        "findings": [
            {
                "rule_id": "github-pat",
                "match": {"value": _HIST_LIVE_VALUE, "fingerprint": _FP_HIST_LIVE},
                "location": {"path": "old/deploy.sh", "start_line": 7},
                "attributes": {"git.sha": "abc123"},
                "analysis": {"status": "valid"},
            },
            {
                "rule_id": "slack-bot-token",
                "match": {"value": "xoxb-E2EHISTORYDEAD000000000000", "fingerprint": _FP_HIST_DEAD},
                "location": {"path": "old/bot.py", "start_line": 2},
                "attributes": {"git.sha": "abc123"},
                "analysis": {"status": "revoked"},
            },
        ],
        "scan": {"state": "complete", "config_hash": "cfg-e2e"},
    }


@contextmanager
def _fake_betterleaks():
    with (
        mock.patch.object(secrets_mod, "betterleaks_available", return_value=True),
        mock.patch.object(secrets_mod, "scan_worktree", side_effect=_stateful_fs),
        mock.patch.object(secrets_mod, "scan_history", side_effect=_recorded_history),
        mock.patch.object(secrets_mod, "_ensure_full_history", return_value=None),
        mock.patch.object(scan_mod, "kev_exploited_ids", return_value=set()),
    ):
        yield


def _secrets(repo_id: int) -> list[SecretFinding]:
    with session_scope() as db:
        rows = list(db.scalars(select(SecretFinding).where(SecretFinding.repo_id == repo_id)))
        for r in rows:
            db.expunge(r)
        return rows


def test_live_secret_alerts_with_removal_pr_and_history_once(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fixture = _fixture_repo(tmp_path)
    repo = _connect_fixture("h5-e2e", fixture)
    run_id = _manual_run(repo.id)
    with _fake_betterleaks():
        result = scan_mod.run_scan(repo.id, run_id)
    assert result["status"] == "done"  # DONE-empty for vulns, secrets still ran
    by_fp = {r.fingerprint: r for r in _secrets(repo.id)}
    assert set(by_fp) == {_FP_LIVE, _FP_HIST_LIVE, _FP_HIST_DEAD}
    live = by_fp[_FP_LIVE]
    assert live.status.value == "proposed"  # removal PR proposed at scan
    assert live.liveness == "live" and "rotate" in (live.guidance or "").lower()
    assert live.proposal_id is not None
    assert by_fp[_FP_HIST_LIVE].status.value == "awaiting_rotation"  # HEAD-clean already
    assert by_fp[_FP_HIST_DEAD].status.value == "informational"  # dead: no alert
    with session_scope() as db:
        assert db.get(SecretBaseline, repo.id) is not None
        proposal = db.get(Proposal, live.proposal_id)
        assert proposal is not None and proposal.secret_finding_id == live.id
        notes = db.get(ScanRun, run_id).notes or ""
        assert "secrets:" in notes and "1 removal PR(s) proposed" in notes
    # No secret bytes rest anywhere: findings, proposals, notes, audit.
    blob = repr([r.__dict__ for r in _secrets(repo.id)])
    with session_scope() as db:
        proposals = list(db.scalars(select(Proposal).where(Proposal.repo_id == repo.id)))
        blob += repr([p.__dict__ for p in proposals]) + notes
    from security_agent.audit import get_shared_log

    blob += repr(get_shared_log().query(action_class="secret"))
    assert _VALUE not in blob
    assert "E2EHISTORYLIVE" not in blob
    # Second identical run: history never re-alerts, nothing new.
    run_id2 = _manual_run(repo.id)
    with _fake_betterleaks():
        scan_mod.run_scan(repo.id, run_id2)
    assert len(_secrets(repo.id)) == 3


def test_merged_pr_never_closes_and_rotation_closes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fixture = _fixture_repo(tmp_path)
    repo = _connect_fixture("h5-e2e-close", fixture)
    run_id = _manual_run(repo.id)
    with _fake_betterleaks():
        scan_mod.run_scan(repo.id, run_id)
        delivered = deliver_mod.run_deliver(repo.id, run_id, delivery_root=tmp_path / "out")
    assert delivered["errors"] == []
    assert len(delivered["proposal_ids"]) == 1
    # Delivery artifacts carry no secret bytes either (H5 G2).
    out = tmp_path / "out"
    delivered_files = [p for p in out.rglob("*") if p.is_file()] if out.exists() else []
    assert [p for p in delivered_files if p.suffix == ".patch"] == []
    assert _VALUE not in "".join(p.read_text(errors="replace") for p in delivered_files)
    live = next(r for r in _secrets(repo.id) if r.fingerprint == _FP_LIVE)
    with session_scope() as db:
        proposal = db.get(Proposal, delivered["proposal_ids"][0])
        assert proposal is not None and proposal.branch
        branch = proposal.branch
    # Operator merges the removal branch provider-side; sync observes it.
    _git(["-C", str(fixture), "merge", "--no-ff", branch, "-m", "merge removal"], fixture)
    assert deliver_mod.sync_proposal_states(repo.id)["synced"] == 1
    with session_scope() as db:
        assert db.get(Proposal, proposal.id).status.value == "merged"
    live = next(r for r in _secrets(repo.id) if r.fingerprint == _FP_LIVE)
    assert live.status.value == "proposed"  # merged PR alone never closes
    # Next scan sees HEAD clean: awaiting rotation, still not closed.
    run_id2 = _manual_run(repo.id)
    with _fake_betterleaks():
        scan_mod.run_scan(repo.id, run_id2)
    live = next(r for r in _secrets(repo.id) if r.fingerprint == _FP_LIVE)
    assert live.status.value == "awaiting_rotation"
    # Rotation confirmed by hand: closed. Further scans stay silent.
    from datetime import UTC, datetime

    owner = accounts_svc.create_user(
        f"h5-owner-{datetime.now(UTC).timestamp()}@example.com", None, Role.OWNER
    )
    assert lifecycle.mark_secret_rotated(live.id, owner).status.value == "closed"
    run_id3 = _manual_run(repo.id)
    with _fake_betterleaks():
        scan_mod.run_scan(repo.id, run_id3)
    live = next(r for r in _secrets(repo.id) if r.fingerprint == _FP_LIVE)
    assert live.status.value == "closed"


def test_graph_runs_secrets_stage_without_topology_change(tmp_path, monkeypatch):
    """The unchanged 7-node graph carries secrets notes on the run."""
    from security_agent.worker import build_graph

    monkeypatch.chdir(tmp_path)
    fixture = _fixture_repo(tmp_path)
    repo = _connect_fixture("h5-e2e-graph", fixture)
    run_id = _manual_run(repo.id)
    graph = build_graph()
    with (
        _fake_betterleaks(),
        mock.patch("security_agent.worker.news.poll_news", return_value={}),
        mock.patch(
            "security_agent.worker.news_intel.process_news",
            return_value={"classified": 0, "major": 0, "minted": 0, "linked": 0},
        ),
    ):
        final = graph.invoke({"repo_id": repo.id, "run_id": run_id})
    assert "notify" in final["done"]
    with session_scope() as db:
        notes = db.get(ScanRun, run_id).notes or ""
        assert "secrets:" in notes
    assert len(_secrets(repo.id)) == 3


def test_live_betterleaks_invocation_contract(tmp_path):
    """Live probe: real binary argv + report shape, skipped when absent."""
    import pytest

    if shutil.which("betterleaks") is None:
        pytest.skip("betterleaks binary not on PATH")
    fixture = _fixture_repo(tmp_path)
    report = secrets_mod.scan_worktree(fixture)
    assert isinstance(report.get("findings"), list)
    drafts, config_hash, dropped = secrets_mod.normalize_report(report)
    assert isinstance(drafts, list) and dropped >= 0
    assert config_hash is None or isinstance(config_hash, str)
    hist = secrets_mod.scan_history(fixture)
    assert isinstance(hist.get("findings"), list)
