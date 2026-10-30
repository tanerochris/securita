"""Slice E: H4 end-to-end validation (Python mirrors the H2 checks).

Offline only: the scanner is faked statefully from requirements pins, so the
full graph runs against the vuln-py-app fixture with real git workdirs.
"""

import json
import re
import shutil
import socket
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command
from sqlalchemy import select

from security_agent.control import repos as repo_svc
from security_agent.db.models import (
    Finding,
    FindingStatus,
    Proposal,
    RepoKind,
    RunTrigger,
    ScanRun,
)
from security_agent.db.session import session_scope
from security_agent.sandbox import tools
from security_agent.worker import build_graph
from security_agent.worker import patch as patch_mod
from security_agent.worker import reachability as reach_mod
from security_agent.worker import scan as scan_mod

FIXTURES = Path(__file__).parent / "fixtures"
SYNTHETIC_OSV = FIXTURES / "osv-py-synthetic.json"

DEFAULT_PY_TEST_REPO_URL = "https://github.com/feelcoder/mcq"

_GIT_IDENTITY = ["-c", "user.email=t@t", "-c", "user.name=t"]

_PIN_RE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([^;\s#]+)")


def _git(args: list[str], cwd: Path) -> str:
    return tools.run_allowlisted("git", args, cwd=str(cwd))


def _fixture_repo(tmp_path: Path) -> Path:
    """Copy vuln-py-app to tmp and turn it into a committed git repo."""
    dest = tmp_path / "vuln-py-app"
    import shutil

    shutil.copytree(FIXTURES / "vuln-py-app", dest)
    _git(["init", "-b", "main", str(dest)], dest)
    _git(["-C", str(dest), "add", "."], dest)
    _git(["-C", str(dest), *_GIT_IDENTITY, "commit", "-m", "fixture"], dest)
    return dest


def _connect_fixture(tag: str, path: Path):
    return repo_svc.connect_repo(tag, RepoKind.LOCAL, local_path=str(path))


def _manual_run(repo_id: int) -> int:
    """Finish the connect run, then enqueue a manual run (single-flight)."""
    from datetime import UTC, datetime

    from security_agent.db.models import RunStatus
    from security_agent.worker.scheduler import enqueue_scan

    with session_scope() as db:
        for run in db.scalars(select(ScanRun).where(ScanRun.repo_id == repo_id)):
            run.status = RunStatus.DONE
            run.finished_at = datetime.now(UTC)
    return enqueue_scan(repo_id, RunTrigger.MANUAL).id


def _synthetic_osv() -> dict:
    return json.loads(SYNTHETIC_OSV.read_text())


def _recorded_pins() -> dict[str, str]:
    """package → vulnerable version, from the fixture's committed requirements."""
    pins: dict[str, str] = {}
    for line in (FIXTURES / "vuln-py-app" / "requirements.txt").read_text().splitlines():
        match = _PIN_RE.match(line)
        if match:
            pins[scan_mod.normalize_dist_name(match.group(1))] = match.group(2)
    return pins


@contextmanager
def _stateful_scan():
    """Scanner fake that follows requirements state: vulns only at fixture pins."""

    def fake(lockfile):
        pins: dict[str, str] = {}
        for line in Path(lockfile).read_text().splitlines():
            match = _PIN_RE.match(line)
            if match:
                pins[scan_mod.normalize_dist_name(match.group(1))] = match.group(2)
        vuln_pins = _recorded_pins()
        out: dict = {"results": []}
        for result in _synthetic_osv().get("results", []):
            pkgs = [
                p
                for p in result.get("packages", [])
                if pins.get(scan_mod.normalize_dist_name(str(p["package"]["name"])))
                == vuln_pins.get(scan_mod.normalize_dist_name(str(p["package"]["name"])))
            ]
            if pkgs:
                out["results"].append({**result, "packages": pkgs})
        return out

    with (
        mock.patch.object(scan_mod, "scan_lockfile", side_effect=fake),
        mock.patch.object(patch_mod, "scan_lockfile", side_effect=fake),
    ):
        yield


def test_importing_fixture_patches_and_silent_stays_silent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fixture = _fixture_repo(tmp_path)
    repo = _connect_fixture("h4-e2e", fixture)
    run_id = _manual_run(repo.id)
    with (
        _stateful_scan(),
        mock.patch.object(scan_mod, "kev_exploited_ids", return_value=set()),
    ):
        scan_result = scan_mod.run_scan(repo.id, run_id)
        assert scan_result["status"] == "done"
        reach_result = reach_mod.run_reachability(repo.id, run_id)
        assert reach_result["status"] == "done"
        patch_result = patch_mod.run_patch(repo.id, run_id)
    with session_scope() as db:
        imported = list(
            db.scalars(
                select(Finding).where(Finding.repo_id == repo.id, Finding.package == "insecure-pkg")
            )
        )
        silent = list(
            db.scalars(
                select(Finding).where(Finding.repo_id == repo.id, Finding.package == "unused-pkg")
            )
        )
        assert len(imported) == 1 and imported[0].advisory_id == "CVE-2026-9001"
        assert imported[0].ecosystem == "PyPI"
        assert len(silent) == 1 and silent[0].advisory_id == "CVE-2026-9002"
        assert all(r.status == FindingStatus.PROPOSED for r in imported)
        assert all(r.status == FindingStatus.SILENT for r in silent)
        assert all(r.silent_reason == "no-import-chain" for r in silent)
        assert len(patch_result["proposal_ids"]) == 1
        proposal = db.get(Proposal, patch_result["proposal_ids"][0])
        assert proposal is not None
        assert proposal.finding_ids == [imported[0].id]
        assert "insecure-pkg==1.0.1" in (proposal.patch or "")


def test_failed_verification_yields_report_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fixture = _fixture_repo(tmp_path)
    repo = _connect_fixture("h4-report", fixture)
    run_id = _manual_run(repo.id)
    with session_scope() as db:
        finding = Finding(
            repo_id=repo.id,
            package="insecure-pkg",
            installed_version="1.0.0",
            advisory_id="CVE-NOFIX-1",
            ecosystem="PyPI",
            fixed_versions=[],
        )
        db.add(finding)
        db.flush()
        fid = finding.id
        from security_agent.db.models import Verdict

        db.add(Verdict(finding_id=fid, run_id=run_id, reachable=True))
    result = patch_mod.run_patch(repo.id, run_id, source_dir=fixture)
    assert result["results"][0]["outcome"] == "unpatchable"
    with session_scope() as db:
        row = db.get(Finding, fid)
        assert row is not None and row.status == FindingStatus.UNPATCHABLE
        assert row.guidance is not None and "No fixed version" in row.guidance


def test_failing_pytest_verify_yields_report_only(tmp_path, monkeypatch):
    """Failing repo tests gate the bump: report-only with the failure reason."""
    monkeypatch.chdir(tmp_path)
    fixture = _fixture_repo(tmp_path)
    (fixture / "tests").mkdir()
    (fixture / "tests" / "test_a.py").write_text("def test_x():\n    assert True\n")
    _git(["-C", str(fixture), "add", "."], fixture)
    _git(["-C", str(fixture), *_GIT_IDENTITY, "commit", "-m", "tests"], fixture)
    repo = _connect_fixture("h4-verify-fail", fixture)
    run_id = _manual_run(repo.id)
    with session_scope() as db:
        finding = Finding(
            repo_id=repo.id,
            package="insecure-pkg",
            installed_version="1.0.0",
            advisory_id="CVE-2026-9001",
            ecosystem="PyPI",
            fixed_versions=["1.0.1"],
        )
        db.add(finding)
        db.flush()
        fid = finding.id
        from security_agent.db.models import Verdict

        db.add(Verdict(finding_id=fid, run_id=run_id, reachable=True))
    calls = {"n": 0}

    def flaky(name, args, **kwargs):
        if name == "pip-install":
            Path(args[args.index("--target") + 1]).mkdir(parents=True, exist_ok=True)
            return ""
        if name == "pytest":
            calls["n"] += 1
            return "1 passed" if calls["n"] == 1 else "[exit 1]\nFAILED tests/test_a.py"
        return tools.run_allowlisted(name, args, **kwargs)

    monkeypatch.setattr(patch_mod, "_pytest_probe", True)
    with (
        _stateful_scan(),
        mock.patch.object(patch_mod, "run_allowlisted", side_effect=flaky),
    ):
        result = patch_mod.run_patch(repo.id, run_id, source_dir=fixture)
    assert result["results"][0]["outcome"] == "unpatchable"
    assert "tests failed" in result["results"][0]["reason"]
    with session_scope() as db:
        row = db.get(Finding, fid)
        assert row is not None and row.status == FindingStatus.UNPATCHABLE


def test_withhold_approval_merges_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fixture = _fixture_repo(tmp_path)
    repo = _connect_fixture("h4-withhold", fixture)
    run_id = _manual_run(repo.id)
    graph = build_graph(checkpointer=InMemorySaver(), interrupt_before=["merge"])
    cfg = {"configurable": {"thread_id": "h4-withhold"}}
    with (
        _stateful_scan(),
        mock.patch.object(scan_mod, "kev_exploited_ids", return_value=set()),
        mock.patch("security_agent.worker.news.poll_news", return_value={}),
        mock.patch(
            "security_agent.worker.news.run_matcher", return_value={"items": 0, "boosts": 0}
        ),
    ):
        graph.invoke({"repo_id": repo.id, "run_id": run_id}, cfg)
        state = graph.get_state(cfg)
        assert state.next == ("merge",)  # paused BEFORE merge
        final = graph.invoke(Command(resume=True), cfg)  # resume with no approval
    assert "notify" in final["done"]
    assert final.get("merges", []) == []
    with session_scope() as db:
        proposals = list(db.scalars(select(Proposal).where(Proposal.repo_id == repo.id)))
        assert proposals and all(p.status.value == "open" for p in proposals)
        assert all(p.pr_url is None for p in proposals)
        assert all(p.branch for p in proposals)  # delivery ran; merge withheld


def _live_prereqs() -> str | None:
    """None when a live run is possible, else the skip reason."""
    if shutil.which("osv-scanner") is None:
        return "osv-scanner binary not on PATH"
    try:
        socket.create_connection(("github.com", 443), timeout=5).close()
    except OSError:
        return "github.com unreachable"
    return None


def test_live_python_repo_scan_and_reachability(tmp_path):
    """Live read-only loop over feelcoder/mcq (mirrors the H2 live check).

    Structural assertions only: the repo currently ships no manifests
    (DONE-empty is the designed D1 outcome), and the test stays green if
    upstream adds some later.
    """
    reason = _live_prereqs()
    if reason is not None:
        import pytest

        pytest.skip(reason)
    repo = repo_svc.connect_repo("mcq-live", RepoKind.GIT, url=DEFAULT_PY_TEST_REPO_URL)
    run_id = _manual_run(repo.id)
    scan_result = scan_mod.run_scan(repo.id, run_id)
    assert scan_result["status"] == "done"
    with session_scope() as db:
        findings = list(db.scalars(select(Finding).where(Finding.repo_id == repo.id)))
    for finding in findings:
        assert finding.package and finding.advisory_id
        assert finding.status == FindingStatus.OPEN
    reach_result = reach_mod.run_reachability(repo.id, run_id)
    assert reach_result["status"] == "done"
    assert reach_result["reachable"] + reach_result["unreachable"] == len(findings)
