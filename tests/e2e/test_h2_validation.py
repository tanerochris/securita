"""Slice H: H2 end-to-end validation.

Default live target is DEFAULT_TEST_REPO_URL (read-only: scan + reachability;
no delivery ever runs against it). Offline graph checks replay recorded
scanner output against the vuln-app fixture with real git workdirs.
"""

import json
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

DEFAULT_TEST_REPO_URL = "https://github.com/devcbuea/dt-collect-web-client"

FIXTURES = Path(__file__).parent / "fixtures"
RECORDED_OSV = FIXTURES / "osv-recorded.json"

_GIT_IDENTITY = ["-c", "user.email=t@t", "-c", "user.name=t"]


def _git(args: list[str], cwd: Path) -> str:
    return tools.run_allowlisted("git", args, cwd=str(cwd))


def _fixture_repo(tmp_path: Path) -> Path:
    """Copy vuln-app to tmp and turn it into a committed git repo."""
    dest = tmp_path / "vuln-app"
    shutil.copytree(FIXTURES / "vuln-app", dest)
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


def _recorded_osv() -> dict:
    return json.loads(RECORDED_OSV.read_text())


def _pkg_name(pkg: dict) -> str:
    return str(pkg.get("package", {}).get("name", ""))


@contextmanager
def _stateful_scan():
    """Scanner fake that follows lockfile state: vulns only at fixture pins."""

    def fake(lockfile):
        data = json.loads(Path(lockfile).read_text())
        versions = {
            key.split("node_modules/")[-1]: entry.get("version")
            for key, entry in data.get("packages", {}).items()
            if key and isinstance(entry, dict)
        }
        pins = {"lodash": "4.17.11", "axios": "0.18.0"}
        out: dict = {"results": []}
        for result in _recorded_osv().get("results", []):
            pkgs = [
                p
                for p in result.get("packages", [])
                if versions.get(_pkg_name(p)) == pins.get(_pkg_name(p))
            ]
            if pkgs:
                out["results"].append({**result, "packages": pkgs})
        return out

    with (
        mock.patch.object(scan_mod, "scan_lockfile", side_effect=fake),
        mock.patch.object(patch_mod, "scan_lockfile", side_effect=fake),
    ):
        yield


def _refresh_fake():
    """Fake `npm install` by syncing lockfile versions to package.json ranges."""
    real = tools.run_allowlisted

    def fake(name, args, **kwargs):
        if name == "npm" and args[:1] == ["install"]:
            workdir = Path(kwargs["cwd"])
            manifest = json.loads((workdir / "package.json").read_text())
            lock_path = workdir / "package-lock.json"
            lock = json.loads(lock_path.read_text())
            deps = {**manifest.get("dependencies", {}), **manifest.get("devDependencies", {})}
            for key, entry in lock.get("packages", {}).items():
                if not key or not isinstance(entry, dict):
                    continue
                pkg = key.split("node_modules/")[-1]
                if pkg in deps:
                    entry["version"] = str(deps[pkg]).lstrip("^~")
            lock_path.write_text(json.dumps(lock, indent=2))
            return ""
        return real(name, args, **kwargs)

    return mock.patch.object(patch_mod, "run_allowlisted", side_effect=fake)


def test_importing_fixture_patches_and_silent_stays_silent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fixture = _fixture_repo(tmp_path)
    repo = _connect_fixture("h2-e2e", fixture)
    run_id = _manual_run(repo.id)
    with (
        _stateful_scan(),
        mock.patch.object(scan_mod, "kev_exploited_ids", return_value=set()),
        _refresh_fake(),
    ):
        scan_result = scan_mod.run_scan(repo.id, run_id)
        assert scan_result["status"] == "done"
        reach_result = reach_mod.run_reachability(repo.id, run_id)
        assert reach_result["status"] == "done"
        patch_result = patch_mod.run_patch(repo.id, run_id)
    recorded_counts: dict[str, int] = {}
    for result in _recorded_osv().get("results", []):
        for pkg in result.get("packages", []):
            recorded_counts[pkg["package"]["name"]] = len(pkg.get("vulnerabilities", []))
    assert recorded_counts.get("lodash", 0) >= 1 and recorded_counts.get("axios", 0) >= 1
    with session_scope() as db:
        lodash_rows = list(
            db.scalars(
                select(Finding).where(Finding.repo_id == repo.id, Finding.package == "lodash")
            )
        )
        axios_rows = list(
            db.scalars(
                select(Finding).where(Finding.repo_id == repo.id, Finding.package == "axios")
            )
        )
        assert len(lodash_rows) == recorded_counts["lodash"]
        assert len(axios_rows) == recorded_counts["axios"]
        assert all(r.status == FindingStatus.PROPOSED for r in lodash_rows)
        assert all(r.status == FindingStatus.SILENT for r in axios_rows)
        assert all(r.silent_reason == "no-import-chain" for r in axios_rows)
        assert len(patch_result["proposal_ids"]) == 1  # one proposal per package group
        proposal = db.get(Proposal, patch_result["proposal_ids"][0])
        assert proposal is not None
        assert len(proposal.finding_ids) == recorded_counts["lodash"]


def test_failed_verification_yields_report_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fixture = _fixture_repo(tmp_path)
    repo = _connect_fixture("h2-report", fixture)
    run_id = _manual_run(repo.id)
    with session_scope() as db:
        finding = Finding(
            repo_id=repo.id,
            package="lodash",
            installed_version="4.17.11",
            advisory_id="CVE-NOFIX-1",
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


def test_withhold_approval_merges_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fixture = _fixture_repo(tmp_path)
    repo = _connect_fixture("h2-withhold", fixture)
    run_id = _manual_run(repo.id)
    graph = build_graph(checkpointer=InMemorySaver(), interrupt_before=["merge"])
    cfg = {"configurable": {"thread_id": "h2-withhold"}}
    with (
        _stateful_scan(),
        mock.patch.object(scan_mod, "kev_exploited_ids", return_value=set()),
        mock.patch("security_agent.worker.news.poll_news", return_value={}),
        mock.patch(
            "security_agent.worker.news.run_matcher", return_value={"items": 0, "boosts": 0}
        ),
        _refresh_fake(),
    ):
        graph.invoke({"repo_id": repo.id, "run_id": run_id}, cfg)
        state = graph.get_state(cfg)
        assert state.next == ("merge",)  # paused BEFORE merge
        final = graph.invoke(Command(resume=True), cfg)  # resume with no approval
    assert "notify" in final["done"]
    assert final.get("merges", []) == []
    with session_scope() as db:
        # Local delivery files no PR gate (branch-only); the merge node skipped
        # for lack of approved gates either way. Proposals stay open: zero merges.
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


def test_live_default_repo_scan_and_reachability(tmp_path):
    reason = _live_prereqs()
    if reason is not None:
        import pytest

        pytest.skip(reason)
    repo = repo_svc.connect_repo("dt-collect-live", RepoKind.GIT, url=DEFAULT_TEST_REPO_URL)
    run_id = _manual_run(repo.id)
    scan_result = scan_mod.run_scan(repo.id, run_id)
    assert scan_result["status"] == "done"
    with session_scope() as db:
        findings = list(db.scalars(select(Finding).where(Finding.repo_id == repo.id)))
    assert len(findings) >= 1, "expected real findings in a 2019-era app"
    for finding in findings:
        assert finding.package and finding.advisory_id
        assert finding.status == FindingStatus.OPEN
    reach_result = reach_mod.run_reachability(repo.id, run_id)
    assert reach_result["status"] == "done"
    assert reach_result["reachable"] + reach_result["unreachable"] == len(findings)
