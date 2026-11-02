"""Post-approval patching: rewriters, grouping, D20 queue, proposals (D8/D20)."""

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from sqlalchemy import select

from security_agent.control import repos as repo_svc
from security_agent.db.models import (
    Dependency,
    DependencyReport,
    DependencyStatus,
    Finding,
    FindingStatus,
    Proposal,
    ProposalStatus,
    RepoKind,
)
from security_agent.db.session import session_scope
from security_agent.sandbox import tools
from security_agent.worker import deps_patch as dp
from security_agent.worker.patch import PatchError

_GIT_IDENTITY = ["-c", "user.email=t@t", "-c", "user.name=t"]


def _repo():
    return repo_svc.connect_repo(
        f"deppatch-{datetime.now(UTC).timestamp()}", RepoKind.LOCAL, local_path="/tmp/x"
    )


def _git_fixture(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "package.json").write_text(json.dumps({"dependencies": {"left-pad": "^1.3.0"}}))
    (path / "package-lock.json").write_text(
        json.dumps({"packages": {"": {}, "node_modules/left-pad": {"version": "1.3.0"}}})
    )
    tools.run_allowlisted("git", ["init", str(path)])
    tools.run_allowlisted("git", ["-C", str(path), "add", "."])
    tools.run_allowlisted("git", ["-C", str(path), *_GIT_IDENTITY, "commit", "-m", "x"])
    return path


def _dep(repo_id: int, **overrides) -> Dependency:
    base = {
        "repo_id": repo_id,
        "ecosystem": "npm",
        "manifest_path": "package.json",
        "package": "left-pad",
        "manifest_spec": "^1.3.0",
        "installed_version": "1.3.0",
        "latest_version": "1.9.0",
        "update_class": "minor",
        "status": DependencyStatus.PROPOSED,
    }
    base.update(overrides)
    with session_scope() as db:
        row = Dependency(**base)
        db.add(row)
        db.flush()
        db.expunge(row)
        return row


def _sync_lock_fake(manifest_dir: Path, pm: str) -> None:
    """Fake lockfile refresh: sync lock versions to the bumped manifest."""
    manifest = json.loads((manifest_dir / "package.json").read_text())
    lock = json.loads((manifest_dir / "package-lock.json").read_text())
    for package, spec in manifest["dependencies"].items():
        lock["packages"][f"node_modules/{package}"]["version"] = str(spec).lstrip("^~")
    (manifest_dir / "package-lock.json").write_text(json.dumps(lock, indent=2))


def test_bump_spec_text_preserves_style():
    assert dp.bump_spec_text("^1.2.3", "1.9.0") == "^1.9.0"
    assert dp.bump_spec_text("~1.2.3", "1.2.9") == "~1.2.9"
    assert dp.bump_spec_text("1.2.3", "1.9.0") == "1.9.0"
    assert dp.bump_spec_text("==1.2.3", "1.9.0") == "==1.9.0"
    assert dp.bump_spec_text(">=1.0", "2.0.0") == ">=2.0.0"
    assert dp.bump_spec_text("*", "2.0.0") == "2.0.0"
    assert dp.bump_spec_text(">=1.0,<2.0", "2.0.0") is None  # upper bound excludes
    assert dp.bump_spec_text(">=1.0,<3.0", "2.0.0") == ">=1.0,<3.0"  # already admits
    assert dp.bump_spec_text("https://x.tgz", "2.0.0") is None
    assert dp.bump_spec_text("<2.0.0", "2.0.0") is None


def test_npm_rewriter_preserves_prefix(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({"dependencies": {"a": "^1.0.0", "b": "2.0.0"}}))
    assert dp.apply_npm_bump_at(manifest, "a", "1.9.0") == "^1.9.0"
    assert dp.apply_npm_bump_at(manifest, "b", "2.1.0") == "2.1.0"
    data = json.loads(manifest.read_text())
    assert data["dependencies"] == {"a": "^1.9.0", "b": "2.1.0"}


def test_requirements_rewriter_pins(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("django==4.2.0  # web\n")
    assert dp.apply_requirements_bump_at(req, "django", "5.0.0") == "==5.0.0"
    assert req.read_text() == "django==5.0.0  # web\n"


def test_pyproject_and_pipfile_rewriters_roundtrip(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "# keep me\n[project]\ndependencies = [\n  # web framework\n  \"flask==3.0.0\",\n]\n"
    )
    assert dp.apply_pyproject_bump_at(pyproject, "flask", "3.1.0") == "==3.1.0"
    text = pyproject.read_text()
    assert "# keep me" in text and "# web framework" in text  # comments survive
    assert '"flask==3.1.0"' in text
    pipfile = tmp_path / "Pipfile"
    pipfile.write_text('[packages]\ncelery = "==5.3.0"\n')
    assert dp.apply_pipfile_bump_at(pipfile, "celery", "5.4.0") == "==5.4.0"
    assert 'celery = "==5.4.0"' in pipfile.read_text()


def test_bump_spec_text_never_narrows_ranges():
    # || unions, hyphen/space sets, tags, and x-ranges are never narrowed.
    assert dp.bump_spec_text("^1.2.3 || ^2.0.0", "2.0.0") == "^1.2.3 || ^2.0.0"
    assert dp.bump_spec_text("^1.2.3 || ^2.0.0", "3.0.0") is None
    assert dp.bump_spec_text(">=1.0 <2.0", "2.0.0") is None
    assert dp.bump_spec_text("1.0.0 - 1.9.9", "2.0.0") is None
    assert dp.bump_spec_text("next", "2.0.0") is None
    assert dp.bump_spec_text("latest", "2.0.0") is None
    assert dp.bump_spec_text("1.2.x", "1.2.9") == "1.2.x"  # already admits
    assert dp.bump_spec_text("1.2.x", "2.0.0") is None
    # Segment count is preserved for ~, ^, and ~=.
    assert dp.bump_spec_text("~1.2", "1.9.0") == "~1.9"
    assert dp.bump_spec_text("~1", "2.0.0") == "~2"
    assert dp.bump_spec_text("^1", "2.0.0") == "^2"
    assert dp.bump_spec_text("~=1.2", "2.0.0") == "~=2.0"
    assert dp.bump_spec_text("~=1.2.3", "2.0.0") == "~=2.0.0"


def test_claim_group_is_atomic():
    repo = _repo()
    a = _dep(repo.id, package="a")
    b = _dep(repo.id, package="b", proposal_id=999999)  # already claimed elsewhere
    assert dp._claim_group(repo.id, [a, b], "test") is None
    with session_scope() as db:
        assert db.get(Dependency, a.id).proposal_id is None  # rolled back whole
    pid = dp._claim_group(repo.id, [a], "test")
    assert pid is not None
    with session_scope() as db:
        assert db.get(Dependency, a.id).proposal_id == pid
        assert db.get(Proposal, pid) is not None


def test_grouping_majors_alone_rest_together():
    repo = _repo()
    major = _dep(repo.id, package="m", update_class="major", latest_version="2.0.0")
    a = _dep(repo.id, package="a", update_class="minor", latest_version="1.9.0")
    b = _dep(repo.id, package="b", update_class="patch", latest_version="1.3.1")
    groups = dp.group_approved([major, a, b])
    assert len(groups) == 2  # one solo major + one shared minor/patch PR
    solo = next(g for g in groups if [m.package for m in g[1]] == ["m"])
    assert "rides alone" in solo[2]  # grouping disclosed (D8)
    shared = next(g for g in groups if len(g[1]) == 2)
    assert "package.json" in shared[2]


def test_run_approved_updates_proposes_verified_patch(tmp_path):
    repo = _repo()
    source = _git_fixture(tmp_path / "repo")
    row = _dep(repo.id)
    with (
        mock.patch.object(dp, "refresh_npm_lockfile", side_effect=_sync_lock_fake),
        mock.patch.object(dp, "_scan_keys_for", return_value=set()),
    ):
        out = dp.run_approved_updates(repo.id, source_dir=source)
    assert len(out["proposal_ids"]) == 1
    assert out["results"][0]["outcome"] == "proposed"
    assert out["results"][0]["bumps"] == {"left-pad": "1.9.0"}
    with session_scope() as db:
        stored = db.get(Dependency, row.id)
        assert stored is not None and stored.proposal_id == out["proposal_ids"][0]
        proposal = db.get(Proposal, out["proposal_ids"][0])
        assert proposal is not None
        assert proposal.grouping_reason.startswith(dp.DEPS_GROUP_PREFIX)
        assert proposal.patch and "1.9.0" in proposal.patch


def test_run_approved_updates_queues_behind_finding(tmp_path):
    repo = _repo()
    source = _git_fixture(tmp_path / "repo")
    row = _dep(repo.id)
    with session_scope() as db:
        finding = Finding(
            repo_id=repo.id, package="left-pad", installed_version="1.3.0",
            advisory_id="CVE-X", status=FindingStatus.PROPOSED,
        )
        db.add(finding)
        db.flush()
        db.add(
            Proposal(
                repo_id=repo.id, finding_ids=[finding.id], package_from="1.3.0",
                package_to="1.3.1", verification_result="ok", status=ProposalStatus.OPEN,
            )
        )
    out = dp.run_approved_updates(repo.id, source_dir=source)
    assert out["proposal_ids"] == []  # no duplicate PR (D20)
    assert out["queued_behind_findings"] == ["package.json:left-pad"]
    with session_scope() as db:
        stored = db.get(Dependency, row.id)
        assert stored is not None and stored.status == DependencyStatus.COVERED_BY_FINDING


def test_validation_failure_releases_rows(tmp_path):
    repo = _repo()
    source = _git_fixture(tmp_path / "repo")
    row = _dep(repo.id)
    with (
        mock.patch.object(dp, "refresh_npm_lockfile", side_effect=_sync_lock_fake),
        mock.patch.object(dp, "_scan_keys_for", side_effect=[set(), {("x", "CVE-NEW")}]),
    ):
        out = dp.run_approved_updates(repo.id, source_dir=source)
    assert out["proposal_ids"] == []
    assert "new advisories" in out["results"][0]["reason"]
    with session_scope() as db:
        stored = db.get(Dependency, row.id)
        assert stored is not None and stored.status == DependencyStatus.UPDATE_AVAILABLE


def test_release_settled_proposals():
    repo = _repo()
    with session_scope() as db:
        proposal = Proposal(
            repo_id=repo.id, finding_ids=[], package_from="a", package_to="b",
            verification_result="ok", status=ProposalStatus.MERGED,
        )
        db.add(proposal)
        db.flush()
        pid = proposal.id
    row = _dep(repo.id, proposal_id=pid)
    assert dp.release_settled_proposals(repo.id) == 1
    with session_scope() as db:
        stored = db.get(Dependency, row.id)
        assert stored is not None
        assert stored.status == DependencyStatus.UPDATE_AVAILABLE
        assert stored.proposal_id is None


def test_report_helpers_render():
    title, body = dp.render_deps_pr(
        ["a 1->2"], ["repo tests passed"], "same manifest", [], "http://d", ["CVE-1"]
    )
    assert title.startswith("[deps]") and "Grouping: same manifest." in body
    assert "CVE-1" in body and "http://d" in body
    assert dp.deps_branch_name("apps/web/package.json", "updates").startswith("deps/")


def test_python_lock_refresh_dispatches_per_kind():
    with mock.patch.object(dp, "run_allowlisted", return_value="") as run:
        dp.refresh_python_lockfile(Path("/tmp"), "poetry", "pyproject")
        run.assert_called_once()
        assert run.call_args.args[:2] == ("poetry", ["lock", "--no-update", "--no-interaction"])
        assert run.call_args.kwargs["allow_network"] is True
    with mock.patch.object(dp, "run_allowlisted", return_value="") as run:
        dp.refresh_python_lockfile(Path("/tmp"), "pdm", "pyproject")
        assert run.call_args.args[:2] == ("pdm", ["lock"])
    with mock.patch.object(dp, "run_allowlisted", return_value="") as run:
        dp.refresh_python_lockfile(Path("/tmp"), "pipfile", "Pipfile")
        assert run.call_args.args[:2] == ("pipenv", ["lock"])
    with mock.patch.object(dp, "run_allowlisted", return_value="") as run:
        dp.refresh_python_lockfile(Path("/tmp"), "requirements", "requirements")  # no-op
        dp.refresh_python_lockfile(Path("/tmp"), None, "pyproject")  # no lock
        run.assert_not_called()


def test_python_lock_refresh_unknown_kind_guidance():
    with __import__("pytest").raises(PatchError, match="no sandbox tool"):
        dp.refresh_python_lockfile(Path("/tmp"), "conda", "pyproject")


def test_security_patch_queues_behind_live_dep_pr():
    """D20 reverse: no second live PR for a package a dep PR already bumps."""
    from security_agent.db.models import RunStatus, RunTrigger, ScanRun, Verdict
    from security_agent.worker.patch import run_patch

    repo = _repo()
    with session_scope() as db:
        for row in db.scalars(select(ScanRun).where(ScanRun.repo_id == repo.id)):
            row.status = RunStatus.DONE
        run = ScanRun(repo_id=repo.id, trigger=RunTrigger.MANUAL)
        db.add(run)
        db.flush()
        run_id = run.id
        finding = Finding(
            repo_id=repo.id, package="left-pad", installed_version="1.3.0",
            advisory_id="CVE-X", status=FindingStatus.OPEN, fixed_versions=["1.3.1"],
        )
        db.add(finding)
        db.flush()
        fid = finding.id
        db.add(Verdict(finding_id=fid, run_id=run_id, reachable=True))
        proposal = Proposal(
            repo_id=repo.id, finding_ids=[], package_from="a", package_to="b",
            verification_result="ok", status=ProposalStatus.OPEN,
            grouping_reason="deps:test",
        )
        db.add(proposal)
        db.flush()
        pid = proposal.id
        db.add(
            Dependency(
                repo_id=repo.id, ecosystem="npm", manifest_path="package.json",
                package="left-pad", installed_version="1.3.0", latest_version="1.9.0",
                status=DependencyStatus.PROPOSED, proposal_id=pid,
            )
        )
    assert dp.live_dep_proposal_for_package(repo.id, "left-pad") is not None
    out = run_patch(repo.id, run_id)
    assert out["proposal_ids"] == []
    assert out["results"][0]["outcome"] == "queued"


def test_pending_approved_scoped_to_report():
    repo = _repo()
    a = _dep(repo.id, package="a")
    b = _dep(repo.id, package="b")
    with session_scope() as db:
        report = DependencyReport(
            repo_id=repo.id, status="decided", summary="s", sections=[],
            decided_keys=["npm|package.json|a"],
        )
        db.add(report)
        db.flush()
        rid = report.id
    scoped = dp._pending_approved(repo.id, rid)
    assert [r.package for r in scoped] == ["a"]
    _ = (a, b)
