"""Slice E: bump mechanics, verify/validate rules, repair loop, report-only."""

import json
from pathlib import Path
from unittest import mock

import pytest
from sqlalchemy import select

from security_agent.control import repos
from security_agent.db.models import (
    Finding,
    FindingStatus,
    Proposal,
    Repo,
    RepoKind,
    ScanRun,
    Verdict,
)
from security_agent.db.session import session_scope
from security_agent.sandbox import tools
from security_agent.worker import build_graph
from security_agent.worker import patch as patch_mod
from security_agent.worker.patch import (
    PatchError,
    apply_bump,
    compare_test_runs,
    diff_files,
    ensure_test_deps,
    patch_one,
    refresh_lockfile,
    run_patch,
    run_repo_tests,
    validate_patch,
)

_GIT_IDENTITY = ["-c", "user.email=t@t", "-c", "user.name=t"]


def _git_repo(path: Path, manifest: dict, lock_version: str = "1.0.0") -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "package.json").write_text(json.dumps(manifest, indent=2))
    (path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"name": "demo"},
                    "node_modules/left-pad": {"version": lock_version},
                }
            },
            indent=2,
        )
    )
    tools.run_allowlisted("git", ["init", str(path)])
    tools.run_allowlisted("git", ["-C", str(path), "add", "."])
    tools.run_allowlisted("git", ["-C", str(path), *_GIT_IDENTITY, "commit", "-m", "x"])
    return path


def _npm_fake():
    """Fakes `npm install` by syncing the lockfile to package.json; runs the rest."""
    real = tools.run_allowlisted

    def fake(name, args, **kwargs):
        if name == "npm" and args[:1] == ["ci"]:
            (Path(kwargs["cwd"]) / "node_modules").mkdir(exist_ok=True)
            return ""
        if name == "npm" and args[:1] == ["install"]:
            workdir = Path(kwargs["cwd"])
            manifest = json.loads((workdir / "package.json").read_text())
            try:
                version = manifest["dependencies"]["left-pad"].lstrip("^~")
            except KeyError:
                version = manifest["overrides"]["left-pad"]
            lock = json.loads((workdir / "package-lock.json").read_text())
            lock["packages"]["node_modules/left-pad"]["version"] = version
            (workdir / "package-lock.json").write_text(json.dumps(lock, indent=2))
            return ""
        return real(name, args, **kwargs)

    return mock.patch.object(patch_mod, "run_allowlisted", side_effect=fake)


def _scan_fake(*, stuck_versions=frozenset()):
    """osv responses that follow lockfile state; stuck versions keep the CVE."""

    def fake(lockfile):
        data = json.loads(Path(lockfile).read_text())
        version = data["packages"]["node_modules/left-pad"]["version"]
        if version == "1.0.0" or version in stuck_versions:
            return {
                "results": [
                    {
                        "packages": [
                            {
                                "package": {"name": "left-pad", "version": version},
                                "vulnerabilities": [{"id": "CVE-2026-0001"}],
                            }
                        ]
                    }
                ]
            }
        return {"results": []}

    return mock.patch.object(patch_mod, "scan_lockfile", side_effect=fake)


def _seed_repo(tag: str = "patch-r"):
    return repos.connect_repo(tag, RepoKind.GIT, url=f"https://example.com/{tag}.git")


def _seed_reachable(repo_id: int, package: str, fixed: list[str] | None) -> int:
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo_id))
        row = Finding(
            repo_id=repo_id,
            package=package,
            installed_version="1.0.0",
            advisory_id="CVE-2026-0001",
            fixed_versions=fixed,
        )
        db.add(row)
        db.flush()
        db.add(Verdict(finding_id=row.id, run_id=run_id, reachable=True))
        db.flush()
        fid = row.id
    return fid


def _finding(fid: int) -> Finding:
    with session_scope() as db:
        row = db.get(Finding, fid)
        assert row is not None
        db.expunge(row)
        return row


def test_apply_bump_rewrites_ranges(tmp_path):
    manifest = {
        "dependencies": {"left-pad": "^1.0.0", "exact": "1.2.3"},
        "devDependencies": {"left-pad": "~1.0.0"},
    }
    (tmp_path / "package.json").write_text(json.dumps(manifest))
    apply_bump(tmp_path, "left-pad", "1.0.1")
    updated = json.loads((tmp_path / "package.json").read_text())
    assert updated["dependencies"]["left-pad"] == "^1.0.1"
    assert updated["devDependencies"]["left-pad"] == "~1.0.1"
    apply_bump(tmp_path, "exact", "1.2.4")
    assert json.loads((tmp_path / "package.json").read_text())["dependencies"]["exact"] == "1.2.4"
    apply_bump(tmp_path, "transitive-dep", "2.0.0")
    assert json.loads((tmp_path / "package.json").read_text())["overrides"] == {
        "transitive-dep": "2.0.0"
    }


def test_ensure_test_deps_skips_without_lockfile(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "demo"}))
    with mock.patch.object(patch_mod, "run_allowlisted") as fake:
        ensure_test_deps(tmp_path)
        fake.assert_not_called()


def test_ensure_test_deps_install_failure_is_patch_error(tmp_path):
    (tmp_path / "package-lock.json").write_text("{}")
    with mock.patch.object(patch_mod, "run_allowlisted", side_effect=RuntimeError("no net")):
        with pytest.raises(PatchError, match="test dependency install failed"):
            ensure_test_deps(tmp_path)


def test_refresh_lockfile_uses_long_timeout(tmp_path):
    with mock.patch.object(patch_mod, "run_allowlisted") as fake:
        refresh_lockfile(tmp_path)
    assert fake.call_args[1]["timeout"] == patch_mod.LOCKFILE_TIMEOUT_SECONDS


def test_diff_files_ignores_node_modules(tmp_path):
    workdir = _git_repo(tmp_path, {"dependencies": {"left-pad": "^1.0.0"}})
    (workdir / "node_modules" / "x").mkdir(parents=True)
    (workdir / "node_modules" / "x" / "i.js").write_text("x\n")
    (workdir / "stray.js").write_text("x\n")
    _changed, untracked = diff_files(workdir)
    assert untracked == {"stray.js"}


def test_patch_one_transitive_uses_overrides(tmp_path):
    repo = _seed_repo("trans-r")
    fid = _seed_reachable(repo.id, "left-pad", ["1.0.1"])
    template = _git_repo(tmp_path, {"dependencies": {"top": "^2.0.0"}})
    with _npm_fake(), _scan_fake():
        with session_scope() as db:
            expunged = db.get(Repo, repo.id)
        outcome = patch_one(expunged, _finding(fid), template, patch_mod.null_adapt)
    assert outcome["outcome"] == "proposed" and outcome["target"] == "1.0.1"


def test_compare_test_runs():
    assert compare_test_runs((True, "ok"), (True, "ok")) == (True, [])
    assert compare_test_runs((False, "bad"), (True, "ok")) == (True, [])
    ok, ignored = compare_test_runs((False, "same"), (False, "same"))
    assert ok and len(ignored) == 1
    assert compare_test_runs((True, "ok"), (False, "boom")) == (False, [])
    assert compare_test_runs((False, "a"), (False, "b")) == (False, [])


def test_compare_test_runs_normalizes_volatile_tokens():
    base = (False, "FAILED tests/t.py:1\n1 failed in 0.12s\nrootdir: /tmp/patch-a1B2c3D4")
    post = (False, "FAILED tests/t.py:1\n1 failed in 1.45s\nrootdir: /tmp/patch-e5F6g7H8")
    ok, ignored = compare_test_runs(base, post)
    assert ok and any("pre-existing" in note for note in ignored)
    changed = (False, "FAILED tests/other.py:9\n1 failed in 0.12s")
    assert compare_test_runs(base, changed) == (False, [])


def test_run_repo_tests_none_without_script(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "demo"}))
    assert run_repo_tests(tmp_path) is None


def test_run_repo_tests_real_pass_and_fail(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "node test.js"}}))
    (tmp_path / "test.js").write_text('console.log("ok");\n')
    ok, out = run_repo_tests(tmp_path)
    assert ok and "ok" in out
    (tmp_path / "test.js").write_text("process.exit(1);\n")
    ok, out = run_repo_tests(tmp_path)
    assert not ok and out.startswith("[exit ")


def test_check_false_returns_output_without_raise():
    def fake(_argv, **kwargs):
        kwargs["stdout"].write(b"oops")
        kwargs["stderr"].write(b"bad")
        return mock.Mock(returncode=1)

    with mock.patch.object(tools.subprocess, "run", side_effect=fake):
        out = tools.run_allowlisted("ripgrep", ["x"], check=False)
        assert out.startswith("[exit 1]") and "bad" in out
        with pytest.raises(RuntimeError, match="failed"):
            tools.run_allowlisted("ripgrep", ["x"])


def test_validate_patch_rules(tmp_path):
    workdir = _git_repo(tmp_path, {"dependencies": {"left-pad": "^1.0.0"}})
    pre = {("left-pad", "CVE-2026-0001")}
    fixed_key = ("left-pad", "CVE-2026-0001")
    with _scan_fake():
        vs = validate_patch(workdir, "left-pad", "1.0.0", [], set(), {("x", "y")})
        assert any("new advisories" in v for v in vs)
        apply_bump(workdir, "left-pad", "1.0.1")
        (workdir / "package-lock.json").write_text(
            json.dumps({"packages": {"node_modules/left-pad": {"version": "1.0.1"}}}, indent=2)
        )
        assert validate_patch(workdir, "left-pad", "1.0.1", [], pre, {fixed_key}) == []
        (workdir / "stray.js").write_text("x\n")
        violations = validate_patch(workdir, "left-pad", "1.0.1", [], pre, {fixed_key})
        assert any("non-dependency" in v for v in violations)
        assert validate_patch(workdir, "left-pad", "1.0.1", ["stray.js"], pre, {fixed_key}) == []
        (workdir / "note.txt").write_text("key=AKIAIOSFODNN7EXAMPLE\n")
        violations = validate_patch(
            workdir, "left-pad", "1.0.1", ["stray.js", "note.txt"], pre, {fixed_key}
        )
        assert any("secret" in v for v in violations)


def test_validate_patch_catches_unremediated_and_new(tmp_path):
    workdir = _git_repo(tmp_path, {"dependencies": {"left-pad": "^1.0.0"}})
    pre = {("left-pad", "CVE-2026-0001")}
    fixed_key = ("left-pad", "CVE-2026-0001")
    with _scan_fake(stuck_versions=frozenset({"1.0.1"})):
        apply_bump(workdir, "left-pad", "1.0.1")
        (workdir / "package-lock.json").write_text(
            json.dumps({"packages": {"node_modules/left-pad": {"version": "1.0.1"}}}, indent=2)
        )
        violations = validate_patch(workdir, "left-pad", "1.0.1", [], pre, {fixed_key})
        assert any("did not remediate" in v for v in violations)


def _run_id(repo_id: int) -> int:
    with session_scope() as db:
        return db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo_id))


def test_patch_one_success_static(tmp_path):
    repo = _seed_repo("static-r")
    fid = _seed_reachable(repo.id, "left-pad", ["1.0.1"])
    template = _git_repo(tmp_path, {"dependencies": {"left-pad": "^1.0.0"}})
    with _npm_fake(), _scan_fake():
        with session_scope() as db:
            expunged = db.get(Repo, repo.id)
        outcome = patch_one(expunged, _finding(fid), template, patch_mod.null_adapt)
    assert outcome["outcome"] == "proposed"
    with session_scope() as db:
        proposal = db.get(Proposal, outcome["proposal_id"])
        assert proposal is not None and "1.0.1" in (proposal.patch or "")
        assert proposal.verification_result.startswith("static analysis clean")
    assert _finding(fid).status == FindingStatus.PROPOSED


def test_patch_one_success_with_tests(tmp_path):
    repo = _seed_repo("tests-r")
    fid = _seed_reachable(repo.id, "left-pad", ["1.0.1"])
    template = _git_repo(
        tmp_path,
        {"dependencies": {"left-pad": "^1.0.0"}, "scripts": {"test": "node test.js"}},
    )
    (template / "test.js").write_text('console.log("green");\n')
    tools.run_allowlisted("git", ["-C", str(template), "add", "."])
    tools.run_allowlisted("git", ["-C", str(template), *_GIT_IDENTITY, "commit", "-m", "t"])
    with _npm_fake(), _scan_fake():
        with session_scope() as db:
            expunged = db.get(Repo, repo.id)
        outcome = patch_one(expunged, _finding(fid), template, patch_mod.null_adapt)
    assert outcome["outcome"] == "proposed"
    with session_scope() as db:
        proposal = db.get(Proposal, outcome["proposal_id"])
        assert proposal is not None
        assert proposal.verification_result == "repo tests passed"


def test_patch_one_tries_alternate_version(tmp_path):
    repo = _seed_repo("alt-r")
    fid = _seed_reachable(repo.id, "left-pad", ["1.0.1", "1.0.2"])
    template = _git_repo(tmp_path, {"dependencies": {"left-pad": "^1.0.0"}})
    with _npm_fake(), _scan_fake(stuck_versions=frozenset({"1.0.1"})):
        with session_scope() as db:
            expunged = db.get(Repo, repo.id)
        outcome = patch_one(expunged, _finding(fid), template, patch_mod.null_adapt)
    assert outcome["outcome"] == "proposed" and outcome["target"] == "1.0.2"


def test_patch_one_exhaustion_is_report_only(tmp_path):
    repo = _seed_repo("exhaust-r")
    fid = _seed_reachable(repo.id, "left-pad", ["1.0.1"])
    template = _git_repo(tmp_path, {"dependencies": {"left-pad": "^1.0.0"}})
    with _npm_fake(), _scan_fake(stuck_versions=frozenset({"1.0.1"})):
        with session_scope() as db:
            expunged = db.get(Repo, repo.id)
        outcome = patch_one(expunged, _finding(fid), template, patch_mod.null_adapt)
    assert outcome["outcome"] == "unpatchable"
    row = _finding(fid)
    assert row.status == FindingStatus.UNPATCHABLE
    assert row.guidance is not None and "did not remediate" in row.guidance
    with session_scope() as db:
        assert db.scalar(select(Proposal).where(Proposal.repo_id == repo.id)) is None


def test_patch_one_no_fixed_version(tmp_path):
    repo = _seed_repo("nofix-r")
    fid = _seed_reachable(repo.id, "left-pad", [])
    template = _git_repo(tmp_path, {"dependencies": {"left-pad": "^1.0.0"}})
    with session_scope() as db:
        expunged = db.get(Repo, repo.id)
    outcome = patch_one(expunged, _finding(fid), template, patch_mod.null_adapt)
    assert outcome["outcome"] == "unpatchable"
    assert _finding(fid).status == FindingStatus.UNPATCHABLE


def test_run_patch_groups_same_package_into_one_proposal(tmp_path):
    repo = _seed_repo("group-r")
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
        for advisory in ("CVE-GRP-1", "CVE-GRP-2"):
            row = Finding(
                repo_id=repo.id,
                package="left-pad",
                installed_version="1.0.0",
                advisory_id=advisory,
                fixed_versions=["1.0.1"],
            )
            db.add(row)
            db.flush()
            db.add(Verdict(finding_id=row.id, run_id=run_id, reachable=True))
    template = _git_repo(tmp_path, {"dependencies": {"left-pad": "^1.0.0"}})
    with _npm_fake(), _scan_fake():
        result = run_patch(repo.id, run_id, source_dir=template)
    assert len(result["proposal_ids"]) == 1
    with session_scope() as db:
        assert "patch: 1 proposed" in (db.get(ScanRun, run_id).notes or "")
    with session_scope() as db:
        proposal = db.get(Proposal, result["proposal_ids"][0])
        assert proposal is not None and len(proposal.finding_ids) == 2
        rows = list(
            db.scalars(
                select(Finding).where(
                    Finding.repo_id == repo.id, Finding.advisory_id.in_(["CVE-GRP-1", "CVE-GRP-2"])
                )
            )
        )
        assert all(r.status == FindingStatus.PROPOSED for r in rows)


def test_run_patch_skips_unreached_and_unknown_ids(tmp_path):
    repo = _seed_repo("skip-r")
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
        silent = Finding(
            repo_id=repo.id,
            package="p",
            installed_version="1",
            advisory_id="ADV",
            fixed_versions=["2"],
            status=FindingStatus.SILENT,
        )
        db.add(silent)
        db.flush()
        db.add(Verdict(finding_id=silent.id, run_id=run_id, reachable=True))
    template = _git_repo(tmp_path, {"dependencies": {"left-pad": "^1.0.0"}})
    result = run_patch(repo.id, run_id, source_dir=template)
    assert result == {"status": "done", "results": [], "proposal_ids": []}
    with pytest.raises(ValueError, match="Unknown repo"):
        run_patch(999999, run_id)


def test_run_patch_prod_refuses():
    settings = mock.Mock(is_prod=True, sandbox_backend="docker")
    with (
        mock.patch("security_agent.config.get_settings", return_value=settings),
        mock.patch("security_agent.sandbox.shutil.which", return_value=None),
    ):
        with pytest.raises(PermissionError, match="Docker sandbox"):
            run_patch(1, 1)


def test_graph_patch_node_runs_real_patches():
    with (
        mock.patch("security_agent.worker.news.poll_news", return_value={}),
        mock.patch(
            "security_agent.worker.news.run_matcher", return_value={"items": 0, "boosts": 0}
        ),
        mock.patch("security_agent.worker.scan.run_scan", return_value={"finding_ids": []}),
        mock.patch(
            "security_agent.worker.reachability.run_reachability",
            return_value={"verdict_ids": []},
        ),
        mock.patch.object(
            patch_mod, "run_patch", return_value={"status": "done", "proposal_ids": [9]}
        ) as fake,
        mock.patch(
            "security_agent.worker.deliver.run_deliver",
            return_value={"status": "done", "proposal_ids": [9]},
        ),
        mock.patch(
            "security_agent.control.gates.run_merge",
            return_value={"status": "done", "merged": [], "skipped": [9]},
        ),
    ):
        result = build_graph().invoke({"repo_id": 1, "run_id": 2})
    fake.assert_called_once_with(1, 2, adapt=mock.ANY)  # adapt hook selected in graph
    assert result["proposals"] == [{"id": 9}]
