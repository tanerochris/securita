"""H4 Slice D: requirements bumps, pytest verify, python validate, routing."""

import json
import re
import sys
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
from security_agent.worker import patch as patch_mod
from security_agent.worker.patch import (
    PatchError,
    apply_python_bump,
    discover_requirement_files,
    ensure_python_test_deps,
    has_python_tests,
    patch_python_group,
    python_pin_resolves,
    run_patch,
    run_python_tests,
    sanitized_requirements,
    validate_python_patch,
)
from security_agent.worker.scan import normalize_dist_name

_GIT_IDENTITY = ["-c", "user.email=t@t", "-c", "user.name=t"]


def _git_repo_py(path: Path, requirements: str, extra: dict[str, str] | None = None) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "requirements.txt").write_text(requirements)
    for rel, content in (extra or {}).items():
        target = path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    tools.run_allowlisted("git", ["init", str(path)])
    tools.run_allowlisted("git", ["-C", str(path), "add", "."])
    tools.run_allowlisted("git", ["-C", str(path), *_GIT_IDENTITY, "commit", "-m", "x"])
    return path


def _pip_pytest_fake(*, pytest_out: str = "2 passed"):
    """Fakes pip installs (creates target) and pytest runs; runs the rest."""
    real = tools.run_allowlisted

    def fake(name, args, **kwargs):
        if name == "pip-install":
            assert "--target" in args and "-r" in args
            Path(args[args.index("--target") + 1]).mkdir(parents=True, exist_ok=True)
            return ""
        if name == "pytest" and args == ["--version"]:
            return "pytest 9.2.0"
        if name == "pytest":
            assert kwargs["env"]["PYTHONPATH"].endswith(".pip-deps")
            return pytest_out
        return real(name, args, **kwargs)

    return mock.patch.object(patch_mod, "run_allowlisted", side_effect=fake)


_PY_LOCK_NAMES = ("poetry.lock", "Pipfile.lock", "pdm.lock", "uv.lock")


def _py_scan_fake(*, stuck=frozenset()):
    """osv responses that follow requirements pins; stuck versions keep the CVE.

    Managed lockfiles always report the CVE when they mention the package:
    v1 never re-locks, so a stale lock cannot remediate.
    """

    def fake(lockfile):
        lockfile = Path(lockfile)
        pins: dict[str, str] = {}
        text = lockfile.read_text()
        for line in text.splitlines():
            match = re.match(r"\s*([A-Za-z0-9._-]+)\s*==\s*([^;\s#]+)", line)
            if match:
                pins[normalize_dist_name(match.group(1))] = match.group(2)
        if lockfile.name in _PY_LOCK_NAMES and "insecure-pkg" in text:
            version = "1.0.0"  # stale lock still lists the vulnerable release
        else:
            version = pins.get("insecure-pkg", "")
        if version == "1.0.0" or version in stuck:
            return {
                "results": [
                    {
                        "packages": [
                            {
                                "package": {
                                    "name": "insecure-pkg",
                                    "version": version,
                                    "ecosystem": "PyPI",
                                },
                                "vulnerabilities": [{"id": "CVE-2026-9001"}],
                            }
                        ]
                    }
                ]
            }
        return {"results": []}

    return mock.patch.object(patch_mod, "scan_lockfile", side_effect=fake)


def _seed_repo(tag: str = "pypatch-r"):
    return repos.connect_repo(tag, RepoKind.GIT, url=f"https://example.com/{tag}.git")


def _seed_reachable(repo_id: int, package: str, fixed: list[str] | None) -> int:
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo_id))
        row = Finding(
            repo_id=repo_id,
            package=package,
            installed_version="1.0.0",
            advisory_id="CVE-2026-9001",
            ecosystem="PyPI",
            fixed_versions=fixed,
        )
        db.add(row)
        db.flush()
        db.add(Verdict(finding_id=row.id, run_id=run_id, reachable=True))
        db.flush()
        return row.id


def _finding(fid: int) -> Finding:
    with session_scope() as db:
        row = db.get(Finding, fid)
        assert row is not None
        db.expunge(row)
        return row


def test_apply_bump_rewrites_pins(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "insecure-pkg==1.0.0\n"
        "spaced  ==  1.0.0  # keep me\n"
        "with-extra[x,y]==1.0; python_version>'3'\n"
        "bare-pkg\n"
        "other==2.0\n"
    )
    changed = apply_python_bump(tmp_path, "insecure-pkg", "1.0.1")
    assert changed == ["requirements.txt"]
    assert (tmp_path / "requirements.txt").read_text().splitlines()[0] == "insecure-pkg==1.0.1"
    apply_python_bump(tmp_path, "spaced", "2.0")
    assert "spaced  ==  2.0  # keep me" in (tmp_path / "requirements.txt").read_text()
    apply_python_bump(tmp_path, "with-extra", "3.0")
    assert "with-extra[x,y]==3.0; python_version>'3'" in (tmp_path / "requirements.txt").read_text()
    apply_python_bump(tmp_path, "bare-pkg", "4.0")
    assert "bare-pkg==4.0" in (tmp_path / "requirements.txt").read_text()


def test_apply_bump_multi_file_and_transitive(tmp_path):
    (tmp_path / "requirements.txt").write_text("a==1\n")
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "base.txt").write_text("insecure-pkg==1.0.0\n")
    changed = apply_python_bump(tmp_path, "insecure-pkg", "1.0.1")
    assert changed == ["requirements/base.txt"]
    assert "insecure-pkg==1.0.1" in (tmp_path / "requirements" / "base.txt").read_text()
    changed = apply_python_bump(tmp_path, "transitive-dep", "2.0")
    assert changed == ["requirements.txt"]
    assert "transitive-dep==2.0" in (tmp_path / "requirements.txt").read_text()


def test_apply_bump_creates_requirements(tmp_path):
    assert apply_python_bump(tmp_path, "new-pkg", "1.0") == ["requirements.txt"]
    assert (tmp_path / "requirements.txt").read_text() == "new-pkg==1.0\n"


def test_apply_bump_refuses_unsafe_shapes(tmp_path):
    (tmp_path / "requirements.txt").write_text("insecure-pkg>=1.0\n")
    with pytest.raises(PatchError, match="version range"):
        apply_python_bump(tmp_path, "insecure-pkg", "1.0.1")
    (tmp_path / "requirements.txt").write_text("insecure-pkg @ https://x/pkg.tar.gz\n")
    with pytest.raises(PatchError, match="unsupported declaration"):
        apply_python_bump(tmp_path, "insecure-pkg", "1.0.1")
    (tmp_path / "requirements.txt").write_text("-e git+https://x/r#egg=insecure-pkg\n")
    with pytest.raises(PatchError, match="unsupported declaration"):
        apply_python_bump(tmp_path, "insecure-pkg", "1.0.1")
    (tmp_path / "requirements.txt").write_text("insecure-pkg==1.0.0 \\\n")
    with pytest.raises(PatchError, match="not safely editable"):
        apply_python_bump(tmp_path, "insecure-pkg", "1.0.1")


def test_apply_bump_preserves_compound_tail_and_refuses_hashes(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "comp==1.0,!=1.5; python_version>'3'\nhashed==1.0 --hash=sha256:abc\n"
    )
    apply_python_bump(tmp_path, "comp", "1.0.1")
    assert "comp==1.0.1,!=1.5; python_version>'3'" in (tmp_path / "requirements.txt").read_text()
    with pytest.raises(PatchError, match="not safely editable"):
        apply_python_bump(tmp_path, "hashed", "1.0.1")
    (tmp_path / "requirements.txt").write_text("excluded==1.0,!=1.0.1\n")
    with pytest.raises(PatchError, match="version range"):
        apply_python_bump(tmp_path, "excluded", "1.0.1")  # target is excluded: refuse


def test_apply_bump_follows_includes_and_constraints(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r deps/base.txt\n-c constraints.txt\n")
    (tmp_path / "deps").mkdir()
    (tmp_path / "deps" / "base.txt").write_text("insecure-pkg==1.0.0\n")
    (tmp_path / "constraints.txt").write_text("other-pkg==2.0\n")
    changed = apply_python_bump(tmp_path, "insecure-pkg", "1.0.1")
    assert "deps/base.txt" in changed
    assert "insecure-pkg==1.0.1" in (tmp_path / "deps" / "base.txt").read_text()
    changed = apply_python_bump(tmp_path, "other-pkg", "2.1")
    assert "constraints.txt" in changed
    assert "other-pkg==2.1" in (tmp_path / "constraints.txt").read_text()
    assert python_pin_resolves(tmp_path, "insecure-pkg", "1.0.1") is True


def test_apply_bump_ignores_escaping_include(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r ../outside.txt\n")
    (tmp_path.parent / "outside.txt").write_text("evil==1\n")
    changed = apply_python_bump(tmp_path, "evil", "2")
    assert changed == ["requirements.txt"]  # transitive append; outside file untouched
    assert (tmp_path.parent / "outside.txt").read_text() == "evil==1\n"


def test_apply_bump_refuses_malicious_target(tmp_path):
    (tmp_path / "requirements.txt").write_text("pkg==1.0\n")
    with pytest.raises(PatchError, match="malformed target"):
        apply_python_bump(tmp_path, "pkg", "1.0\n evil==9")


def test_apply_bump_preserves_crlf(tmp_path):
    (tmp_path / "requirements.txt").write_bytes(b"insecure-pkg==1.0.0\r\nbare-pkg\r\n")
    apply_python_bump(tmp_path, "insecure-pkg", "1.0.1")
    apply_python_bump(tmp_path, "bare-pkg", "4.0")
    assert (tmp_path / "requirements.txt").read_bytes() == (
        b"insecure-pkg==1.0.1\r\nbare-pkg==4.0\r\n"
    )


def test_apply_bump_preserves_options(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "--index-url https://x\n-r other.txt\ninsecure-pkg==1.0.0\n"
    )
    apply_python_bump(tmp_path, "insecure-pkg", "1.0.1")
    text = (tmp_path / "requirements.txt").read_text()
    assert text.startswith("--index-url https://x\n-r other.txt\n")


def test_python_pin_resolves(tmp_path):
    (tmp_path / "requirements.txt").write_text("insecure-pkg==1.0.1\n")
    assert python_pin_resolves(tmp_path, "Insecure_Pkg", "1.0.1") is True
    assert python_pin_resolves(tmp_path, "insecure-pkg", "1.0.2") is False
    assert python_pin_resolves(tmp_path, "other", "1.0.1") is False


def test_sanitized_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "flask==3.0  # web\n"
        "-r more.txt\n"
        "--index-url https://evil.example\n"
        "-e .\n"
        "pkg @ https://x/pkg.tar.gz\n"
        "cont==1 \\\n"
    )
    (tmp_path / "more.txt").write_text("gunicorn>=1\n-r requirements.txt\n")
    text, skipped = sanitized_requirements(tmp_path, discover_requirement_files(tmp_path))
    assert text == "flask==3.0\n"  # pins-only: the range is dropped, not installed
    assert any("option dropped" in s for s in skipped)
    assert any("non-pin dropped" in s for s in skipped)
    assert any("unpinned spec dropped" in s for s in skipped)
    assert any("continuation dropped" in s for s in skipped)
    assert any("cycle" in s for s in skipped)  # mutual include terminates
    assert "evil.example" not in text and "gunicorn" not in text


def test_sanitized_keeps_hashes_and_markers_drops_compounds(tmp_path):
    from security_agent.worker.patch import _canonical_pin

    assert _canonical_pin("pkg==1.0 --hash=sha256:abc123") == "pkg==1.0 --hash=sha256:abc123"
    assert _canonical_pin("pkg[x]==1.0; python_version>'3'") == "pkg[x]==1.0; python_version>'3'"
    assert _canonical_pin("pkg>=1.0") is None
    assert _canonical_pin("bare-pkg") is None
    assert _canonical_pin("pkg==1.0,!=1.5") is None
    assert _canonical_pin("pkg==1.0 --hash=md5:abc") is None
    assert _canonical_pin("pkg==1.0\n evil==9") is None


def test_sanitized_blocks_escape_and_depth(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("-r ../outside.txt\n")
    (tmp_path.parent / "outside.txt").write_text("evil==1\n")
    text, skipped = sanitized_requirements(tmp_path, discover_requirement_files(tmp_path))
    assert text == "" and any("outside repo" in s for s in skipped)
    monkeypatch.setattr(patch_mod, "_MAX_INCLUDE_DEPTH", 0)
    (tmp_path / "requirements.txt").write_text("-r more.txt\n")
    (tmp_path / "more.txt").write_text("a==1\n")
    # Explicit files, not discovery: discovery pre-resolves includes now.
    text, skipped = sanitized_requirements(tmp_path, [tmp_path / "requirements.txt"])
    assert text == "" and any("depth" in s for s in skipped)


def test_ensure_python_test_deps_success_and_argv(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0\n")
    seen: dict = {}

    def fake(name, args, **kwargs):
        seen["name"], seen["args"] = name, args
        Path(args[args.index("--target") + 1]).mkdir(parents=True, exist_ok=True)
        return ""

    with mock.patch.object(patch_mod, "run_allowlisted", side_effect=fake):
        assert ensure_python_test_deps(tmp_path) == ""
    assert seen["name"] == "pip-install"
    assert tools.MANIFEST["pip-install"][:5] == [
        "python3",
        "-m",
        "pip",
        "install",
        "--no-input",
    ]
    assert "--only-binary" in tools.MANIFEST["pip-install"]
    assert not (tmp_path / ".agent-requirements.txt").exists()  # temp cleaned
    with mock.patch.object(patch_mod, "run_allowlisted") as noop:
        assert ensure_python_test_deps(tmp_path) == ""  # .pip-deps exists: no-op
        noop.assert_not_called()


def test_ensure_python_test_deps_never_raises(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0\n")
    with mock.patch.object(patch_mod, "run_allowlisted", side_effect=RuntimeError("no net")):
        note = ensure_python_test_deps(tmp_path)
    assert "compared raw outputs" in note
    with mock.patch.object(patch_mod, "run_allowlisted", side_effect=FileNotFoundError("no pip")):
        assert "compared raw outputs" in ensure_python_test_deps(tmp_path)
    (tmp_path / "requirements.txt").write_text("# empty\n")
    assert "no installable" in ensure_python_test_deps(tmp_path)


def test_has_python_tests(tmp_path):
    assert has_python_tests(tmp_path) is False
    (tmp_path / "app.py").write_text("x = 1\n")
    assert has_python_tests(tmp_path) is False
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("x = 1\n")
    assert has_python_tests(tmp_path) is True


def test_has_python_tests_ignores_venv(tmp_path):
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "test_a.py").write_text("x = 1\n")
    assert has_python_tests(tmp_path) is False
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    assert has_python_tests(tmp_path) is True


def test_run_python_tests_none_paths(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("")
    assert run_python_tests(tmp_path) is None  # no tests → static
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("def test_x(): assert True\n")
    monkeypatch.setattr(patch_mod, "_pytest_probe", False)
    assert run_python_tests(tmp_path) is None  # no runner → static
    monkeypatch.setattr(patch_mod, "_pytest_probe", True)
    with _pip_pytest_fake(pytest_out="[exit 5]\nno tests ran\n"):
        assert run_python_tests(tmp_path) is None  # nothing collected → static


def test_run_python_tests_mocked_pass_and_note(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("flask==3.0\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("def test_x(): assert True\n")
    monkeypatch.setattr(patch_mod, "_pytest_probe", True)
    with _pip_pytest_fake(pytest_out="1 passed"):
        passed, _out, note = run_python_tests(tmp_path)
    assert passed is True and note == ""


def test_run_python_tests_real_runner(tmp_path, monkeypatch):
    """Real pytest via this interpreter's own bin dir; empty reqs keep it hermetic."""
    (tmp_path / "requirements.txt").write_text("# nothing to install\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_ok.py").write_text("def test_ok():\n    assert 1 + 1 == 2\n")
    monkeypatch.setattr(patch_mod, "_pytest_probe", None)
    import os

    venv_bin = str(Path(sys.executable).parent)
    monkeypatch.setenv("PATH", f"{venv_bin}{os.pathsep}{os.environ['PATH']}")
    result = run_python_tests(tmp_path)
    assert result is not None
    passed, out, note = result
    assert passed is True and "passed" in out
    assert "no installable" in note


def test_validate_python_patch_rules(tmp_path, monkeypatch):
    # Sentinel marker (not a real secret shape): proves diff content flows
    # into the secrets check; the marker list itself is shared with Node.
    monkeypatch.setattr(patch_mod, "_SECRET_MARKERS", ("SENTINEL-NOT-A-SECRET-XYZ",))
    workdir = _git_repo_py(tmp_path, "insecure-pkg==1.0.0\n")
    pre = {("insecure-pkg", "CVE-2026-9001")}
    fixed = {("insecure-pkg", "CVE-2026-9001")}
    with _py_scan_fake():
        vs = validate_python_patch(workdir, "insecure-pkg", "1.0.0", [], set(), {("x", "y")})
        assert any("new advisories" in v for v in vs)
        apply_python_bump(workdir, "insecure-pkg", "1.0.1")
        assert validate_python_patch(workdir, "insecure-pkg", "1.0.1", [], pre, fixed) == []
        (workdir / "stray.py").write_text("x\n")
        violations = validate_python_patch(workdir, "insecure-pkg", "1.0.1", [], pre, fixed)
        assert any("non-dependency" in v for v in violations)
        assert (
            validate_python_patch(workdir, "insecure-pkg", "1.0.1", ["stray.py"], pre, fixed) == []
        )
        (workdir / "note.txt").write_text("key=SENTINEL-NOT-A-SECRET-XYZ\n")
        violations = validate_python_patch(
            workdir, "insecure-pkg", "1.0.1", ["stray.py", "note.txt"], pre, fixed
        )
        assert any("secret" in v for v in violations)


@pytest.mark.parametrize("lock", _PY_LOCK_NAMES)
def test_validate_python_patch_stale_lock_report_only(tmp_path, lock):
    workdir = _git_repo_py(
        tmp_path,
        "insecure-pkg==1.0.0\n",
        extra={lock: '[[package]]\nname = "insecure-pkg"\nversion = "1.0.0"\n'},
    )
    pre = {("insecure-pkg", "CVE-2026-9001")}
    with _py_scan_fake():
        apply_python_bump(workdir, "insecure-pkg", "1.0.1")
        violations = validate_python_patch(workdir, "insecure-pkg", "1.0.1", [], pre, pre)
        assert any("did not remediate" in v for v in violations)


def test_patch_python_group_exhaustion_mentions_relock(tmp_path):
    repo, fid = _repo_and_finding("pyrelock-r", ["1.0.1"])
    template = _git_repo_py(
        tmp_path,
        "insecure-pkg==1.0.0\n",
        extra={"poetry.lock": '[[package]]\nname = "insecure-pkg"\nversion = "1.0.0"\n'},
    )
    with _py_scan_fake():
        with session_scope() as db:
            expunged = db.get(Repo, repo.id)
        outcome = patch_python_group(expunged, [_finding(fid)], template, patch_mod.null_adapt)
    assert outcome["outcome"] == "unpatchable"
    assert "re-lock" in outcome["reason"]
    assert _finding(fid).status == FindingStatus.UNPATCHABLE


def test_validate_python_patch_catches_unremediated(tmp_path):
    workdir = _git_repo_py(tmp_path, "insecure-pkg==1.0.0\n")
    pre = {("insecure-pkg", "CVE-2026-9001")}
    with _py_scan_fake(stuck=frozenset({"1.0.1"})):
        apply_python_bump(workdir, "insecure-pkg", "1.0.1")
        violations = validate_python_patch(workdir, "insecure-pkg", "1.0.1", [], pre, pre)
        assert any("did not remediate" in v for v in violations)


def _run_id(repo_id: int) -> int:
    with session_scope() as db:
        return db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo_id))


def _repo_and_finding(tag: str, fixed):
    repo = _seed_repo(tag)
    fid = _seed_reachable(repo.id, "insecure-pkg", fixed)
    return repo, fid


def test_patch_python_group_static_success(tmp_path):
    repo, fid = _repo_and_finding("pystatic-r", ["1.0.1"])
    template = _git_repo_py(tmp_path, "insecure-pkg==1.0.0\n")
    with _py_scan_fake():
        with session_scope() as db:
            expunged = db.get(Repo, repo.id)
        outcome = patch_python_group(expunged, [_finding(fid)], template, patch_mod.null_adapt)
    assert outcome["outcome"] == "proposed"
    with session_scope() as db:
        proposal = db.get(Proposal, outcome["proposal_id"])
        assert proposal is not None and "insecure-pkg==1.0.1" in (proposal.patch or "")
        assert proposal.verification_result.startswith("static analysis clean")
    assert _finding(fid).status == FindingStatus.PROPOSED


def test_patch_python_group_with_tests(tmp_path, monkeypatch):
    repo, fid = _repo_and_finding("pytest-r", ["1.0.1"])
    template = _git_repo_py(
        tmp_path,
        "insecure-pkg==1.0.0\n",
        {"tests/test_a.py": "def test_x():\n    assert True\n"},
    )
    monkeypatch.setattr(patch_mod, "_pytest_probe", True)
    with _pip_pytest_fake(pytest_out="1 passed"), _py_scan_fake():
        with session_scope() as db:
            expunged = db.get(Repo, repo.id)
        outcome = patch_python_group(expunged, [_finding(fid)], template, patch_mod.null_adapt)
    assert outcome["outcome"] == "proposed"
    with session_scope() as db:
        proposal = db.get(Proposal, outcome["proposal_id"])
        assert proposal is not None
        assert proposal.verification_result == "repo tests passed"


def test_patch_python_group_tests_gate_regressions(tmp_path, monkeypatch):
    repo, fid = _repo_and_finding("pytest-gate-r", ["1.0.1"])
    template = _git_repo_py(
        tmp_path,
        "insecure-pkg==1.0.0\n",
        {"tests/test_a.py": "def test_x():\n    assert True\n"},
    )
    monkeypatch.setattr(patch_mod, "_pytest_probe", True)
    calls = {"n": 0}

    def flaky(name, args, **kwargs):
        if name == "pip-install":
            return ""
        if name == "pytest" and args == ["--version"]:
            return "pytest 9.2.0"
        if name == "pytest":
            calls["n"] += 1
            return "1 passed" if calls["n"] == 1 else "[exit 1]\nFAILED"
        return tools.run_allowlisted(name, args, **kwargs)

    with mock.patch.object(patch_mod, "run_allowlisted", side_effect=flaky), _py_scan_fake():
        with session_scope() as db:
            expunged = db.get(Repo, repo.id)
        outcome = patch_python_group(expunged, [_finding(fid)], template, patch_mod.null_adapt)
    assert outcome["outcome"] == "unpatchable"
    assert "tests failed" in outcome["reason"]
    assert _finding(fid).status == FindingStatus.UNPATCHABLE


def test_patch_python_group_alternate_and_exhaustion(tmp_path):
    repo, fid = _repo_and_finding("pyalt-r", ["1.0.1", "1.0.2"])
    template = _git_repo_py(tmp_path, "insecure-pkg==1.0.0\n")
    with _py_scan_fake(stuck=frozenset({"1.0.1"})):
        with session_scope() as db:
            expunged = db.get(Repo, repo.id)
        outcome = patch_python_group(expunged, [_finding(fid)], template, patch_mod.null_adapt)
    assert outcome["outcome"] == "proposed" and outcome["target"] == "1.0.2"
    repo2, fid2 = _repo_and_finding("pyexhaust-r", ["1.0.1"])
    template2 = tmp_path / "t2"
    _git_repo_py(template2, "insecure-pkg==1.0.0\n")
    with _py_scan_fake(stuck=frozenset({"1.0.1"})):
        with session_scope() as db:
            expunged = db.get(Repo, repo2.id)
        outcome = patch_python_group(expunged, [_finding(fid2)], template2, patch_mod.null_adapt)
    assert outcome["outcome"] == "unpatchable"
    assert _finding(fid2).status == FindingStatus.UNPATCHABLE


def test_patch_python_group_no_fixed_version(tmp_path):
    repo, fid = _repo_and_finding("pynofix-r", [])
    template = _git_repo_py(tmp_path, "insecure-pkg==1.0.0\n")
    with session_scope() as db:
        expunged = db.get(Repo, repo.id)
    outcome = patch_python_group(expunged, [_finding(fid)], template, patch_mod.null_adapt)
    assert outcome["outcome"] == "unpatchable"
    assert _finding(fid).status == FindingStatus.UNPATCHABLE


def test_run_patch_separates_ecosystems(tmp_path):
    repo = _seed_repo("ecosep-r")
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
        for eco in ("npm", "PyPI"):
            row = Finding(
                repo_id=repo.id,
                package="same-name",
                installed_version="1",
                advisory_id=f"ADV-{eco}",
                ecosystem=eco,
                fixed_versions=["2"],
            )
            db.add(row)
            db.flush()
            db.add(Verdict(finding_id=row.id, run_id=run_id, reachable=True))
    template = _git_repo_py(tmp_path, "same-name==1\n")
    (template / "package.json").write_text(json.dumps({"dependencies": {"same-name": "^1"}}))
    tools.run_allowlisted("git", ["-C", str(template), "add", "."])
    tools.run_allowlisted("git", ["-C", str(template), *_GIT_IDENTITY, "commit", "-m", "m"])
    with (
        mock.patch.object(
            patch_mod, "patch_group", return_value={"outcome": "proposed", "proposal_id": 1}
        ) as node_fake,
        mock.patch.object(
            patch_mod, "patch_python_group", return_value={"outcome": "proposed", "proposal_id": 2}
        ) as py_fake,
    ):
        result = run_patch(repo.id, run_id, source_dir=template)
    assert len(result["results"]) == 2
    node_fake.assert_called_once()
    py_fake.assert_called_once()
    assert node_fake.call_args[0][1][0].ecosystem == "npm"
    assert py_fake.call_args[0][1][0].ecosystem == "PyPI"


def test_run_patch_unknown_eco_sniffs_manifests(tmp_path):
    repo = _seed_repo("sniff-r")
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
        row = Finding(
            repo_id=repo.id,
            package="mystery",
            installed_version="1",
            advisory_id="ADV-X",
            ecosystem=None,
            fixed_versions=["2"],
        )
        db.add(row)
        db.flush()
        db.add(Verdict(finding_id=row.id, run_id=run_id, reachable=True))
    py_only = tmp_path / "py"
    _git_repo_py(py_only, "mystery==1\n")
    node_only = tmp_path / "node"
    node_only.mkdir()
    (node_only / "package.json").write_text(json.dumps({"dependencies": {"mystery": "^1"}}))
    with (
        mock.patch.object(patch_mod, "patch_group", return_value={"outcome": "x"}),
        mock.patch.object(patch_mod, "patch_python_group", return_value={"outcome": "x"}),
    ):
        run_patch(repo.id, run_id, source_dir=py_only)
        patch_mod.patch_python_group.assert_called_once()  # requirements-owned → python
        run_patch(repo.id, run_id, source_dir=node_only)
        patch_mod.patch_group.assert_called_once()  # package.json-only → node
