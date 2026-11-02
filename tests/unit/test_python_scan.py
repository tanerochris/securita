"""H4 Slice B: Python manifest discovery, dev contexts, merge, multi-eco scan."""

import json
from pathlib import Path
from unittest import mock

import pytest
from sqlalchemy import select

from security_agent.control import repos
from security_agent.db.models import Finding, RepoKind, RunStatus, ScanRun
from security_agent.db.session import session_scope
from security_agent.worker import scan as scan_mod
from security_agent.worker.scan import (
    ScanError,
    discover_python_manifests,
    merge_drafts,
    normalize,
    normalize_dist_name,
    python_context,
    python_dev_packages,
    python_unpinned_note,
    requirement_name,
    run_scan,
)

OSV_PY = {
    "results": [
        {
            "source": {"path": "requirements.txt", "type": "lockfile"},
            "packages": [
                {
                    "package": {
                        "name": "insecure-pkg",
                        "version": "1.0.0",
                        "ecosystem": "PyPI",
                    },
                    "vulnerabilities": [
                        {
                            "id": "GHSA-py-1",
                            "aliases": ["CVE-2026-9001"],
                            "severity": [{"type": "CVSS_V3", "score": 8.1}],
                            "references": [{"url": "https://example.com/p"}],
                            "affected": [
                                {
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [{"introduced": "0"}, {"fixed": "1.0.1"}],
                                        }
                                    ]
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    ]
}

OSV_NODE = {
    "results": [
        {
            "packages": [
                {
                    "package": {"name": "left-pad", "version": "1.0.0", "ecosystem": "npm"},
                    "vulnerabilities": [{"id": "CVE-2026-0001"}],
                }
            ]
        }
    ]
}


def test_normalize_dist_name():
    assert normalize_dist_name("Foo_Bar.baz") == "foo-bar-baz"
    assert normalize_dist_name("requests") == "requests"


def test_requirement_name():
    assert requirement_name("pkg==1.0") == "pkg"
    assert requirement_name("Pkg_Name[x]==1.0 ; python_version>'3'  # c") == "pkg-name"
    assert requirement_name("bare-pkg") == "bare-pkg"
    assert requirement_name("pkg>=1.0") == "pkg"
    assert requirement_name("") is None
    assert requirement_name("# comment") is None
    assert requirement_name("-r other.txt") is None
    assert requirement_name("-e .[x]") is None
    assert requirement_name("--index-url https://x") is None
    assert requirement_name("pkg @ https://example.com/pkg.tar.gz") is None


def test_discover_python_manifests_order_and_bounds(tmp_path):
    (tmp_path / "requirements.txt").write_text("a==1\n")
    (tmp_path / "requirements-dev.txt").write_text("b==1\n")
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "base.txt").write_text("c==1\n")
    (tmp_path / "poetry.lock").write_text("x")
    (tmp_path / "venv").mkdir()
    (tmp_path / "venv" / "requirements.txt").write_text("nope==1\n")
    files, truncated = discover_python_manifests(tmp_path)
    assert [f.name for f in files] == [
        "requirements.txt",
        "requirements-dev.txt",
        "base.txt",
        "poetry.lock",
    ]
    assert truncated is False


def test_discover_excludes_escaping_symlink(tmp_path):
    outside = tmp_path.parent / "outside-req.txt"
    outside.write_text("evil==1\n")
    link = tmp_path / "requirements-evil.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    (tmp_path / "requirements.txt").write_text("a==1\n")
    files, _ = discover_python_manifests(tmp_path)
    assert [f.name for f in files] == ["requirements.txt"]


def test_discover_truncates(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_mod, "MAX_PYTHON_MANIFESTS", 3)
    (tmp_path / "requirements.txt").write_text("a==1\n")
    for i in range(5):
        (tmp_path / f"requirements-{i}.txt").write_text("a==1\n")
    files, truncated = discover_python_manifests(tmp_path)
    assert truncated is True and len(files) == 3


def test_discover_follows_includes_and_constraints(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r deps/base.txt\n-c constraints.txt\n")
    (tmp_path / "deps").mkdir()
    (tmp_path / "deps" / "base.txt").write_text("a==1\n")
    (tmp_path / "constraints.txt").write_text("b==1\n")
    files, truncated = discover_python_manifests(tmp_path)
    names = [f.relative_to(tmp_path).as_posix() for f in files]
    assert names == ["requirements.txt", "constraints.txt", "deps/base.txt"]
    assert truncated is False


def test_discover_include_depth_and_escape_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_mod, "_MAX_MANIFEST_INCLUDE_DEPTH", 1)
    (tmp_path / "requirements.txt").write_text("-r a.txt\n")
    (tmp_path / "a.txt").write_text("-r b.txt\n")
    (tmp_path / "b.txt").write_text("c==1\n")
    files, _ = discover_python_manifests(tmp_path)
    names = sorted(f.name for f in files)
    assert names == ["a.txt", "requirements.txt"]  # b.txt past depth
    (tmp_path / "requirements.txt").write_text("-r ../outside.txt\n")
    (tmp_path.parent / "outside.txt").write_text("evil==1\n")
    files, _ = discover_python_manifests(tmp_path)
    assert [f.name for f in files] == ["requirements.txt"]


def test_discover_include_cycle_terminates(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r more.txt\n")
    (tmp_path / "more.txt").write_text("-r requirements.txt\nx==1\n")
    files, _ = discover_python_manifests(tmp_path)
    assert sorted(f.name for f in files) == ["more.txt", "requirements.txt"]


def test_discover_python_manifests_finds_nested_locks(tmp_path):
    (tmp_path / "requirements.txt").write_text("a==1\n")
    svc = tmp_path / "svc"
    svc.mkdir()
    (svc / "requirements.txt").write_text("b==1\n")
    (svc / "poetry.lock").write_text("x")
    (tmp_path / "venv").mkdir()
    (tmp_path / "venv" / "requirements.txt").write_text("nope==1\n")
    files, truncated = discover_python_manifests(tmp_path)
    rels = [f.relative_to(tmp_path).as_posix() for f in files]
    assert rels == ["requirements.txt", "svc/poetry.lock", "svc/requirements.txt"]
    assert truncated is False


def test_python_unpinned_note_names_nested_markers(tmp_path):
    svc = tmp_path / "svc"
    svc.mkdir()
    (svc / "pyproject.toml").write_text("x")
    note = python_unpinned_note(tmp_path, [])
    assert "svc/pyproject.toml" in note


def test_python_unpinned_note(tmp_path):
    assert python_unpinned_note(tmp_path, []) == ""
    (tmp_path / "pyproject.toml").write_text("x")
    (tmp_path / "setup.py").write_text("x")
    note = python_unpinned_note(tmp_path, [])
    assert "pyproject.toml" in note and "setup.py" in note
    assert python_unpinned_note(tmp_path, [tmp_path / "requirements.txt"]) == ""


def test_python_generation_plan_detection(tmp_path):
    plan = scan_mod._python_generation_plan
    want = scan_mod._PythonGenPlan
    poetry = tmp_path / "pyproject.toml"
    poetry.write_text(
        '[tool.poetry]\nname="c"\n[tool.poetry.dependencies]\npython="^3.12"\nflask="^3"\n'
    )
    assert plan(poetry) == want("poetry", ["lock", "--no-interaction"], "poetry.lock")
    other = tmp_path / "pdm.toml"
    other.write_text('[project]\nname="p"\n[tool.pdm]\n')
    # Only known manifest names are planned, whatever the content.
    assert plan(other) is None
    (tmp_path / "sub").mkdir()
    pep621 = tmp_path / "sub" / "pyproject.toml"
    pep621.write_text('[project]\nname="a"\ndependencies=["flask>=3"]\n')
    assert plan(pep621) == want("uv", ["lock"], "uv.lock")
    pep621.write_text('[project]\nname="a"\n[tool.pdm]\n')
    assert plan(pep621) == want("pdm", ["lock"], "pdm.lock")
    pipfile = tmp_path / "Pipfile"
    pipfile.write_text('[packages]\nflask="*"\n')
    assert plan(pipfile) == want("pipenv", ["lock"], "Pipfile.lock")
    pep621.write_text("[tool.ruff]\nline-length=100\n")
    assert plan(pep621) is None  # tool-only config: nothing to resolve
    pep621.write_text("not = [toml\n")
    assert plan(pep621) is None
    assert plan(tmp_path / "missing.toml") is None
    req_in = tmp_path / "req.in"
    req_in.write_text("flask==3.0\n")
    assert plan(req_in) is None  # only requirements.in is compiled
    req_in = tmp_path / "requirements.in"
    req_in.write_text("# just a comment\n\n")
    assert plan(req_in) is None  # empty input: nothing to resolve
    req_in.write_text("flask==3.0\n")
    assert plan(req_in) == want(
        "uv", ["pip", "compile", "requirements.in", "-o", "requirements.txt"], "requirements.txt"
    )
    req_in.unlink()  # setup.py extraction must not see a declared .in
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        'from setuptools import setup\nsetup(name="a", install_requires=["flask>=3"])\n'
    )
    assert plan(setup_py) == want(
        "uv",
        ["pip", "compile", "requirements.in", "-o", "requirements.txt"],
        "requirements.txt",
        write_first=("requirements.in", "flask>=3\n"),
    )
    setup_py.write_text(
        "import x\nREQUIRES = ['a==1', 'b==2']\nsetup(name='q', install_requires=REQUIRES)\n"
    )
    assert plan(setup_py) is not None and plan(setup_py).write_first == (
        "requirements.in",
        "a==1\nb==2\n",
    )
    setup_py.write_text("setup(name='q', install_requires=get_reqs())\n")
    assert plan(setup_py) is None  # dynamic requirements: refuse to guess
    (tmp_path / "requirements.in").write_text("flask==3.0\n")
    setup_py.write_text('setup(name="a", install_requires=["flask>=3"])\n')
    assert plan(setup_py) is None  # declared .in wins; never clobbered
    (tmp_path / "requirements.in").unlink()
    setup_cfg = tmp_path / "setup.cfg"
    setup_cfg.write_text("[options]\ninstall_requires =\n  flask>=3\n  gunicorn\n")
    assert plan(setup_cfg) is not None and plan(setup_cfg).write_first == (
        "requirements.in",
        "flask>=3\ngunicorn\n",
    )
    setup_cfg.write_text("not an ini file at all [[[\n")
    assert plan(setup_cfg) is None


def test_ensure_python_lockfiles_generates_per_manager(tmp_path):
    r1 = tmp_path / "r1"
    r1.mkdir()
    (r1 / "pyproject.toml").write_text('[project]\nname="a"\ndependencies=["flask>=3"]\n')
    r2 = tmp_path / "r2"
    r2.mkdir()
    (r2 / "Pipfile").write_text('[packages]\nflask="*"\n')
    r3 = tmp_path / "r3"
    r3.mkdir()
    (r3 / "pyproject.toml").write_text('[tool.poetry]\nname="c"\n')
    lock_for = {"uv": "uv.lock", "pipenv": "Pipfile.lock", "poetry": "poetry.lock"}
    calls = []

    def fake(name, args, **kwargs):
        calls.append((name, list(args), kwargs.get("cwd")))
        assert kwargs["timeout"] == scan_mod.LOCKFILE_TIMEOUT_SECONDS
        assert kwargs["allow_network"] is True
        Path(kwargs["cwd"], lock_for[name]).write_text("# generated\n")
        return ""

    with mock.patch.object(scan_mod, "run_allowlisted", side_effect=fake):
        gen1, notes1 = scan_mod.ensure_python_lockfiles(r1, [])
        gen2, _ = scan_mod.ensure_python_lockfiles(r2, [])
        gen3, _ = scan_mod.ensure_python_lockfiles(r3, [])
    assert [g.name for g in gen1] == ["uv.lock"]
    assert [g.name for g in gen2] == ["Pipfile.lock"]
    assert [g.name for g in gen3] == ["poetry.lock"]
    by_cwd = {cwd: (name, args) for name, args, cwd in calls}
    assert by_cwd[str(r1)] == ("uv", ["lock"])
    assert by_cwd[str(r2)] == ("pipenv", ["lock"])
    assert by_cwd[str(r3)] == ("poetry", ["lock", "--no-interaction"])
    assert notes1 == ["python: generated 1 lockfile(s) in-sandbox"]


def test_ensure_python_lockfiles_skips_covered_and_members(tmp_path):
    root = tmp_path / "owned"
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname="a"\ndependencies=["flask>=3"]\n')
    member = root / "svc"
    member.mkdir()
    (member / "pyproject.toml").write_text('[project]\nname="b"\ndependencies=["flask>=3"]\n')
    calls = []

    def fake(name, args, **kwargs):
        calls.append(kwargs.get("cwd"))
        Path(kwargs["cwd"], "uv.lock").write_text("# generated\n")
        return ""

    with mock.patch.object(scan_mod, "run_allowlisted", side_effect=fake):
        generated, notes = scan_mod.ensure_python_lockfiles(root, [])
    assert [g.relative_to(root).as_posix() for g in generated] == ["uv.lock"]
    assert calls == [str(root)]  # member resolves from the parent lock
    assert any("1 nested manifest(s) under another project skipped" in n for n in notes)
    covered = tmp_path / "covered"
    covered.mkdir()
    (covered / "pyproject.toml").write_text('[project]\nname="c"\ndependencies=["flask>=3"]\n')
    (covered / "requirements.txt").write_text("flask==3.0\n")

    def fail(name, args, **kwargs):
        raise AssertionError("covered dirs must not generate")

    with mock.patch.object(scan_mod, "run_allowlisted", side_effect=fail):
        assert scan_mod.ensure_python_lockfiles(covered, []) == ([], [])
        assert scan_mod.ensure_python_lockfiles(root, [root] * 20) == ([], [])


def test_ensure_python_lockfiles_failure_named(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="a"\ndependencies=["flask>=3"]\n')

    def boom(name, args, **kwargs):
        raise RuntimeError("resolver exploded")

    with mock.patch.object(scan_mod, "run_allowlisted", side_effect=boom):
        generated, notes = scan_mod.ensure_python_lockfiles(tmp_path, [])
    assert generated == []
    assert len(notes) == 1
    assert "failed for 1 manifest(s) (pyproject.toml)" in notes[0]
    assert "resolver exploded" in notes[0]

    def silent(name, args, **kwargs):
        return ""  # tool "succeeded" but wrote no lockfile

    with mock.patch.object(scan_mod, "run_allowlisted", side_effect=silent):
        generated, notes = scan_mod.ensure_python_lockfiles(tmp_path, [])
    assert generated == []
    assert "produced no uv.lock" in notes[0]


def test_ensure_python_lockfiles_compiles_requirements_in(tmp_path):
    (tmp_path / "requirements.in").write_text("insecure-pkg==1.0.0\n")
    calls = []

    def fake(name, args, **kwargs):
        calls.append((name, list(args), kwargs.get("cwd")))
        assert kwargs["timeout"] == scan_mod.LOCKFILE_TIMEOUT_SECONDS
        assert kwargs["allow_network"] is True
        (tmp_path / "requirements.txt").write_text("insecure-pkg==1.0.0\n")
        return ""

    with mock.patch.object(scan_mod, "run_allowlisted", side_effect=fake):
        generated, notes = scan_mod.ensure_python_lockfiles(tmp_path, [])
    assert [g.name for g in generated] == ["requirements.txt"]
    assert calls == [
        ("uv", ["pip", "compile", "requirements.in", "-o", "requirements.txt"], str(tmp_path))
    ]
    assert notes == ["python: compiled 1 requirements file(s) in-sandbox"]


def test_ensure_python_lockfiles_extracts_setup_py(tmp_path):
    (tmp_path / "setup.py").write_text(
        'from setuptools import setup\nsetup(name="a", install_requires=["flask>=3"])\n'
    )

    def fake(name, args, **kwargs):
        assert (tmp_path / "requirements.in").read_text() == "flask>=3\n"
        (tmp_path / "requirements.txt").write_text("flask==3.0\n")
        return ""

    with mock.patch.object(scan_mod, "run_allowlisted", side_effect=fake):
        generated, notes = scan_mod.ensure_python_lockfiles(tmp_path, [])
    assert [g.name for g in generated] == ["requirements.txt"]
    assert notes == ["python: compiled 1 requirements file(s) in-sandbox"]


def test_ensure_python_lockfiles_compile_failure_named(tmp_path):
    (tmp_path / "requirements.in").write_text("flask==3.0\n")

    def boom(name, args, **kwargs):
        raise RuntimeError("index unreachable")

    with mock.patch.object(scan_mod, "run_allowlisted", side_effect=boom):
        generated, notes = scan_mod.ensure_python_lockfiles(tmp_path, [])
    assert generated == []
    assert len(notes) == 1
    assert "requirements compile failed for 1 manifest(s) (requirements.in)" in notes[0]
    assert "index unreachable" in notes[0]


def test_python_generation_pending(tmp_path):
    pending = scan_mod.python_generation_pending
    assert pending(tmp_path) is False
    (tmp_path / "pyproject.toml").write_text('[project]\nname="a"\ndependencies=["x"]\n')
    assert pending(tmp_path) is True
    (tmp_path / "requirements.txt").write_text("x==1\n")
    assert pending(tmp_path) is False  # covered dirs generate nothing
    (tmp_path / "requirements.txt").unlink()
    (tmp_path / "pyproject.toml").write_text("[tool.ruff]\n")
    (tmp_path / "setup.py").write_text("setup(name='q', install_requires=get_reqs())\n")
    assert pending(tmp_path) is False  # tool-only + dynamic: no candidates


def test_run_scan_python_pyproject_generates_and_scans(tmp_path):
    repo = repos.connect_repo("pygen", RepoKind.GIT, url="https://example.com/pygen.git")
    run_id = _run_id(repo.id)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="a"\ndependencies=["insecure-pkg>=1"]\n'
    )

    def fake_tools(name, args, **kwargs):
        assert name == "uv"
        (tmp_path / "uv.lock").write_text("# uv.lock\n")
        return ""

    with (
        mock.patch.object(scan_mod, "run_allowlisted", side_effect=fake_tools),
        mock.patch.object(scan_mod, "scan_lockfile", return_value=OSV_PY),
        mock.patch.object(scan_mod, "kev_exploited_ids", return_value=set()),
    ):
        result = run_scan(repo.id, run_id, source_dir=tmp_path)
    assert result["status"] == "done" and result["created"] == 1
    with session_scope() as db:
        notes = db.get(ScanRun, run_id).notes or ""
        assert "python: generated 1 lockfile(s) in-sandbox" in notes
        assert "python: scanned 1 manifest(s)" in notes


def test_run_scan_python_requirements_in_compiles_and_scans(tmp_path):
    repo = repos.connect_repo("pyin", RepoKind.GIT, url="https://example.com/pyin.git")
    run_id = _run_id(repo.id)
    (tmp_path / "requirements.in").write_text("insecure-pkg==1.0.0\n")

    def fake_tools(name, args, **kwargs):
        assert (name, list(args)) == (
            "uv",
            ["pip", "compile", "requirements.in", "-o", "requirements.txt"],
        )
        (tmp_path / "requirements.txt").write_text("insecure-pkg==1.0.0\n")
        return ""

    with (
        mock.patch.object(scan_mod, "run_allowlisted", side_effect=fake_tools),
        mock.patch.object(scan_mod, "scan_lockfile", return_value=OSV_PY),
        mock.patch.object(scan_mod, "kev_exploited_ids", return_value=set()),
    ):
        result = run_scan(repo.id, run_id, source_dir=tmp_path)
    assert result["status"] == "done" and result["created"] == 1
    with session_scope() as db:
        notes = db.get(ScanRun, run_id).notes or ""
        assert "python: compiled 1 requirements file(s) in-sandbox" in notes
        assert "python: scanned 1 manifest(s)" in notes


def test_python_dev_packages_requirements(tmp_path):
    prod = tmp_path / "requirements.txt"
    prod.write_text("flask==3.0\n")
    dev = tmp_path / "requirements-dev.txt"
    dev.write_text("pytest==8.0\n")
    assert python_dev_packages([prod, dev]) == {"pytest"}
    nested = tmp_path / "requirements"
    nested.mkdir()
    dev2 = nested / "dev.txt"
    dev2.write_text("tox==4\n")
    prod2 = nested / "prod.txt"
    prod2.write_text("gunicorn==1\n")
    assert python_dev_packages([dev2, prod2]) == {"tox"}


def test_python_dev_packages_locks(tmp_path):
    pipfile = tmp_path / "Pipfile.lock"
    pipfile.write_text(json.dumps({"default": {"flask": {}}, "develop": {"PyTest": {}}}))
    poetry = tmp_path / "poetry.lock"
    poetry.write_text(
        '[[package]]\nname = "requests"\n'
        '[[package]]\nname = "black"\ncategory = "dev"\n'
        '[[package]]\nname = "ruff"\ngroups = ["dev"]\n'
    )
    assert python_dev_packages([pipfile, poetry]) == {"pytest", "black", "ruff"}


def test_python_dev_packages_pdm_uv(tmp_path):
    pdm = tmp_path / "pdm.lock"
    pdm.write_text(
        '[[package]]\nname = "flask"\ngroups = ["default"]\n'
        '[[package]]\nname = "pytest"\ngroups = ["dev"]\n'
        '[[package]]\nname = "shared"\ngroups = ["default", "dev"]\n'
    )
    uv = tmp_path / "uv.lock"
    uv.write_text(
        '[[package]]\nname = "root"\n'
        'dependencies = ["flask>=3"]\n'
        'dev-dependencies = ["pytest>=8", { name = "tox" }]\n'
    )
    assert python_dev_packages([pdm, uv]) == {"pytest", "tox"}


def test_python_dev_packages_bad_input_ignored(tmp_path, monkeypatch):
    bad = tmp_path / "Pipfile.lock"
    bad.write_text("not json")
    bad2 = tmp_path / "poetry.lock"
    bad2.write_text("not = [toml")
    assert python_dev_packages([bad, bad2]) == set()
    monkeypatch.setattr(scan_mod, "MAX_LOCK_PARSE_BYTES", 4)
    big = tmp_path / "requirements-dev.txt"
    big.write_text("pytest==8.0\n")
    assert python_dev_packages([big]) == set()


def test_python_context_flat(tmp_path):
    dev = tmp_path / "requirements-dev.txt"
    dev.write_text("pytest==8.0\n")
    ctx = python_context([dev])
    assert ctx("pytest", "8.0") == (["pytest"], True)
    assert ctx("flask", "3.0") == (["flask"], False)


def test_normalize_records_ecosystem(tmp_path):
    lock = tmp_path / "requirements.txt"
    lock.write_text("insecure-pkg==1.0.0\n")
    (draft,) = normalize(OSV_PY, lock, set(), context=python_context([lock]))
    assert draft["ecosystem"] == "PyPI"
    assert draft["advisory_id"] == "CVE-2026-9001"
    assert draft["fixed_versions"] == ["1.0.1"]
    assert draft["dep_path"] == ["insecure-pkg"]
    bare = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "p", "version": "1"},
                        "vulnerabilities": [{"id": "X"}],
                    }
                ]
            }
        ]
    }
    (draft2,) = normalize(bare, lock, set())
    assert draft2["ecosystem"] is None  # legacy scanner output stays NULL


def test_normalize_validates_osv_tokens(tmp_path):
    lock = tmp_path / "requirements.txt"
    lock.write_text("ok-pkg==1.0\n")
    osv = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "ok-pkg", "version": "1.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "CVE-1",
                                "affected": [
                                    {
                                        "ranges": [
                                            {
                                                "events": [
                                                    {"fixed": "1.0\n evil==9"},
                                                    {"fixed": "2.0"},
                                                ]
                                            }
                                        ]
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "package": {"name": "bad\nname", "version": "1", "ecosystem": "PyPI"},
                        "vulnerabilities": [{"id": "CVE-2"}],
                    },
                ]
            }
        ]
    }
    (draft,) = normalize(osv, lock, set(), context=python_context([lock]))
    assert draft["package"] == "ok-pkg"
    assert draft["fixed_versions"] == ["2.0"]  # newline-injection fixed dropped


def test_merge_drafts_collapse_conflict_and_cross_eco():
    base = {"package": "p", "advisory_id": "A", "severity_score": 5.0, "ecosystem": "PyPI"}
    same = dict(base)
    merged, skipped = merge_drafts([[base, same]])
    assert merged == [base] and skipped == 0
    conflict = dict(base, severity_score=9.0)
    with pytest.raises(ScanError, match="severity conflict"):
        merge_drafts([[base], [conflict]])
    other_eco = dict(base, ecosystem="npm")
    merged, skipped = merge_drafts([[base], [other_eco]])
    assert merged == [base] and skipped == 1  # first file wins, counted


def _run_id(repo_id: int) -> int:
    with session_scope() as db:
        return db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo_id))


def test_run_scan_python_only(tmp_path):
    repo = repos.connect_repo("py-only", RepoKind.GIT, url="https://example.com/py.git")
    run_id = _run_id(repo.id)
    (tmp_path / "requirements.txt").write_text("insecure-pkg==1.0.0\n")
    with (
        mock.patch.object(scan_mod, "scan_lockfile", return_value=OSV_PY),
        mock.patch.object(scan_mod, "kev_exploited_ids", return_value=set()),
    ):
        result = run_scan(repo.id, run_id, source_dir=tmp_path)
    assert result["status"] == "done" and result["created"] == 1
    with session_scope() as db:
        row = db.scalar(select(Finding).where(Finding.repo_id == repo.id))
        assert row is not None
        assert row.ecosystem == "PyPI" and row.advisory_id == "CVE-2026-9001"
        assert row.scope.value == "prod"
        notes = db.get(ScanRun, run_id).notes or ""
        assert "python: scanned 1 manifest(s)" in notes
        assert "node:" in notes and "skipped" in notes


def test_run_scan_mixed_ecosystems(tmp_path):
    repo = repos.connect_repo("mixed", RepoKind.GIT, url="https://example.com/m.git")
    run_id = _run_id(repo.id)
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {}}))
    (tmp_path / "requirements.txt").write_text("insecure-pkg==1.0.0\n")

    def fake(lockfile):
        return OSV_NODE if Path(lockfile).name == "package-lock.json" else OSV_PY

    with (
        mock.patch.object(scan_mod, "scan_lockfile", side_effect=fake),
        mock.patch.object(scan_mod, "kev_exploited_ids", return_value=set()),
    ):
        result = run_scan(repo.id, run_id, source_dir=tmp_path)
    assert result["status"] == "done" and result["created"] == 2
    with session_scope() as db:
        rows = list(db.scalars(select(Finding).where(Finding.repo_id == repo.id)))
        assert {(r.package, r.ecosystem) for r in rows} == {
            ("left-pad", "npm"),
            ("insecure-pkg", "PyPI"),
        }


def test_run_scan_no_manifests_done_empty(tmp_path):
    repo = repos.connect_repo("empty", RepoKind.GIT, url="https://example.com/e.git")
    run_id = _run_id(repo.id)
    with mock.patch.object(scan_mod, "kev_exploited_ids", return_value=set()):
        result = run_scan(repo.id, run_id, source_dir=tmp_path)
    assert result == {"status": "done", "created": 0, "updated": 0, "finding_ids": []}
    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        assert run is not None and run.status == RunStatus.DONE
        assert "nothing to scan" in (run.notes or "")
