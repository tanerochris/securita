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


def test_python_unpinned_note(tmp_path):
    assert python_unpinned_note(tmp_path, []) == ""
    (tmp_path / "pyproject.toml").write_text("x")
    (tmp_path / "setup.py").write_text("x")
    note = python_unpinned_note(tmp_path, [])
    assert "pyproject.toml" in note and "setup.py" in note
    assert python_unpinned_note(tmp_path, [tmp_path / "requirements.txt"]) == ""


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
