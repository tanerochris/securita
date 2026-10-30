"""H4 Slice C: AST parser, distro matching, ecosystem routing."""

import shutil
import tempfile
from pathlib import Path
from unittest import mock

import pytest
from sqlalchemy import select

from security_agent.control import repos
from security_agent.db.models import Finding, FindingStatus, RepoKind, ScanRun, Verdict
from security_agent.db.session import session_scope
from security_agent.worker.reachability import (
    analyze_python,
    first_party_python_files,
    first_party_tops,
    package_of_python,
    parse_python_imports,
    run_reachability,
    verdict_for_package_python,
)


def _write(repo: Path, rel: str, content: str) -> None:
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def _seed(repo_id: int, package: str, ecosystem: str | None) -> int:
    with session_scope() as db:
        row = Finding(
            repo_id=repo_id,
            package=package,
            installed_version="1.0.0",
            advisory_id=f"ADV-{package}-{ecosystem or 'none'}",
            ecosystem=ecosystem,
        )
        db.add(row)
        db.flush()
        return row.id


def _run_id(repo_id: int) -> int:
    with session_scope() as db:
        return db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo_id))


def test_parser_kinds_and_lines():
    src = """import os
import requests
import myapp.lib
from flask import Flask, render_template
from . import sibling
from .mod import thing
from ..pkg import other
from x import *
mod = importlib.import_module("dyn_pkg")
mod2 = importlib.import_module(name)
val = __import__("dunder_pkg")
val2 = __import__(other)
bad = importlib.import_module("not a module!")
"""
    by_line: dict[int, list[str]] = {}
    for site in parse_python_imports(src, "a.py"):
        by_line.setdefault(site.line, []).append(site.specifier)
    assert by_line[1] == ["os"]
    assert by_line[2] == ["requests"]
    assert by_line[3] == ["myapp", "myapp.lib"]
    assert by_line[4] == ["flask", "flask.Flask", "flask.render_template"]
    assert by_line[5] == [".", ".sibling"]
    assert by_line[6] == [".mod", ".mod.thing"]
    assert by_line[7] == ["..pkg", "..pkg.other"]
    assert by_line[8] == ["x"]
    assert by_line[9] == ["dyn_pkg"]
    assert by_line[11] == ["dunder_pkg"]
    unresolved = [s for s in parse_python_imports(src, "a.py") if s.dynamic_unresolved]
    # non-literal dynamics + the invalid module path fail open
    assert sorted(s.line for s in unresolved) == [10, 12, 13]


def test_parser_aliased_dynamic_imports():
    src = """import importlib as il
mod = il.import_module("aliased_pkg")
bad = il.import_module(name)
"""
    by_line: dict[int, list[str]] = {}
    for site in parse_python_imports(src, "a.py"):
        by_line.setdefault(site.line, []).append(site.specifier)
    assert by_line[2] == ["aliased_pkg"]
    unresolved = [s for s in parse_python_imports(src, "a.py") if s.dynamic_unresolved]
    assert [s.line for s in unresolved] == [3]
    src2 = 'from importlib import import_module as im\nm = im("from_aliased")\n'
    specs2 = [s.specifier for s in parse_python_imports(src2, "b.py") if s.line == 2]
    assert specs2 == ["from_aliased"]
    src3 = 'from builtins import __import__ as bi\nm = bi("bi_pkg")\n'
    specs3 = [s.specifier for s in parse_python_imports(src3, "c.py") if s.line == 2]
    assert specs3 == ["bi_pkg"]


def test_package_of_python_mapping():
    tops = {"myapp"}
    assert package_of_python("requests.models", tops) == "requests"
    assert package_of_python("PIL.Image", tops) == "pillow"
    assert package_of_python("Foo_Bar.baz", tops) == "foo-bar"
    assert package_of_python("yaml", tops) == "pyyaml"
    assert package_of_python("sklearn.ensemble", tops) == "scikit-learn"
    assert package_of_python("os.path", tops) is None
    assert package_of_python("myapp.lib", tops) is None
    assert package_of_python(".mod", tops) is None
    assert package_of_python("", tops) is None
    assert package_of_python("email.mime", {"email"}) is None  # shadowing wins


def test_package_of_python_dotted_candidates():
    assert (
        package_of_python("google.cloud.storage", set(), {"google-cloud-storage"})
        == "google-cloud-storage"
    )
    assert package_of_python("google.cloud.storage", set(), {"other"}) is None
    assert package_of_python("PIL.Image", set(), {"pillow"}) == "pillow"  # alias wins
    assert package_of_python("os.path", set(), {"os-path"}) is None  # stdlib first
    assert package_of_python("myapp.lib", {"myapp"}, {"myapp-lib"}) is None


def test_namespace_distro_reachable(tmp_path):
    _write(tmp_path, "app.py", "from google.cloud import storage\n")
    graph = analyze_python(tmp_path)
    ok, evidence, reason = verdict_for_package_python(graph, "google-cloud-storage")
    assert ok and reason is None and evidence["chain"]
    assert verdict_for_package_python(graph, "azure-storage-blob")[1:] == ({}, "no-import-chain")


def test_first_party_tops(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "mod.py", "")
    _write(tmp_path, "__init__.py", "")
    _write(tmp_path, "src/other/__init__.py", "")
    _write(tmp_path, "ns/plain.py", "")
    assert first_party_tops(tmp_path) == {"pkg", "mod", "other"}


def test_importing_fixture_reachable_single_hop(tmp_path):
    _write(tmp_path, "app.py", "from insecure_pkg import connect\n")
    graph = analyze_python(tmp_path)
    ok, evidence, reason = verdict_for_package_python(graph, "insecure-pkg")
    assert ok and reason is None
    assert evidence["chain"] == [{"file": "app.py", "line": 1, "specifier": "insecure_pkg"}]


def test_non_importing_fixture_silent(tmp_path):
    _write(tmp_path, "app.py", "print('hi')\n")
    graph = analyze_python(tmp_path)
    ok, _evidence, reason = verdict_for_package_python(graph, "insecure-pkg")
    assert not ok and reason == "no-import-chain"


def test_alias_and_stdlib_and_first_party(tmp_path):
    _write(tmp_path, "myapp/__init__.py", "")
    _write(tmp_path, "app.py", "import os\nfrom PIL import Image\nfrom myapp import x\n")
    graph = analyze_python(tmp_path)
    assert verdict_for_package_python(graph, "Pillow")[0] is True
    assert verdict_for_package_python(graph, "os")[1:] == ({}, "no-import-chain")
    assert verdict_for_package_python(graph, "myapp")[1:] == ({}, "no-import-chain")


def test_test_only_import_counts_reachable(tmp_path):
    _write(tmp_path, "app.py", "print('hi')\n")
    _write(tmp_path, "tests/test_app.py", "import insecure_pkg\n")
    graph = analyze_python(tmp_path)
    ok, _evidence, reason = verdict_for_package_python(graph, "insecure-pkg")
    assert ok and reason is None


def test_encoding_cookie_and_bom_parsed(tmp_path):
    (tmp_path / "latin.py").write_bytes(b"# coding: latin-1\nimport insecure_pkg  # caf\xe9\n")
    (tmp_path / "bom.py").write_bytes(b"\xef\xbb\xbfimport other_pkg\n")
    graph = analyze_python(tmp_path)
    assert graph["fail_open_files"] == []
    assert verdict_for_package_python(graph, "insecure-pkg")[0] is True
    assert verdict_for_package_python(graph, "other-pkg")[0] is True


def test_graph_truncation_fails_open(tmp_path, monkeypatch):
    from security_agent.worker import reachability as reach

    _write(tmp_path, "a.py", "x = 1\n")
    _write(tmp_path, "b.py", "x = 1\n")
    monkeypatch.setattr(reach, "MAX_GRAPH_FILES", 1)
    graph = analyze_python(tmp_path)
    assert graph["truncated"] is True
    ok, evidence, _ = verdict_for_package_python(graph, "anything")
    assert ok and evidence["fail_open"] == "graph-truncated"


def test_dynamic_bare_fails_open(tmp_path):
    _write(tmp_path, "app.py", "import importlib\nm = importlib.import_module(name)\n")
    graph = analyze_python(tmp_path)
    ok, evidence, _ = verdict_for_package_python(graph, "anything")
    assert ok and evidence["fail_open"] == "dynamic-import"


def test_unparseable_and_oversize_fail_open(tmp_path, monkeypatch):
    from security_agent.worker import reachability as reach

    _write(tmp_path, "broken.py", "def broken(:\n")
    _write(tmp_path, "big.py", "x = 1\n")
    (tmp_path / "bin.py").write_bytes(b"\xff\xfe\x00invalid-utf8")
    monkeypatch.setattr(reach, "MAX_FILE_BYTES", 4)
    graph = analyze_python(tmp_path)
    assert sorted(graph["fail_open_files"]) == ["big.py", "bin.py", "broken.py"]
    ok, evidence, reason = verdict_for_package_python(graph, "anything-at-all")
    assert ok and reason is None and evidence["fail_open"] == "dynamic-import"


def test_recursion_error_fails_open(tmp_path, monkeypatch):
    _write(tmp_path, "app.py", "import x\n")
    with mock.patch("ast.parse", side_effect=RecursionError("deep")):
        graph = analyze_python(tmp_path)
    assert graph["fail_open_files"] == ["app.py"]


def test_walk_skips_venvs_caches_and_egginfo(tmp_path):
    _write(tmp_path, "app.py", "x = 1\n")
    _write(tmp_path, "src/lib.py", "x = 1\n")
    _write(tmp_path, ".venv/lib/x.py", "x = 1\n")
    _write(tmp_path, "proj.egg-info/x.py", "x = 1\n")
    _write(tmp_path, "node_modules/x.py", "x = 1\n")
    found = {
        p.relative_to(tmp_path.resolve()).as_posix() for p in first_party_python_files(tmp_path)
    }
    assert found == {"app.py", "src/lib.py"}


def test_escaping_symlink_skipped(tmp_path):
    outside_dir = Path(tempfile.mkdtemp(prefix="pyreach-escape-"))
    try:
        outside = outside_dir / "outside.py"
        outside.write_text("import evil\n")
        link = tmp_path / "link.py"
        try:
            link.symlink_to(outside)
        except OSError:
            pytest.skip("symlinks unavailable")
        _write(tmp_path, "app.py", "x = 1\n")
        graph = analyze_python(tmp_path)
        assert "link.py" not in graph["sites"]
        assert "app.py" in graph["sites"]
    finally:
        shutil.rmtree(outside_dir, ignore_errors=True)


def test_run_reachability_routes_by_ecosystem(tmp_path):
    repo = repos.connect_repo("py-route", RepoKind.GIT, url="https://example.com/r.git")
    run_id = _run_id(repo.id)
    fid_npm = _seed(repo.id, "npmpkg", "npm")
    fid_py = _seed(repo.id, "pypkg", "PyPI")
    fid_weird = _seed(repo.id, "bothpkg", "weird-eco")
    fid_none = _seed(repo.id, "npmpkg", None)
    _write(tmp_path, "main.js", "import x from 'npmpkg';\nimport y from 'bothpkg';\n")
    _write(tmp_path, "app.py", "import pypkg\n")
    result = run_reachability(repo.id, run_id, source_dir=tmp_path)
    assert result["status"] == "done"
    assert (result["reachable"], result["unreachable"]) == (4, 0)
    with session_scope() as db:
        for fid in (fid_npm, fid_py, fid_weird, fid_none):
            assert db.get(Finding, fid).status == FindingStatus.OPEN


def test_run_reachability_unknown_eco_silent_when_neither(tmp_path):
    repo = repos.connect_repo("py-route2", RepoKind.GIT, url="https://example.com/r2.git")
    run_id = _run_id(repo.id)
    fid = _seed(repo.id, "ghost", "weird-eco")
    _write(tmp_path, "app.py", "print(1)\n")
    result = run_reachability(repo.id, run_id, source_dir=tmp_path)
    assert result["unreachable"] == 1
    with session_scope() as db:
        row = db.get(Finding, fid)
        assert row is not None and row.status == FindingStatus.SILENT
        assert row.silent_reason == "no-import-chain"


def test_run_reachability_pypi_without_sources_silent(tmp_path):
    repo = repos.connect_repo("py-route3", RepoKind.GIT, url="https://example.com/r3.git")
    run_id = _run_id(repo.id)
    fid = _seed(repo.id, "pypkg", "PyPI")
    _write(tmp_path, "main.js", "console.log(1);\n")
    result = run_reachability(repo.id, run_id, source_dir=tmp_path)
    assert result["unreachable"] == 1
    with session_scope() as db:
        assert db.get(Finding, fid).status == FindingStatus.SILENT


def test_run_reachability_parks_and_reopens(tmp_path):
    repo = repos.connect_repo("py-flip", RepoKind.GIT, url="https://example.com/f.git")
    run_id = _run_id(repo.id)
    fid = _seed(repo.id, "leftpad", "PyPI")
    _write(tmp_path, "app.py", "print(1)\n")
    first = run_reachability(repo.id, run_id, source_dir=tmp_path)
    assert (first["reachable"], first["unreachable"]) == (0, 1)
    with session_scope() as db:
        assert db.get(Finding, fid).status == FindingStatus.SILENT
    _write(tmp_path, "app.py", "import leftpad\n")
    second = run_reachability(repo.id, run_id, source_dir=tmp_path)
    assert second["reachable"] == 1
    with session_scope() as db:
        row = db.get(Finding, fid)
        assert row.status == FindingStatus.OPEN and row.silent_reason is None
        assert db.scalar(select(Verdict).where(Verdict.finding_id == fid)) is not None
