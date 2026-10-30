"""Slice D: import parser, graph verdicts, reopen flips."""

import json
import shutil
import tempfile
from pathlib import Path
from unittest import mock

import pytest
from sqlalchemy import select

from security_agent.control import repos
from security_agent.db.models import (
    Finding,
    FindingStatus,
    RepoKind,
    ScanRun,
    Verdict,
)
from security_agent.db.session import session_scope
from security_agent.worker import build_graph
from security_agent.worker import reachability as reach_mod
from security_agent.worker.reachability import (
    analyze,
    package_of,
    parse_imports,
    run_reachability,
    verdict_for_package,
)


def _write(repo: Path, rel: str, content: str) -> None:
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def test_analyze_accepts_unresolved_tmpdir() -> None:
    """mkdtemp returns /var/... while resolved entries live under /private/var."""
    tmp = Path(tempfile.mkdtemp(prefix="reach-"))
    try:
        _write(tmp, "package.json", json.dumps({"main": "src/app.js"}))
        _write(tmp, "src/app.js", "import _ from 'lodash';\n")
        graph = analyze(tmp)
        assert graph["roots"] == {"src/app.js"}
        sites = graph["sites"]["src/app.js"]
        assert [s.specifier for s in sites] == ["lodash"]
        ok, _evidence, reason = verdict_for_package(graph, "lodash")
        assert ok and reason is None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _seed_finding(repo_id: int, package: str) -> int:
    with session_scope() as db:
        row = Finding(
            repo_id=repo_id,
            package=package,
            installed_version="1.0.0",
            advisory_id=f"ADV-{package}",
        )
        db.add(row)
        db.flush()
        return row.id


def _run_id(repo_id: int) -> int:
    with session_scope() as db:
        return db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo_id))


def test_parser_kinds_and_lines():
    src = """import pad from 'left-pad';
const x = require("@scope/pkg/sub");
const y = await import('dyn-pkg');
const z = await import(name);
const t = require(`./static`);
const u = import(`./loc/${lang}`);
"""
    sites = {s.specifier: s for s in parse_imports(src, "a.js")}
    assert sites["left-pad"].line == 1 and not sites["left-pad"].dynamic_unresolved
    assert sites["@scope/pkg/sub"].line == 2
    assert sites["dyn-pkg"].line == 3
    assert sites["./static"].line == 5 and not sites["./static"].dynamic_unresolved
    unresolved = [s for s in parse_imports(src, "a.js") if s.dynamic_unresolved]
    assert [(s.line) for s in unresolved] == [4]  # bare dynamic only


def test_package_of_mapping():
    assert package_of("left-pad") == "left-pad"
    assert package_of("@scope/pkg/sub") == "@scope/pkg"
    assert package_of("./rel") is None
    assert package_of("node:fs") is None


def test_importing_fixture_reachable_with_chain(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"main": "src/main.js"}))
    _write(tmp_path, "src/main.js", "import { b } from './lib';\n")
    _write(tmp_path, "src/lib.js", "import pad from 'left-pad';\n")
    graph = analyze(tmp_path)
    ok, evidence, reason = verdict_for_package(graph, "left-pad")
    assert ok and reason is None
    assert [h["file"] for h in evidence["chain"]] == ["src/main.js", "src/lib.js"]
    assert evidence["chain"][-1]["specifier"] == "left-pad"


def test_non_importing_fixture_silent(tmp_path):
    _write(tmp_path, "src/main.js", "console.log('hi');\n")
    graph = analyze(tmp_path)
    ok, _evidence, reason = verdict_for_package(graph, "left-pad")
    assert not ok and reason == "no-import-chain"


def test_entry_point_excluded_and_test_counts(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"main": "src/main.js"}))
    _write(tmp_path, "src/main.js", "console.log(1);\n")
    _write(tmp_path, "src/unused.js", "import pad from 'left-pad';\n")
    _write(tmp_path, "test/x.test.js", "import t from 'test-pkg';\n")
    graph = analyze(tmp_path)
    ok, evidence, reason = verdict_for_package(graph, "left-pad")
    assert not ok and reason == "entry-point-excluded"
    assert evidence["excluded_imports"] == [{"file": "src/unused.js", "line": 1}]
    ok_test, _, _ = verdict_for_package(graph, "test-pkg")
    assert ok_test  # test-only imports count as reachable (FR-3 D3)


def test_walk_prunes_skipped_dirs(tmp_path):
    from security_agent.worker.reachability import first_party_files

    _write(tmp_path, "src/app.js", "import _ from 'lodash';\n")
    _write(tmp_path, "node_modules/dep/index.js", "import _ from 'evil';\n")
    found = {p.relative_to(tmp_path.resolve()).as_posix() for p in first_party_files(tmp_path)}
    assert found == {"src/app.js"}


def test_oversize_and_undecodable_fail_open(tmp_path, monkeypatch):
    from security_agent.worker import reachability as reach

    _write(tmp_path, "src/big.js", "x = 1;\n")
    (tmp_path / "src" / "bin.js").write_bytes(b"\xff\xfe\x00invalid-utf8")
    monkeypatch.setattr(reach, "MAX_FILE_BYTES", 4)
    graph = analyze(tmp_path)
    assert sorted(graph["fail_open_files"]) == ["src/big.js", "src/bin.js"]
    ok, evidence, reason = verdict_for_package(graph, "anything-at-all")
    assert ok and reason is None and evidence["fail_open"] == "dynamic-import"


def test_escaping_symlink_skipped(tmp_path):
    outside_dir = Path(tempfile.mkdtemp(prefix="reach-escape-"))
    try:
        outside = outside_dir / "outside.js"
        outside.write_text("import _ from 'evil';\n")
        link = tmp_path / "src" / "link.js"
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            link.symlink_to(outside)
        except OSError:
            pytest.skip("symlinks unavailable")
        inner = tmp_path / "inner" / "real.js"
        inner.parent.mkdir(parents=True, exist_ok=True)
        inner.write_text("import _ from 'lodash';\n")
        link2 = tmp_path / "src" / "inner-link.js"
        try:
            link2.symlink_to(inner)
        except OSError:
            pytest.skip("symlinks unavailable")
        graph = analyze(tmp_path)
        assert "src/link.js" not in graph["sites"]
        assert "src/inner-link.js" in graph["sites"]
    finally:
        shutil.rmtree(outside_dir, ignore_errors=True)


def test_reachability_index_computed_once(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"main": "src/app.js"}))
    _write(tmp_path, "src/app.js", "import _ from 'lodash';\n")
    graph = analyze(tmp_path)
    verdict_for_package(graph, "lodash")
    first = graph["_reachability_index"]
    verdict_for_package(graph, "other")
    assert graph["_reachability_index"] is first


def test_dynamic_bare_fails_open(tmp_path):
    _write(tmp_path, "src/main.js", "const m = await import(name);\n")
    graph = analyze(tmp_path)
    ok, evidence, _ = verdict_for_package(graph, "anything")
    assert ok and evidence["fail_open"] == "dynamic-import"


def test_run_reachability_parks_and_reopens(tmp_path):
    repo = repos.connect_repo("reach-r", RepoKind.GIT, url="https://example.com/r.git")
    run_id = _run_id(repo.id)
    fid = _seed_finding(repo.id, "left-pad")
    _write(tmp_path, "src/main.js", "console.log(1);\n")
    first = run_reachability(repo.id, run_id, source_dir=tmp_path)
    assert first["status"] == "done"
    assert (first["reachable"], first["unreachable"]) == (0, 1)
    assert len(first["verdict_ids"]) == 1
    with session_scope() as db:
        assert db.get(Finding, fid).status == FindingStatus.SILENT
    _write(tmp_path, "src/main.js", "import pad from 'left-pad';\n")
    second = run_reachability(repo.id, run_id, source_dir=tmp_path)
    assert second["reachable"] == 1
    with session_scope() as db:
        row = db.get(Finding, fid)
        assert row.status == FindingStatus.OPEN and row.silent_reason is None
        assert db.scalar(select(Verdict).where(Verdict.finding_id == fid)) is not None


def test_run_reachability_skips_terminal_findings(tmp_path):
    repo = repos.connect_repo("term-r", RepoKind.GIT, url="https://example.com/t.git")
    run_id = _run_id(repo.id)
    fid = _seed_finding(repo.id, "closed-pkg")
    with session_scope() as db:
        db.get(Finding, fid).status = FindingStatus.CLOSED
    _write(tmp_path, "src/main.js", "import p from 'closed-pkg';\n")
    result = run_reachability(repo.id, run_id, source_dir=tmp_path)
    assert result["verdict_ids"] == []


def test_run_reachability_prod_refuses():
    settings = mock.Mock(is_prod=True, sandbox_backend="docker")
    with (
        mock.patch("security_agent.config.get_settings", return_value=settings),
        mock.patch("security_agent.sandbox.shutil.which", return_value=None),
    ):
        with pytest.raises(PermissionError, match="Docker sandbox"):
            run_reachability(1, 1)


def test_graph_reachability_node_runs_real_verdicts():
    with (
        mock.patch("security_agent.worker.news.poll_news", return_value={}),
        mock.patch(
            "security_agent.worker.news.run_matcher", return_value={"items": 0, "boosts": 0}
        ),
        mock.patch.object(
            reach_mod,
            "run_reachability",
            return_value={"status": "done", "verdict_ids": [3]},
        ) as fake,
        mock.patch("security_agent.worker.scan.run_scan", return_value={"finding_ids": []}),
        mock.patch(
            "security_agent.worker.patch.run_patch",
            return_value={"status": "done", "proposal_ids": []},
        ),
        mock.patch(
            "security_agent.worker.deliver.run_deliver",
            return_value={"status": "done", "proposal_ids": []},
        ),
        mock.patch(
            "security_agent.control.gates.run_merge",
            return_value={"status": "done", "merged": [], "skipped": []},
        ),
    ):
        result = build_graph().invoke({"repo_id": 1, "run_id": 2})
    fake.assert_called_once_with(1, 2)
    assert result["verdicts"] == [{"id": 3}]
