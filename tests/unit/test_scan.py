"""Slice C: scan normalization, clone, KEV join, run bookkeeping."""

import json
from pathlib import Path
from unittest import mock

import pytest
from sqlalchemy import select

from security_agent.control import repos
from security_agent.db.models import Finding, RepoKind, RunStatus, ScanRun
from security_agent.db.session import session_scope
from security_agent.sandbox import tools
from security_agent.worker import build_graph
from security_agent.worker import scan as scan_mod
from security_agent.worker.scan import (
    ScanError,
    canonical_id,
    clone_repo,
    ensure_lockfile,
    kev_exploited_ids,
    load_lockfile_packages,
    lockfile_context,
    normalize,
    persist_findings,
    run_scan,
)

OSV_FIXTURE = {
    "results": [
        {
            "packages": [
                {
                    "package": {"name": "left-pad", "version": "1.0.0"},
                    "vulnerabilities": [
                        {
                            "id": "GHSA-aaaa-bbbb-cccc",
                            "aliases": ["CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"],
                            "severity": [
                                {"type": "CVSS_V3", "score": 7.5},
                                {"type": "CVSS_V2", "score": 4.0},
                            ],
                            "references": [{"url": "https://example.com/advisory"}],
                            "affected": [
                                {
                                    "ranges": [
                                        {
                                            "type": "SEMVER",
                                            "events": [
                                                {"introduced": "0"},
                                                {"fixed": "1.0.1"},
                                            ],
                                        }
                                    ]
                                }
                            ],
                        }
                    ],
                },
                {
                    "package": {"name": "nested-dep", "version": "2.0.0"},
                    "vulnerabilities": [{"id": "OSV-2026-1"}],
                },
            ]
        }
    ]
}

LOCK_FIXTURE = {
    "packages": {
        "": {"name": "demo"},
        "node_modules/left-pad": {"version": "1.0.0"},
        "node_modules/top/node_modules/nested-dep": {"version": "2.0.0", "dev": True},
    }
}


def _lockfile(tmp_path: Path) -> Path:
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps(LOCK_FIXTURE))
    return lock


def test_normalize_canonical_and_enrichment(tmp_path):
    drafts = normalize(OSV_FIXTURE, _lockfile(tmp_path), {"CVE-2026-0001"})
    by_pkg = {d["package"]: d for d in drafts}
    direct = by_pkg["left-pad"]
    assert direct["advisory_id"] == "CVE-2026-0001"
    assert direct["kev_exploited"] is True
    assert direct["severity_score"] == 7.5
    assert direct["severity_source"] == "CVSS_V3"
    assert direct["fixed_versions"] == ["1.0.1"]
    assert direct["dep_path"] == ["left-pad"]
    assert direct["scope"].value == "prod"
    assert "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc" in direct["citations"]
    transitive = by_pkg["nested-dep"]
    assert transitive["advisory_id"] == "OSV-2026-1"
    assert transitive["severity_score"] is None
    assert transitive["kev_exploited"] is False
    assert transitive["dep_path"] == ["top", "nested-dep"]
    assert transitive["scope"].value == "dev"


def test_canonical_prefers_cve_then_ghsa():
    assert canonical_id("OSV-1", ["GHSA-x", "CVE-2026-9"]) == "CVE-2026-9"
    assert canonical_id("OSV-1", ["GHSA-x"]) == "GHSA-x"
    assert canonical_id("OSV-1", []) == "OSV-1"


def test_normalize_conflict_fails_loud_and_dup_collapses(tmp_path):
    lock = _lockfile(tmp_path)
    assert len(normalize(OSV_FIXTURE, lock, set())) == 2
    doubled = {"results": OSV_FIXTURE["results"] + OSV_FIXTURE["results"]}
    assert len(normalize(doubled, lock, set())) == 2  # identical dupes collapse
    conflict = json.loads(json.dumps(OSV_FIXTURE))
    conflict["results"][0]["packages"][0]["vulnerabilities"][0]["severity"] = [
        {"type": "CVSS_V3", "score": 9.9}
    ]
    mixed = {"results": OSV_FIXTURE["results"] + conflict["results"]}
    with pytest.raises(ScanError, match="severity conflict"):
        normalize(mixed, lock, set())


def test_lockfile_context_fallbacks(tmp_path):
    assert load_lockfile_packages(tmp_path / "missing.json") == {}
    v1 = tmp_path / "v1.json"
    v1.write_text(json.dumps({"dependencies": {"p": {}}}))
    assert load_lockfile_packages(v1) == {}
    assert lockfile_context({}, "p", "1") == (["p"], False)
    assert lockfile_context(LOCK_FIXTURE["packages"], "nested-dep", "2.0.0") == (
        ["top", "nested-dep"],
        True,
    )


def test_lockfile_packages_oversize_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_mod, "MAX_LOCK_PARSE_BYTES", 10)
    lock = _lockfile(tmp_path)
    assert load_lockfile_packages(lock) == {}
    assert lockfile_context(load_lockfile_packages(lock), "left-pad", "1.0.0") == (
        ["left-pad"],
        False,
    )


def test_indexed_lockfile_context_matches_direct():
    from security_agent.worker.scan import indexed_lockfile_context, lockfile_package_index

    packages = LOCK_FIXTURE["packages"]
    index = lockfile_package_index(packages)
    for package, version in [("nested-dep", "2.0.0"), ("left-pad", "1.0.0"), ("ghost", "")]:
        assert indexed_lockfile_context(index, package, version) == lockfile_context(
            packages, package, version
        )


def test_clone_argv_shape_and_redaction(tmp_path):
    repo = repos.connect_repo(
        "clone-r", RepoKind.GIT, url="https://example.com/c.git", token="tok-123"
    )
    dest = tmp_path / "dest"
    (dest / ".git").mkdir(parents=True)  # mocked clone: checkout visible on the worker
    with mock.patch.object(scan_mod, "run_allowlisted") as fake:
        clone_repo(repo, dest)
    assert fake.call_count == 2
    (name, args), kwargs = fake.call_args_list[0]
    assert name == "git"
    assert args[:5] == ["clone", "--depth", "1", "--no-single-branch", "--"]
    assert "tok-123" in args[5] and kwargs["redact"] == ("tok-123",)
    (_name2, args2), _kwargs2 = fake.call_args_list[1]
    assert args2 == ["remote", "set-url", "origin", "https://example.com/c.git"]


def test_clone_failure_redacts_token(tmp_path):
    repo = repos.connect_repo(
        "clone-fail", RepoKind.GIT, url="https://example.com/f.git", token="tok-SECRET"
    )
    with mock.patch.object(
        scan_mod,
        "run_allowlisted",
        side_effect=RuntimeError("fatal: unable to access 'https://tok-SECRET@example.com/f.git'"),
    ):
        with pytest.raises(RuntimeError) as exc_info:
            clone_repo(repo, tmp_path / "dest")
    assert "tok-SECRET" not in str(exc_info.value)
    assert "***" in str(exc_info.value)


def test_scan_lockfile_uses_scanner_output_cap(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text("{}")
    with mock.patch.object(scan_mod, "run_allowlisted", return_value='{"results": []}') as fake:
        assert scan_mod.scan_lockfile(lock) == {"results": []}
    (_name, _args), kwargs = fake.call_args
    assert kwargs["success_codes"] == (0, 1)
    assert kwargs["max_output"] == tools.MAX_SCANNER_OUTPUT_CHARS


def test_tool_audit_redacts_secrets():
    completed = mock.Mock(returncode=0, stdout="", stderr="")
    with mock.patch.object(tools.subprocess, "run", return_value=completed):
        tools.run_allowlisted("git", ["clone", "https://tok-SECRET@h/r"], redact=("tok-SECRET",))
    lines = [r["line"] for r in tools.audit.query(action_class="tool")]
    assert lines and "tok-SECRET" not in lines[-1] and "***" in lines[-1]


def test_clone_local_repo_for_real(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    tools.run_allowlisted("git", ["init", str(src)])
    (src / "package.json").write_text('{"name":"demo"}')
    tools.run_allowlisted("git", ["-C", str(src), "add", "."])
    tools.run_allowlisted(
        "git",
        ["-C", str(src), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "x"],
    )
    repo = repos.connect_repo("local-clone", RepoKind.LOCAL, local_path=str(src))
    dest = tmp_path / "dest"
    clone_repo(repo, dest)
    assert (dest / "package.json").exists()


def test_ensure_lockfile_generates_and_notes(tmp_path):
    workdir = tmp_path / "gen"
    workdir.mkdir()

    def _fake(name, args, **kwargs):
        assert name == "npm"
        assert "--package-lock-only" in args and "--ignore-scripts" in args
        assert kwargs["timeout"] == scan_mod.LOCKFILE_TIMEOUT_SECONDS
        (workdir / "package-lock.json").write_text("{}")
        return ""

    with mock.patch.object(scan_mod, "run_allowlisted", side_effect=_fake):
        lock, generated = ensure_lockfile(workdir)
    assert generated is True and lock == workdir / "package-lock.json"
    with mock.patch.object(scan_mod, "run_allowlisted") as fake:
        assert ensure_lockfile(workdir) == (lock, False)
        fake.assert_not_called()


def test_kev_cache_and_failopen():
    scan_mod._kev_cache = None
    resp = mock.Mock()
    resp.text = "cveID,vendorProject\nCVE-2026-0001,Acme\n,blank-row\n"
    with mock.patch.object(scan_mod.httpx, "get", return_value=resp) as fake_get:
        assert kev_exploited_ids() == {"CVE-2026-0001"}
        assert kev_exploited_ids() == {"CVE-2026-0001"}
        assert fake_get.call_count == 1
        assert fake_get.call_args[0][0] == scan_mod._KEV_URL
        assert fake_get.call_args[1]["timeout"] == scan_mod._KEV_TIMEOUT_SECONDS
    scan_mod._kev_cache = None
    with mock.patch.object(scan_mod.httpx, "get", side_effect=TimeoutError("down")):
        assert kev_exploited_ids() == set()


def test_normalize_uses_group_severity(tmp_path):
    osv = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "axios", "version": "0.18.0"},
                        "groups": [
                            {
                                "ids": ["GHSA-xxx"],
                                "aliases": ["CVE-2020-28168"],
                                "max_severity": "5.4",
                            }
                        ],
                        "vulnerabilities": [
                            {
                                "id": "GHSA-xxx",
                                "aliases": ["CVE-2020-28168"],
                                "severity": [
                                    {
                                        "type": "CVSS_V3",
                                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ]
    }
    (draft,) = normalize(osv, _lockfile(tmp_path), set())
    assert draft["severity_score"] == 5.4
    assert draft["severity_source"] == "osv-scanner-group"


def test_persist_findings_merges_on_conflict():
    repo = repos.connect_repo("merge-r", RepoKind.GIT, url="https://example.com/m.git")
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    draft = {"package": "p", "installed_version": "1", "advisory_id": "CVE-1"}
    created, updated, ids = persist_findings(repo.id, run_id, [draft])
    assert (created, updated) == (1, 0)
    created, updated, ids2 = persist_findings(repo.id, run_id, [draft])
    assert (created, updated) == (0, 1)
    assert ids2 == ids


def test_run_scan_end_to_end_with_fixture(tmp_path):
    repo = repos.connect_repo("e2e-r", RepoKind.GIT, url="https://example.com/e.git")
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    _lockfile(tmp_path)
    with (
        mock.patch.object(scan_mod, "scan_lockfile", return_value=OSV_FIXTURE),
        mock.patch.object(scan_mod, "kev_exploited_ids", return_value={"CVE-2026-0001"}),
    ):
        result = run_scan(repo.id, run_id, source_dir=tmp_path)
    assert result["status"] == "done" and result["created"] == 2
    with session_scope() as db:
        rows = list(db.scalars(select(Finding).where(Finding.repo_id == repo.id)))
        assert {r.advisory_id for r in rows} == {"CVE-2026-0001", "OSV-2026-1"}
        run = db.get(ScanRun, run_id)
        assert run.status == RunStatus.DONE and "2 new" in (run.notes or "")
        assert "scan: KEV catalog ready (1 exploited ids)" in (run.notes or "")
        assert "node: package-lock.json: 2 finding(s)" in (run.notes or "")
        assert "scan: saving 2 finding(s)..." in (run.notes or "")
    # Second run updates rather than duplicating.
    with session_scope() as db:
        run2 = ScanRun(repo_id=repo.id, trigger="manual")
        db.add(run2)
        db.flush()
        run2_id = run2.id
    with (
        mock.patch.object(scan_mod, "scan_lockfile", return_value=OSV_FIXTURE),
        mock.patch.object(scan_mod, "kev_exploited_ids", return_value=set()),
    ):
        result2 = run_scan(repo.id, run2_id, source_dir=tmp_path)
    assert result2 == {
        "status": "done",
        "created": 0,
        "updated": 2,
        "finding_ids": result2["finding_ids"],
    }


def test_clone_repo_fails_loud_when_checkout_invisible_on_worker(tmp_path):
    """Volume split: git "succeeded" container-side, worker sees an empty dir."""
    repo = repos.connect_repo(
        "clone-split", RepoKind.GIT, url="https://example.com/s.git", token="tok-1"
    )
    dest = tmp_path / "dest"
    dest.mkdir()  # mkdtemp left this behind; the clone landed elsewhere
    with mock.patch.object(scan_mod, "run_allowlisted", return_value=""):
        with pytest.raises(ScanError, match="not shared"):
            clone_repo(repo, dest)


def test_run_scan_clone_split_fails_instead_of_empty_scan():
    """Run #8 regression: invisible checkout must FAIL loud, never "nothing to scan"."""
    repo = repos.connect_repo("split-r", RepoKind.GIT, url="https://example.com/s.git")
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    with mock.patch.object(scan_mod, "run_allowlisted", return_value=""):
        result = run_scan(repo.id, run_id)
    assert result["status"] == "failed"
    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        assert run.status == RunStatus.FAILED
        assert "not shared" in (run.notes or "")
        assert "nothing to scan" not in (run.notes or "")


def test_run_scan_failure_recorded(tmp_path):
    repo = repos.connect_repo("fail-r", RepoKind.GIT, url="https://example.com/f.git")
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    _lockfile(tmp_path)
    with mock.patch.object(scan_mod, "scan_lockfile", side_effect=ScanError("boom")):
        result = run_scan(repo.id, run_id, source_dir=tmp_path)
    assert result["status"] == "failed"
    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        assert run.status == RunStatus.FAILED and "boom" in (run.notes or "")


def test_run_scan_prod_refuses():
    settings = mock.Mock(is_prod=True, sandbox_backend="docker")
    with (
        mock.patch("security_agent.config.get_settings", return_value=settings),
        mock.patch("security_agent.sandbox.shutil.which", return_value=None),
    ):
        with pytest.raises(PermissionError, match="Docker sandbox"):
            run_scan(1, 1)


def test_discover_node_manifests_lock_preference(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "1"}}')
    (tmp_path / "yarn.lock").write_text('a@^1:\n  version "1.0.0"\n')
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
    targets, truncated = scan_mod.discover_node_manifests(tmp_path)
    assert truncated is False
    assert len(targets) == 1
    assert targets[0].lockfile.name == "yarn.lock"
    assert targets[0].lock_kind == "yarn"
    (tmp_path / "package-lock.json").write_text('{"packages": {}}')
    targets, _ = scan_mod.discover_node_manifests(tmp_path)
    assert targets[0].lockfile.name == "package-lock.json"
    assert targets[0].lock_kind == "package-lock"


def test_discover_node_manifests_nested_and_stray(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "1"}}')
    (tmp_path / "yarn.lock").write_text("# yarn lockfile v1\n")
    svc = tmp_path / "svc-a"
    svc.mkdir()
    (svc / "package.json").write_text('{"dependencies": {"a": "1"}}')
    (svc / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
    bare = tmp_path / "svc-b"
    bare.mkdir()
    (bare / "package.json").write_text('{"dependencies": {"b": "1"}}')
    ignored = tmp_path / "node_modules" / "evil"
    ignored.mkdir(parents=True)
    (ignored / "package.json").write_text('{"dependencies": {"evil": "1"}}')
    targets, truncated = scan_mod.discover_node_manifests(tmp_path)
    assert truncated is False
    by_rel = {t.manifest.relative_to(tmp_path).as_posix(): t for t in targets}
    assert sorted(by_rel) == ["package.json", "svc-a/package.json", "svc-b/package.json"]
    assert by_rel["package.json"].lock_kind == "yarn"
    assert by_rel["svc-a/package.json"].lock_kind == "pnpm"
    assert by_rel["svc-b/package.json"].lockfile is None


def test_discover_node_manifests_stray_lock_scanned(tmp_path):
    (tmp_path / "yarn.lock").write_text("# yarn lockfile v1\n")
    targets, truncated = scan_mod.discover_node_manifests(tmp_path)
    assert truncated is False
    assert len(targets) == 1
    assert targets[0].manifest is None
    assert targets[0].lockfile.name == "yarn.lock"


def test_discover_node_manifests_caps(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_mod, "MAX_NODE_MANIFESTS", 2)
    for i in range(4):
        sub = tmp_path / f"svc-{i}"
        sub.mkdir()
        (sub / "package.json").write_text("{}")
        (sub / "yarn.lock").write_text("# yarn lockfile v1\n")
    targets, truncated = scan_mod.discover_node_manifests(tmp_path)
    assert truncated is True and len(targets) == 2


def test_npm_context_marks_dev_from_package_json(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"prod-a": "1"}, "devDependencies": {"jest": "29"}})
    )
    lock = tmp_path / "yarn.lock"
    lock.write_text("# yarn lockfile v1\n")
    osv = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "prod-a", "version": "1", "ecosystem": "npm"},
                        "vulnerabilities": [{"id": "CVE-P"}],
                    },
                    {
                        "package": {"name": "jest", "version": "29", "ecosystem": "npm"},
                        "vulnerabilities": [{"id": "CVE-D"}],
                    },
                ]
            }
        ]
    }
    ctx = scan_mod.npm_context(tmp_path / "package.json")
    by_pkg = {d["package"]: d for d in normalize(osv, lock, set(), context=ctx)}
    assert by_pkg["prod-a"]["scope"].value == "prod"
    assert by_pkg["jest"]["scope"].value == "dev"
    assert by_pkg["jest"]["dep_path"] == ["jest"]
    assert scan_mod.npm_dev_packages(None) == set()
    assert scan_mod.npm_dev_packages(tmp_path / "missing.json") == set()


def test_run_scan_node_yarn_and_nested_pnpm(tmp_path):
    repo = repos.connect_repo("yarn-r", RepoKind.GIT, url="https://example.com/y.git")
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"root-pkg": "1"}}))
    (tmp_path / "yarn.lock").write_text("# yarn lockfile v1\n")
    svc = tmp_path / "svc"
    svc.mkdir()
    (svc / "package.json").write_text(json.dumps({"dependencies": {"svc-pkg": "1"}}))
    (svc / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")

    def fake(lockfile):
        pkg = "root-pkg" if Path(lockfile).name == "yarn.lock" else "svc-pkg"
        return {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": pkg, "version": "1", "ecosystem": "npm"},
                            "vulnerabilities": [{"id": f"CVE-{pkg}"}],
                        }
                    ]
                }
            ]
        }

    with (
        mock.patch.object(scan_mod, "scan_lockfile", side_effect=fake),
        mock.patch.object(scan_mod, "kev_exploited_ids", return_value=set()),
    ):
        result = run_scan(repo.id, run_id, source_dir=tmp_path)
    assert result["status"] == "done" and result["created"] == 2
    with session_scope() as db:
        rows = list(db.scalars(select(Finding).where(Finding.repo_id == repo.id)))
        assert {(r.package, r.ecosystem) for r in rows} == {
            ("root-pkg", "npm"),
            ("svc-pkg", "npm"),
        }
        notes = db.get(ScanRun, run_id).notes or ""
        assert "node: scanned 2 lockfile(s)" in notes


def test_run_scan_nested_no_lock_skipped_without_npm(tmp_path):
    repo = repos.connect_repo("nolock-r", RepoKind.GIT, url="https://example.com/n.git")
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": "1"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {}}))
    bare = tmp_path / "bare"
    bare.mkdir()
    (bare / "package.json").write_text(json.dumps({"dependencies": {"b": "1"}}))
    real = scan_mod.run_allowlisted

    def fake_tools(name, args, **kwargs):
        assert name != "npm", "nested no-lock manifests must not trigger generation"
        return real(name, args, **kwargs)

    with (
        mock.patch.object(scan_mod, "scan_lockfile", return_value={"results": []}),
        mock.patch.object(scan_mod, "kev_exploited_ids", return_value=set()),
        mock.patch.object(scan_mod, "run_allowlisted", side_effect=fake_tools),
    ):
        result = run_scan(repo.id, run_id, source_dir=tmp_path)
    assert result["status"] == "done"
    with session_scope() as db:
        notes = db.get(ScanRun, run_id).notes or ""
        assert "without lockfile skipped (bare/package.json)" in notes


def test_graph_scan_node_runs_real_scan():
    with (
        mock.patch("security_agent.worker.news.poll_news", return_value={}),
        mock.patch(
            "security_agent.worker.news_intel.process_news",
            return_value={"classified": 0, "major": 0, "minted": 0, "linked": 0},
        ),
        mock.patch.object(
            scan_mod, "run_scan", return_value={"status": "done", "finding_ids": [7]}
        ) as fake,
        mock.patch(
            "security_agent.worker.reachability.run_reachability",
            return_value={"status": "done", "verdict_ids": []},
        ),
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
    assert result["findings"] == [{"id": 7}]
    assert "sandbox_scan" in result["done"]
