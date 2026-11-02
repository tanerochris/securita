"""DependencyCheck orchestration: table, reports, reuse, failures, D20 (D5/D14/D19)."""

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import delete, select

from security_agent.control import deps as deps_svc
from security_agent.control import repos as repo_svc
from security_agent.db.models import (
    DashboardNotification,
    Dependency,
    DependencyCheck,
    DependencyReport,
    DependencyStatus,
    Finding,
    FindingStatus,
    NotifyState,
    Proposal,
    ProposalStatus,
    RepoKind,
    Role,
    RunStatus,
    RunTrigger,
)
from security_agent.db.session import session_scope
from security_agent.worker import deps_check as dc
from security_agent.worker.deps_freshness import Freshness


def _repo():
    return repo_svc.connect_repo(
        f"depchk-{datetime.now(UTC).timestamp()}", RepoKind.LOCAL, local_path="/tmp/x"
    )


def _reset_deps_budget():
    with session_scope() as db:
        db.execute(
            delete(NotifyState).where(NotifyState.key.in_(["deps.token_cap", "deps.spend_cap"]))
        )


def _settle_checks(repo_id: int):
    with session_scope() as db:
        for row in db.scalars(
            select(DependencyCheck).where(DependencyCheck.repo_id == repo_id)
        ):
            row.status = RunStatus.DONE
            row.finished_at = datetime.now(UTC)


def _source(tmp_path: Path, *, sub: bool = False) -> Path:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"left-pad": "^1.3.0"}})
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"packages": {"": {}, "node_modules/left-pad": {"version": "1.3.0"}}})
    )
    (tmp_path / "index.js").write_text("const p = require('left-pad');\n")
    (tmp_path / "requirements.txt").write_text("django==4.2.0\n")
    if sub:
        nested = tmp_path / "apps" / "web"
        nested.mkdir(parents=True)
        (nested / "package.json").write_text(json.dumps({"dependencies": {"wibble": "1.0.0"}}))
    return tmp_path


def _npm(manifest_dir, specs, pm="npm"):
    out = {}
    for package, (installed, _spec) in specs.items():
        latest = {"left-pad": "2.0.0", "wibble": "1.0.1"}.get(package, installed)
        cls = {"2.0.0": "major", "1.0.1": "patch"}.get(latest or "")
        out[package] = Freshness(
            package=package, installed=installed, wanted=None, latest=latest,
            update_class=cls,
        )
    return out


def _pip(specs):
    out = {}
    for package, (installed, _spec) in specs.items():
        out[package] = Freshness(
            package=package, installed=installed, wanted=None, latest="5.0.0",
            update_class="major",
        )
    return out


def _usage(workdir, ecosystem, package):
    return ["index.js:1"] if package == "left-pad" else []


class _Model:
    def __init__(self, content="model summary", calls=None):
        self.content = content
        self.calls = calls if calls is not None else []

    def invoke(self, prompt):
        self.calls.append(prompt)
        return SimpleNamespace(content=self.content, usage_metadata={})


def _rows(repo_id: int):
    with session_scope() as db:
        rows = list(db.scalars(select(Dependency).where(Dependency.repo_id == repo_id)))
        for r in rows:
            db.expunge(r)
        return rows


def _reports(repo_id: int):
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(DependencyReport)
                .where(DependencyReport.repo_id == repo_id)
                .order_by(DependencyReport.id)
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


def _notifs(repo_id: int):
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(DashboardNotification).where(DashboardNotification.repo_id == repo_id)
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


def _run(repo_id, source, **kwargs):
    _settle_checks(repo_id)
    check = dc.enqueue_dependency_check(repo_id, RunTrigger.MANUAL)
    kwargs.setdefault("npm_fetch", _npm)
    kwargs.setdefault("pip_fetch", _pip)
    kwargs.setdefault("usage_fetch", _usage)
    return check, dc.run_dependency_check(repo_id, check.id, source_dir=source, **kwargs)


def test_check_builds_table_and_combined_report(tmp_path):
    repo = _repo()
    calls: list = []
    check, out = _run(repo.id, _source(tmp_path), summary_model=_Model(calls=calls))
    assert out["status"] == "done" and out["report_id"]
    assert len(calls) == 1  # one model call for the combined report
    rows = {r.package: r for r in _rows(repo.id)}
    assert rows["left-pad"].installed_version == "1.3.0"  # lockfile-resolved (D3)
    assert rows["left-pad"].latest_version == "2.0.0"
    assert rows["left-pad"].update_class == "major"
    assert rows["left-pad"].status == DependencyStatus.AWAITING_DECISION
    assert rows["django"].status == DependencyStatus.AWAITING_DECISION
    reports = _reports(repo.id)
    assert len(reports) == 1 and reports[0].model_backed is True
    assert len(reports[0].sections) == 2
    section = next(s for s in reports[0].sections if s["package"] == "left-pad")
    assert section["usage_sites"] == ["index.js:1"]
    assert "UNDETERMINED" in section["changelog"]  # named unknown, never invented
    notifs = _notifs(repo.id)
    assert len(notifs) == 1 and notifs[0].kind == "deps-report"  # majors notify (D14)
    with session_scope() as db:
        notes = db.get(DependencyCheck, check.id).notes or ""
        assert "deps: found " in notes and " manifest(s)" in notes
        assert "report: assessing 2 update(s)..." in notes
        assert "report: left-pad: 1 usage site(s)" in notes
        assert "report: writing summary..." in notes
        assert "combined report #" in notes


def test_unchanged_set_reuses_report_without_model_call(tmp_path):
    repo = _repo()
    source = _source(tmp_path)
    _, first = _run(repo.id, source, summary_model=_Model(content="one"))
    calls: list = []
    _, second = _run(repo.id, source, summary_model=_Model(calls=calls))
    assert second["status"] == "done"
    assert second["report_id"] is None  # no new report ...
    assert second["reused_report_id"] == first["report_id"]  # ... previous reused
    assert calls == []  # ... with no model call (D14)
    assert len(_reports(repo.id)) == 1


def test_superseded_version_replaces_report(tmp_path):
    repo = _repo()
    source = _source(tmp_path)
    _run(repo.id, source, summary_model=_Model(content="one"))

    def _npm_newer(manifest_dir, specs, pm="npm"):
        out = _npm(manifest_dir, specs, pm=pm)
        out["left-pad"].latest = "3.0.0"
        return out

    _, second = _run(repo.id, source, npm_fetch=_npm_newer, summary_model=_Model("two"))
    assert second["report_id"]
    reports = _reports(repo.id)
    assert [r.status for r in reports] == ["superseded", "pending"]
    assert reports[1].summary == "two"


def test_declined_version_stays_quiet_until_newer(tmp_path):
    from security_agent.app import accounts as accounts_svc

    owner = accounts_svc.create_user(
        f"dec-{datetime.now(UTC).timestamp()}@example.com", None, Role.OWNER
    )
    repo = _repo()
    source = _source(tmp_path)
    _run(repo.id, source, summary_model=_Model(content="one"))
    rows = {r.package: r for r in _rows(repo.id)}
    deps_svc.decline_version(rows["left-pad"].id, owner)
    deps_svc.decline_version(rows["django"].id, owner)
    calls: list = []
    _, second = _run(repo.id, source, summary_model=_Model(calls=calls))
    assert second["report_id"] is None and calls == []  # declined set: quiet
    rows = {r.package: r for r in _rows(repo.id)}
    assert rows["left-pad"].status == DependencyStatus.DECLINED

    def _npm_newer(manifest_dir, specs, pm="npm"):
        out = _npm(manifest_dir, specs, pm=pm)
        out["left-pad"].latest = "3.0.0"
        return out

    _, third = _run(repo.id, source, npm_fetch=_npm_newer, summary_model=_Model("new"))
    assert third["report_id"]  # newer version re-proposes with a fresh section
    rows = {r.package: r for r in _rows(repo.id)}
    assert rows["left-pad"].status == DependencyStatus.AWAITING_DECISION
    assert rows["django"].status == DependencyStatus.DECLINED  # untouched version quiet


def test_partial_failure_ships_named_gap(tmp_path):
    repo = _repo()
    source = _source(tmp_path, sub=True)

    def _npm_flaky(manifest_dir, specs, pm="npm"):
        if "apps" in str(manifest_dir):
            raise RuntimeError("yarn exploded")
        return _npm(manifest_dir, specs, pm=pm)

    _, out = _run(repo.id, source, npm_fetch=_npm_flaky, summary_model=_Model("s"))
    assert out["status"] == "done"  # partial results ship (D19)
    rows = {r.package: r for r in _rows(repo.id)}
    assert rows["wibble"].status == DependencyStatus.CHECK_FAILED
    assert rows["wibble"].stale is True
    assert "yarn exploded" in (rows["wibble"].check_error or "")
    assert rows["left-pad"].status == DependencyStatus.AWAITING_DECISION
    with session_scope() as db:
        stored = db.get(DependencyCheck, out["report_id"] and _reports(repo.id)[-1].check_id)
        assert stored is not None
        assert any(m.get("status") == "check_failed" for m in stored.manifests or [])


def test_all_failed_marks_run_failed_and_notifies(tmp_path):
    repo = _repo()
    source = _source(tmp_path)

    def _boom(*args, **kwargs):
        raise RuntimeError("registry down")

    _, out = _run(repo.id, source, npm_fetch=_boom, pip_fetch=_boom)
    assert out["status"] == "failed"
    notifs = _notifs(repo.id)
    assert len(notifs) == 1 and notifs[0].kind == "deps-failure"


def test_finding_collision_defers_and_excludes(tmp_path):
    repo = _repo()
    with session_scope() as db:
        finding = Finding(
            repo_id=repo.id, package="left-pad", installed_version="1.3.0",
            advisory_id="CVE-X", status=FindingStatus.PROPOSED, fixed_versions=["1.3.1"],
        )
        db.add(finding)
        db.flush()
        db.add(
            Proposal(
                repo_id=repo.id, finding_ids=[finding.id], package_from="1.3.0",
                package_to="1.3.1", verification_result="ok", status=ProposalStatus.OPEN,
            )
        )
    _, out = _run(repo.id, _source(tmp_path), summary_model=_Model("s"))
    assert out["status"] == "done"
    rows = {r.package: r for r in _rows(repo.id)}
    assert rows["left-pad"].status == DependencyStatus.COVERED_BY_FINDING
    assert rows["left-pad"].security is True
    reports = _reports(repo.id)
    assert len(reports) == 1
    assert [s["package"] for s in reports[0].sections] == ["django"]  # excluded (D20)


def test_security_tag_links_fix_shipped_by_target(tmp_path):
    repo = _repo()
    with session_scope() as db:
        db.add(
            Finding(
                repo_id=repo.id, package="left-pad", installed_version="1.3.0",
                advisory_id="CVE-X", status=FindingStatus.OPEN, fixed_versions=["1.3.1"],
            )
        )
    _run(repo.id, _source(tmp_path), summary_model=_Model("s"))
    rows = {r.package: r for r in _rows(repo.id)}
    assert rows["left-pad"].security is True and rows["left-pad"].finding_id is not None
    assert rows["django"].security is False


def test_minor_patch_only_is_quiet_but_reported(tmp_path):
    repo = _repo()

    def _npm_patch(manifest_dir, specs, pm="npm"):
        return {
            p: Freshness(package=p, installed=i, wanted=None, latest="1.3.1",
                          update_class="patch")
            for p, (i, _s) in specs.items()
        }

    def _pip_none(specs):
        return {
            p: Freshness(package=p, installed=i, wanted=None, latest=i, update_class=None)
            for p, (i, _s) in specs.items()
        }

    _, out = _run(repo.id, _source(tmp_path), npm_fetch=_npm_patch, pip_fetch=_pip_none,
                  summary_model=_Model("s"))
    assert out["report_id"]  # tracked and reported ...
    assert _notifs(repo.id) == []  # ... but quiet (D14)


def test_budget_park_marks_rows_and_notifies(tmp_path):
    from security_agent.app import accounts as accounts_svc

    owner = accounts_svc.create_user(
        f"cap-{datetime.now(UTC).timestamp()}@example.com", None, Role.OWNER
    )
    _reset_deps_budget()
    deps_svc.set_deps_spend_cap(0.000001, owner)
    try:
        repo = _repo()
        _, out = _run(repo.id, _source(tmp_path), summary_model=_Model("s" * 500))
        assert out["status"] == "done" and out["report_id"] is None  # table updated (D23)
        rows = {r.package: r for r in _rows(repo.id)}
        assert rows["left-pad"].status == DependencyStatus.REPORT_PENDING_CAP
        assert rows["left-pad"].latest_version == "2.0.0"
        notifs = _notifs(repo.id)
        assert len(notifs) == 1 and "parked" in notifs[0].title
    finally:
        _reset_deps_budget()


def test_model_outage_fails_report_only(tmp_path):
    repo = _repo()

    class _Outage:
        def invoke(self, prompt):
            raise RuntimeError("connection reset")

    _, out = _run(repo.id, _source(tmp_path), summary_model=_Outage())
    assert out["status"] == "done" and out["report_id"] is None
    rows = {r.package: r for r in _rows(repo.id)}
    assert rows["left-pad"].status == DependencyStatus.UPDATE_AVAILABLE  # retry next check
    assert rows["left-pad"].latest_version == "2.0.0"  # table still updated


def test_enqueue_single_flight_and_due():
    repo = _repo()
    _settle_checks(repo.id)
    first = dc.enqueue_dependency_check(repo.id, RunTrigger.MANUAL)
    second = dc.enqueue_dependency_check(repo.id, RunTrigger.MANUAL)
    assert first.id == second.id  # in-flight returned, not duplicated
    _settle_checks(repo.id)
    from security_agent.app import accounts as accounts_svc

    owner = accounts_svc.create_user(
        f"due-{datetime.now(UTC).timestamp()}@example.com", None, Role.OWNER
    )
    deps_svc.set_repo_dep_interval(repo.id, 0, owner)  # never automatically
    try:
        assert repo.id not in [r.id for r in dc.dep_due_repos()]
    finally:
        deps_svc.set_repo_dep_interval(repo.id, None, owner)


def test_failed_check_preserves_silences(tmp_path):
    """A tool failure marks values stale; it never erases user state (D21)."""
    from security_agent.app import accounts as accounts_svc

    owner = accounts_svc.create_user(
        f"sil-{datetime.now(UTC).timestamp()}@example.com", None, Role.OWNER
    )
    repo = _repo()
    source = _source(tmp_path)
    _run(repo.id, source, summary_model=_Model("s"))
    rows = {r.package: r for r in _rows(repo.id)}
    deps_svc.decline_version(rows["left-pad"].id, owner)
    deps_svc.ignore_package(rows["django"].id, owner)

    def _boom(*args, **kwargs):
        raise RuntimeError("registry down")

    _run(repo.id, source, npm_fetch=_boom, pip_fetch=_boom)
    rows = {r.package: r for r in _rows(repo.id)}
    assert rows["left-pad"].status == DependencyStatus.DECLINED  # silence kept
    assert rows["django"].status == DependencyStatus.IGNORED
    assert rows["left-pad"].stale is True and rows["django"].stale is True
    # Next good check still honours the declined version (no re-proposal).
    calls: list = []
    _, out = _run(repo.id, source, summary_model=_Model(calls=calls))
    assert out["report_id"] is None and calls == []
    rows = {r.package: r for r in _rows(repo.id)}
    assert rows["left-pad"].status == DependencyStatus.DECLINED


def test_pending_cap_rows_recover_into_next_report(tmp_path):
    """Raised budget + new report + decision patches parked rows (D23)."""
    from security_agent.app import accounts as accounts_svc

    owner = accounts_svc.create_user(
        f"rec-{datetime.now(UTC).timestamp()}@example.com", None, Role.OWNER
    )
    _reset_deps_budget()
    deps_svc.set_deps_spend_cap(0.000001, owner)
    repo = _repo()
    source = _source(tmp_path)
    try:
        _run(repo.id, source, summary_model=_Model("s" * 500))
    finally:
        _reset_deps_budget()
    rows = {r.package: r for r in _rows(repo.id)}
    assert rows["left-pad"].status == DependencyStatus.REPORT_PENDING_CAP
    _, out = _run(repo.id, source, summary_model=_Model("fresh"))
    assert out["report_id"]
    rows = {r.package: r for r in _rows(repo.id)}
    assert rows["left-pad"].status == DependencyStatus.AWAITING_DECISION
    report = _reports(repo.id)[-1]
    deps_svc.decide_report(
        report.id, owner, ["npm|package.json|left-pad", "pip|requirements.txt|django"]
    )
    rows = {r.package: r for r in _rows(repo.id)}
    assert rows["left-pad"].status == DependencyStatus.PROPOSED


def test_touch_and_fenced_finish():
    repo = _repo()
    _settle_checks(repo.id)
    check = dc.enqueue_dependency_check(repo.id, RunTrigger.MANUAL)
    owned = dc.claim_dep_checks("worker-a", limit=500)  # suite leaves stale claims
    assert any(c.id == check.id for c in owned)
    assert dc.touch_dep_claim(check.id, "worker-a") is True
    assert dc.touch_dep_claim(check.id, "worker-b") is False
    dc.fail_dependency_check(check.id, "boom", worker_id="worker-b")  # fenced off
    with session_scope() as db:
        assert db.get(DependencyCheck, check.id).status == RunStatus.RUNNING
    dc.fail_dependency_check(check.id, "boom", worker_id="worker-a")
    with session_scope() as db:
        assert db.get(DependencyCheck, check.id).status == RunStatus.FAILED


def test_purge_old_dep_records():
    from datetime import timedelta

    repo = _repo()
    _settle_checks(repo.id)
    old = datetime.now(UTC) - timedelta(days=200)
    with session_scope() as db:
        row = DependencyCheck(
            repo_id=repo.id, status=RunStatus.DONE, trigger=RunTrigger.MANUAL,
            started_at=old, finished_at=old,
        )
        db.add(row)
        db.flush()
        old_check_id = row.id
    counts = dc.purge_old_dep_records()
    assert counts["checks"] >= 1
    with session_scope() as db:
        assert db.get(DependencyCheck, old_check_id) is None


def test_prune_absent_packages(tmp_path):
    repo = _repo()
    _run(repo.id, _source(tmp_path), summary_model=_Model("s"))
    assert {r.package for r in _rows(repo.id)} == {"left-pad", "django"}
    (tmp_path / "requirements.txt").unlink()  # django no longer declared
    _run(repo.id, tmp_path, summary_model=_Model("s2"))
    assert {r.package: r for r in _rows(repo.id)}.keys() == {"left-pad"}
