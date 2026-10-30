"""Slice A: findings lifecycle transitions + verdict-driven flips."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from security_agent.control.lifecycle import (
    apply_verdict,
    list_open_findings,
    purge_old_verdicts,
    transition_finding,
)
from security_agent.db.models import (
    Finding,
    FindingStatus,
    Repo,
    RepoKind,
    RunTrigger,
    ScanRun,
)
from security_agent.db.session import session_scope


def _seed_repo() -> int:
    with session_scope() as db:
        repo = Repo(
            name=f"r-{datetime.now(UTC).timestamp()}",
            kind=RepoKind.GIT,
            url="https://example.com/r.git",
        )
        db.add(repo)
        db.flush()
        return repo.id


def _seed_run(repo_id: int) -> int:
    with session_scope() as db:
        run = ScanRun(repo_id=repo_id, trigger=RunTrigger.MANUAL)
        db.add(run)
        db.flush()
        return run.id


def test_purge_old_verdicts_keeps_recent():
    from datetime import timedelta

    from security_agent.db.models import Verdict

    repo_id = _seed_repo()
    run_id = _seed_run(repo_id)
    fid = _seed_finding(repo_id)
    apply_verdict(fid, run_id, True)
    with session_scope() as db:
        verdict = db.scalar(select(Verdict).where(Verdict.finding_id == fid))
        verdict.created_at = datetime.now(UTC) - timedelta(days=91)
    assert purge_old_verdicts() == 1
    apply_verdict(fid, run_id, False, reason_code="no-import-chain")
    assert purge_old_verdicts() == 0


def _seed_finding(repo_id: int, package: str = "left-pad") -> int:
    with session_scope() as db:
        finding = Finding(
            repo_id=repo_id,
            package=package,
            installed_version="1.0.0",
            advisory_id="CVE-2026-0001",
        )
        db.add(finding)
        db.flush()
        return finding.id


def test_happy_path_open_to_closed():
    repo_id = _seed_repo()
    fid = _seed_finding(repo_id)
    assert transition_finding(fid, FindingStatus.PROPOSED).status == FindingStatus.PROPOSED
    assert transition_finding(fid, FindingStatus.RESOLVED).status == FindingStatus.RESOLVED
    assert transition_finding(fid, FindingStatus.CLOSED).status == FindingStatus.CLOSED


def test_illegal_jump_rejected_and_terminals_stick():
    repo_id = _seed_repo()
    fid = _seed_finding(repo_id, package="jump-pkg")
    with pytest.raises(ValueError, match="Illegal transition"):
        transition_finding(fid, FindingStatus.CLOSED)
    transition_finding(fid, FindingStatus.UNPATCHABLE)
    with pytest.raises(ValueError, match="Illegal transition"):
        transition_finding(fid, FindingStatus.OPEN)


def test_unreachable_parks_and_reachable_reopens():
    repo_id = _seed_repo()
    run_id = _seed_run(repo_id)
    fid = _seed_finding(repo_id, package="flip-pkg")
    apply_verdict(fid, run_id, False, reason_code="no-import-chain")
    with session_scope() as db:
        assert db.get(Finding, fid).status == FindingStatus.SILENT
        assert db.get(Finding, fid).silent_reason == "no-import-chain"
    apply_verdict(fid, run_id, True, evidence={"chain": ["a.js:1"]})
    with session_scope() as db:
        row = db.get(Finding, fid)
        assert row.status == FindingStatus.OPEN
        assert row.silent_reason is None


def test_finding_unique_per_repo_package_advisory():
    repo_id = _seed_repo()
    _seed_finding(repo_id, package="dup-pkg")
    with pytest.raises(IntegrityError):
        _seed_finding(repo_id, package="dup-pkg")


def test_open_list_excludes_silent_kev_first():
    repo_id = _seed_repo()
    run_id = _seed_run(repo_id)
    plain = _seed_finding(repo_id, package="plain-pkg")
    with session_scope() as db:
        kev = Finding(
            repo_id=repo_id,
            package="kev-pkg",
            installed_version="1.0.0",
            advisory_id="CVE-2026-0002",
            kev_exploited=True,
        )
        db.add(kev)
        db.flush()
        kev_id = kev.id
    apply_verdict(plain, run_id, False, reason_code="no-import-chain")
    rows = list_open_findings(repo_id)
    assert [r.id for r in rows] == [kev_id]
