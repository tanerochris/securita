"""Slice G: dashboard flows for repos, findings, patches, approvals."""

import re
from datetime import UTC, datetime
from unittest import mock

from fastapi.testclient import TestClient
from sqlalchemy import select

from security_agent.app import accounts as accounts_svc
from security_agent.app.main import app
from security_agent.control import gates
from security_agent.db.models import (
    Approval,
    Finding,
    FindingStatus,
    GateAction,
    GateStatus,
    Proposal,
    Role,
)
from security_agent.db.session import session_scope
from security_agent.worker import deliver as deliver_mod

client = TestClient(app, raise_server_exceptions=False)


def _login_as(role: Role) -> None:
    client.cookies.clear()
    email = f"dash-{role.value}-{datetime.now(UTC).timestamp()}@example.com"
    user = accounts_svc.create_user(email, None, role)
    sid = accounts_svc.create_session(user.id)
    client.cookies.set("app_session", sid)


def _csrf(path: str) -> str:
    resp = client.get(path)
    match = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert match, f"no csrf token on {path}"
    return match.group(1)


def _seed_gate_fixture() -> tuple[int, int, int]:
    from security_agent.control import repos as repo_svc
    from security_agent.db.models import RepoKind

    repo = repo_svc.connect_repo(
        f"dash-r-{datetime.now(UTC).timestamp()}",
        RepoKind.GIT,
        url="https://github.com/o/dash.git",
    )
    with session_scope() as db:
        finding = Finding(
            repo_id=repo.id,
            package="left-pad",
            installed_version="1.0.0",
            advisory_id="CVE-DASH",
            status=FindingStatus.PROPOSED,
        )
        db.add(finding)
        db.flush()
        proposal = Proposal(
            repo_id=repo.id,
            finding_ids=[finding.id],
            package_from="1.0.0",
            package_to="1.0.1",
            verification_result="tests passed",
            pr_url="https://github.com/o/dash/pull/1",
            pr_state="open",
            branch="security/left-pad-CVE-DASH",
            base_branch="main",
        )
        db.add(proposal)
        db.flush()
        pid = proposal.id
    gate = gates.request_gate(
        repo.id, GateAction.MERGE, "https://github.com/o/dash/pull/1", proposal_id=pid
    )
    return repo.id, pid, gate.id


def test_repo_list_connect_and_detail():
    _login_as(Role.OWNER)
    assert client.get("/repos").status_code == 200
    r = client.post(
        "/repos/connect",
        data={
            "name": f"web-{datetime.now(UTC).timestamp()}",
            "kind": "local",
            "local_path": "/tmp/web-repo",
            "csrf": _csrf("/repos"),
        },
    )
    assert r.status_code in (200, 303)
    detail = client.get("/repos")
    assert "web-" in detail.text


def test_scan_now_roles():
    from security_agent.control import repos as repo_svc
    from security_agent.db.models import RepoKind, RunTrigger, ScanRun

    repo = repo_svc.connect_repo(
        f"scan-{datetime.now(UTC).timestamp()}", RepoKind.LOCAL, local_path="/tmp/scan-r"
    )
    with session_scope() as db:  # connect run already executed; manual scan starts clean
        from security_agent.db.models import RunStatus

        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        run.status = RunStatus.DONE
        run.finished_at = datetime.now(UTC)
    _login_as(Role.DEVELOPER)
    r = client.post(f"/repos/{repo.id}/scan", data={"csrf": _csrf(f"/repos/{repo.id}")})
    assert r.status_code in (200, 303)
    with session_scope() as db:
        assert (
            db.scalar(
                select(ScanRun).where(
                    ScanRun.repo_id == repo.id, ScanRun.trigger == RunTrigger.MANUAL
                )
            )
            is not None
        )
    _login_as(Role.REPORTER)
    from security_agent.app.dependencies import make_csrf

    r = client.post(f"/repos/{repo.id}/scan", data={"csrf": make_csrf()})
    assert r.status_code == 403


def test_token_rotation_owner_only():
    from security_agent.app.dependencies import make_csrf
    from security_agent.control import repos as repo_svc
    from security_agent.db.models import RepoKind

    repo = repo_svc.connect_repo(
        f"tok-{datetime.now(UTC).timestamp()}",
        RepoKind.GIT,
        url="https://github.com/o/t.git",
        token="old",
    )
    _login_as(Role.OWNER)
    r = client.post(
        f"/repos/{repo.id}/token",
        data={"token": "new", "csrf": _csrf(f"/repos/{repo.id}")},
    )
    assert r.status_code in (200, 303)
    assert repo_svc.get_repo_token(repo.id) == "new"
    _login_as(Role.DEVELOPER)
    r = client.post(f"/repos/{repo.id}/token", data={"token": "x", "csrf": make_csrf()})
    assert r.status_code == 403
    local = repo_svc.connect_repo(
        f"tok-local-{datetime.now(UTC).timestamp()}",
        RepoKind.LOCAL,
        local_path="/tmp/tok-local",
    )
    _login_as(Role.OWNER)
    r = client.post(f"/repos/{local.id}/token", data={"token": "x", "csrf": make_csrf()})
    assert r.status_code == 400


def test_findings_and_patches_views():
    repo_id, _pid, _gate = _seed_gate_fixture()
    _login_as(Role.REPORTER)
    findings = client.get(f"/repos/{repo_id}/findings")
    assert findings.status_code == 200 and "CVE-DASH" in findings.text
    patches = client.get(f"/repos/{repo_id}/patches")
    assert patches.status_code == 200 and "1.0.0 → 1.0.1" in patches.text
    assert "Merge now" not in patches.text  # no merge button on patches view


def test_findings_views_carry_no_news_badges():
    from security_agent.control import repos as repo_svc
    from security_agent.db.models import RepoKind

    repo = repo_svc.connect_repo(
        f"nobadge-{datetime.now(UTC).timestamp()}", RepoKind.LOCAL, local_path="/tmp/nobadge-r"
    )
    with session_scope() as db:
        for advisory, score in (("CVE-NB-LOW", 5.0), ("CVE-NB-HIGH", 9.0)):
            db.add(
                Finding(
                    repo_id=repo.id,
                    package="left-pad",
                    installed_version="1.0.0",
                    advisory_id=advisory,
                    severity_score=score,
                    news_weight=100,
                    news_url="https://news.example/story",
                )
            )
    _login_as(Role.REPORTER)
    body = client.get(f"/repos/{repo.id}/findings").text
    assert "news +" not in body
    assert "https://news.example/story" not in body
    assert body.index("CVE-NB-HIGH") < body.index("CVE-NB-LOW")  # severity orders
    detail = client.get(f"/repos/{repo.id}").text
    assert "news +" not in detail
    assert "https://news.example/story" not in detail
    dash = client.get("/dashboard").text
    assert "Boosted by news" not in dash


def test_news_feed_serves_major_only():
    from security_agent.db.models import NewsItem

    stamp = datetime.now(UTC).timestamp()
    with session_scope() as db:
        db.add(
            NewsItem(
                source="hn",
                external_id=f"feed-major-{stamp}",
                title=f"Major breach rocks supply chain {stamp}",
                url="https://news.example/major",
                summary="wormable",
                cve_ids=["CVE-2026-31337"],
                verdict="major",
                category="breach",
            )
        )
        db.add(
            NewsItem(
                source="hn",
                external_id=f"feed-minor-{stamp}",
                title=f"Small vendor advisory {stamp}",
                verdict="minor",
                category="patch",
            )
        )
        db.add(
            NewsItem(
                source="hn",
                external_id=f"feed-uncl-{stamp}",
                title=f"Awaiting classification {stamp}",
            )
        )
    _login_as(Role.REPORTER)
    body = client.get("/news").text
    assert "Major breach rocks supply chain" in body
    assert "CVE-2026-31337" in body
    assert "Small vendor advisory" not in body
    assert "Awaiting classification" not in body


def test_repo_news_section_and_feed_tags():
    from security_agent.control import repos as repo_svc
    from security_agent.db.models import NewsFindingLink, NewsItem, RepoKind

    stamp = datetime.now(UTC).timestamp()
    repo = repo_svc.connect_repo(f"newsrepo-{stamp}", RepoKind.LOCAL, local_path="/tmp/newsrepo-r")
    other = repo_svc.connect_repo(
        f"otherrepo-{stamp}", RepoKind.LOCAL, local_path="/tmp/otherrepo-r"
    )
    with session_scope() as db:
        finding = Finding(
            repo_id=repo.id,
            package="left-pad",
            installed_version="1.0.0",
            advisory_id="CVE-2026-41414",
        )
        db.add(finding)
        item = NewsItem(
            source="hn",
            external_id=f"tagged-{stamp}",
            title=f"Left-pad RCE campaign {stamp}",
            url="https://news.example/leftpad",
            summary="critical",
            cve_ids=["CVE-2026-41414"],
            verdict="major",
            category="vulnerability",
        )
        db.add(item)
        db.flush()
        db.add(NewsFindingLink(news_item_id=item.id, finding_id=finding.id, kind="minted"))
    _login_as(Role.REPORTER)
    detail = client.get(f"/repos/{repo.id}").text
    assert "Security news (1)" in detail
    assert "Left-pad RCE" in detail
    missing = client.get(f"/repos/{other.id}").text
    assert "No security news for this repo" in missing
    feed = client.get("/news").text
    assert f">{repo.name}</a>" in feed  # repo tag chip
    filtered = client.get(f"/news?repo={repo.id}").text
    assert "Left-pad RCE" in filtered
    assert repo.name in filtered
    excluded = client.get(f"/news?repo={other.id}").text
    assert "Left-pad RCE" not in excluded


def test_approve_then_merge_flow():
    _repo_id, pid, gate_id = _seed_gate_fixture()
    _login_as(Role.MAINTAINER)
    queue = client.get("/approvals")
    assert queue.status_code == 200 and "pull/1" in queue.text
    r = client.post(f"/approvals/{gate_id}/approve", data={"csrf": _csrf("/approvals")})
    assert r.status_code in (200, 303)
    with session_scope() as db:
        assert db.get(Approval, gate_id).status == GateStatus.APPROVED
    with (
        mock.patch.object(deliver_mod, "merge_pr"),
        mock.patch.object(deliver_mod, "sync_proposal_states", return_value={"synced": 1}),
        mock.patch("security_agent.control.repos.get_merge_token", return_value="tok"),
    ):
        r = client.post(f"/approvals/{gate_id}/merge", data={"csrf": _csrf("/approvals")})
    assert r.status_code in (200, 303)


def test_deny_and_delegation_flow():
    _repo_id, _pid, gate_id = _seed_gate_fixture()
    _login_as(Role.OWNER)
    csrf = _csrf("/approvals")
    r = client.post(f"/approvals/{gate_id}/deny", data={"csrf": csrf, "reason": "nope"})
    assert r.status_code in (200, 303)
    with session_scope() as db:
        assert db.get(Approval, gate_id).status == GateStatus.DENIED
    dev_email = f"deleg-{datetime.now(UTC).timestamp()}@example.com"
    accounts_svc.create_user(dev_email, None, Role.DEVELOPER)
    r = client.post(
        "/approvals/delegations",
        data={"email": dev_email, "classes": "merge", "csrf": _csrf("/approvals")},
    )
    assert r.status_code in (200, 303)
    with session_scope() as db:
        from security_agent.db.models import Delegation, User

        delegate = db.scalar(select(User).where(User.email == dev_email))
        assert delegate is not None
        row = db.scalar(select(Delegation).where(Delegation.delegate_id == delegate.id))
        assert row is not None and row.classes == ["merge"]


def test_findings_pagination():
    from security_agent.control import repos as repo_svc
    from security_agent.db.models import RepoKind

    repo = repo_svc.connect_repo(
        f"page-{datetime.now(UTC).timestamp()}", RepoKind.LOCAL, local_path="/tmp/page-r"
    )
    with session_scope() as db:
        for i in range(30):
            db.add(
                Finding(
                    repo_id=repo.id,
                    package="left-pad",
                    installed_version="1.0.0",
                    advisory_id=f"CVE-PAGE-{i:02d}",
                    status=FindingStatus.OPEN,
                )
            )
    _login_as(Role.REPORTER)
    first = client.get(f"/repos/{repo.id}/findings").text
    assert "Showing 1–25 of 30" in first
    assert "Page 1 of 2" in first
    assert first.count("CVE-PAGE-") == 25
    second = client.get(f"/repos/{repo.id}/findings?page=2&per=25").text
    assert "Showing 26–30 of 30" in second
    assert second.count("CVE-PAGE-") == 5
    everything = client.get(f"/repos/{repo.id}/findings?per=all").text
    assert "Showing 1–30 of 30" in everything
    assert everything.count("CVE-PAGE-") == 30
    assert "Page 1 of 1" not in everything  # single page hides the pager
    fallback = client.get(f"/repos/{repo.id}/findings?per=bogus&page=99").text
    assert "Showing 26–30 of 30" in fallback  # bad per → 25, high page clamps


def test_disconnect_repo_flow():
    from security_agent.app.dependencies import make_csrf
    from security_agent.control import repos as repo_svc
    from security_agent.db.models import Repo, RepoKind

    repo = repo_svc.connect_repo(
        f"disc-{datetime.now(UTC).timestamp()}", RepoKind.LOCAL, local_path="/tmp/disc-r"
    )
    with session_scope() as db:
        db.add(
            Finding(
                repo_id=repo.id,
                package="left-pad",
                installed_version="1.0.0",
                advisory_id="CVE-DISC",
                status=FindingStatus.OPEN,
            )
        )
    _login_as(Role.REPORTER)
    r = client.post(f"/repos/{repo.id}/disconnect", data={"csrf": make_csrf()})
    assert r.status_code == 403
    _login_as(Role.DEVELOPER)
    r = client.post(f"/repos/{repo.id}/disconnect", data={"csrf": make_csrf()})
    assert r.status_code == 403
    _login_as(Role.OWNER)
    r = client.post(f"/repos/{repo.id}/disconnect", data={"csrf": _csrf(f"/repos/{repo.id}")})
    assert r.status_code in (200, 303)
    assert client.get(f"/repos/{repo.id}").status_code == 404
    with session_scope() as db:
        assert db.get(Repo, repo.id) is None
        assert db.scalar(select(Finding).where(Finding.repo_id == repo.id)) is None
