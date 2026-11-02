"""Overview dashboard: ops strip, queues preview, and attention columns."""

import re
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import select

from security_agent.app import accounts as accounts_svc
from security_agent.app.main import app
from security_agent.db.models import Role
from security_agent.db.session import session_scope

client = TestClient(app, raise_server_exceptions=False)


def _login_as(role: Role) -> None:
    client.cookies.clear()
    email = f"ovw-{role.value}-{datetime.now(UTC).timestamp()}@example.com"
    user = accounts_svc.create_user(email, None, role)
    sid = accounts_svc.create_session(user.id)
    client.cookies.set("app_session", sid)


def _connect_repo(name: str):
    from security_agent.control import repos as repo_svc
    from security_agent.db.models import RepoKind

    return repo_svc.connect_repo(name, RepoKind.LOCAL, local_path="/tmp/ovw-repo")


def _latest_run_id(repo_id: int) -> int:
    from security_agent.db.models import ScanRun

    with session_scope() as db:
        run = db.scalar(
            select(ScanRun)
            .where(ScanRun.repo_id == repo_id)
            .order_by(ScanRun.id.desc())
            .limit(1)
        )
        assert run is not None
        return run.id


def test_ops_strip_running_and_failed():
    from security_agent.db.models import RunStatus, ScanRun

    tag = f"{datetime.now(UTC).timestamp()}"
    repo = _connect_repo(f"ovw-ops-{tag}")
    run_id = _latest_run_id(repo.id)
    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        run.status = RunStatus.RUNNING
        run.parked = False
    _login_as(Role.OWNER)
    body = client.get("/dashboard").text
    assert "Scanning now" in body
    assert f"/repos/{repo.id}/runs/{run_id}" in body

    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        run.status = RunStatus.FAILED
        run.finished_at = datetime.now(UTC)
    body = client.get("/dashboard").text
    assert "failed in 24h" in body
    assert f"/repos/{repo.id}/runs/{run_id}" in body


def test_parked_runs_surface_with_spend():
    from security_agent.db.models import RunStatus, RunTrigger, ScanRun

    tag = f"{datetime.now(UTC).timestamp()}"
    repo = _connect_repo(f"ovw-park-{tag}")
    with session_scope() as db:
        connect_run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        connect_run.status = RunStatus.DONE
        connect_run.finished_at = datetime.now(UTC)
        db.add(
            ScanRun(
                repo_id=repo.id,
                status=RunStatus.RUNNING,
                trigger=RunTrigger.SCHEDULED,
                parked=True,
                park_reason="test cost cap",
                token_usage=123,
            )
        )
    _login_as(Role.OWNER)
    body = client.get("/dashboard").text
    assert "parked by cost cap" in body
    assert repo.name in body
    assert "Spend today $" in body
    assert "Resume in settings" in body


def test_queues_preview_secrets_deps_news_policies():
    from security_agent.db.models import (
        Dependency,
        DependencyStatus,
        Finding,
        FindingStatus,
        NewsItem,
        PolicyRule,
        SecretFinding,
        SecretStatus,
        Verdict,
    )

    tag = f"{datetime.now(UTC).timestamp()}"
    repo = _connect_repo(f"ovw-q-{tag}")
    run_id = _latest_run_id(repo.id)
    rule_id = f"ovw-rule-{tag}"
    package = f"ovw-pkg-{tag}"
    advisory = f"CVE-OVW-{tag}"
    news_title = f"ovw-news-{tag}"
    rule_key = f"ovw-policy-{tag}"
    with session_scope() as db:
        db.add(
            SecretFinding(
                repo_id=repo.id,
                rule_id=rule_id,
                path="src/leak.ts",
                fingerprint=f"fp-{tag}",
                liveness="live",
                status=SecretStatus.OPEN,
            )
        )
        db.add(
            Dependency(
                repo_id=repo.id,
                ecosystem="npm",
                manifest_path="package.json",
                package=package,
                installed_version="1.0.0",
                latest_version="2.0.0",
                update_class="major",
                security=True,
                status=DependencyStatus.UPDATE_AVAILABLE,
            )
        )
        db.add(
            NewsItem(
                source="ovw-test",
                external_id=f"ext-{tag}",
                title=news_title,
                url="https://example.com/ovw",
                category="vulnerability",
                verdict="major",
            )
        )
        db.add(
            PolicyRule(
                rule_key=rule_key,
                scope="platform",
                effect="block",
                match={},
                reason="overview dashboard test",
            )
        )
        finding = Finding(
            repo_id=repo.id,
            package=package,
            installed_version="1.0.0",
            advisory_id=advisory,
            severity_score=9.9,
            kev_exploited=True,
            status=FindingStatus.OPEN,
        )
        db.add(finding)
        db.flush()
        db.add(Verdict(finding_id=finding.id, run_id=run_id, reachable=True))
    _login_as(Role.OWNER)
    body = client.get("/dashboard").text
    assert rule_id in body  # secrets preview
    assert ">live</span>" in body
    assert package in body  # deps security + attention table
    assert news_title in body  # news strip
    assert "awaiting confirmation" in body  # policies banner
    assert advisory in body  # attention table
    assert ">reachable</span>" in body  # reachability column
    assert f"/repos/{repo.id}/findings" in body  # repo column link


def test_header_identity_and_bell_on_every_page():
    _login_as(Role.OWNER)
    pages = [
        "/dashboard",
        "/repos",
        "/news",
        "/notifications",
        "/policies",
        "/approvals",
        "/accounts",
        "/settings",
    ]
    for path in pages:
        body = client.get(path).text
        desktop_id = body.index('ml-auto truncate text-sm text-slate-600">Signed in as')
        desktop_bell = body.index('hx-get="/notifications/count"')
        assert desktop_id < desktop_bell, f"desktop header order on {path}"
        mobile_id = body.index("ml-auto max-w-[45%]")
        mobile_bell = body.index("h-8 w-8 flex-none")
        assert mobile_id < mobile_bell, f"mobile header order on {path}"
    client.cookies.clear()
    assert 'aria-label="Notifications"' not in client.get("/login").text


def test_datetimes_render_as_utc_time_elements():
    tag = f"{datetime.now(UTC).timestamp()}"
    repo = _connect_repo(f"ovw-time-{tag}")
    run_id = _latest_run_id(repo.id)
    _login_as(Role.OWNER)
    for path in [
        "/dashboard",
        "/repos",
        f"/repos/{repo.id}",
        f"/repos/{repo.id}/runs/{run_id}",
        "/notifications",
        "/approvals",
        "/news",
    ]:
        body = client.get(path).text
        assert 'querySelectorAll("time[data-kind]")' in body, f"localizer on {path}"
    for path in ["/dashboard", f"/repos/{repo.id}", f"/repos/{repo.id}/runs/{run_id}"]:
        body = client.get(path).text
        assert "<time datetime=" in body, f"time elements on {path}"
        assert "+00:00" in body, f"UTC instant on {path}"


def test_sidebar_marks_active_section():
    tag = f"{datetime.now(UTC).timestamp()}"
    repo = _connect_repo(f"ovw-nav-{tag}")
    _login_as(Role.OWNER)
    cases = {
        "/dashboard": "/dashboard",
        "/repos": "/repos",
        f"/repos/{repo.id}": "/repos",
        f"/repos/{repo.id}/findings": "/repos",
        "/news": "/news",
        "/notifications": "/notifications",
        "/policies": "/policies",
        "/approvals": "/approvals",
        "/accounts": "/accounts",
        "/settings": "/settings",
    }
    for page, href in cases.items():
        body = client.get(page).text
        hits = re.findall(r'nav-link-active[^"]*" href="([^"]+)"', body)
        assert hits, f"no active link on {page}"
        assert all(h == href for h in hits), f"wrong active link on {page}: {hits}"
        assert 'aria-current="page"' in body, f"no aria-current on {page}"
    profile = client.get("/profile").text
    assert "nav-link-active\" href=" not in profile
    assert "nav-link-active whitespace-nowrap" not in profile
    assert 'aria-current="page"' not in profile


def test_ai_usage_section_renders_day_week_month_and_cap():
    _login_as(Role.OWNER)
    body = client.get("/dashboard").text
    assert "AI usage" in body
    assert "Today" in body and "Last 7 days" in body and "This month" in body
    assert "Monthly spend cap" in body
