"""Dependencies tab, report decisions, settings, notifications (D7/D10/D11/D15/D17)."""

import re
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import select

from security_agent.app import accounts as accounts_svc
from security_agent.app.main import app
from security_agent.control import repos as repo_svc
from security_agent.db.models import (
    Dependency,
    DependencyCheck,
    DependencyReport,
    DependencyStatus,
    RepoKind,
    Role,
    RunStatus,
)
from security_agent.db.session import session_scope

client = TestClient(app, raise_server_exceptions=False)


def _login_as(role: Role) -> None:
    client.cookies.clear()
    email = f"depsdash-{role.value}-{datetime.now(UTC).timestamp()}@example.com"
    user = accounts_svc.create_user(email, None, role)
    sid = accounts_svc.create_session(user.id)
    client.cookies.set("app_session", sid)


def _csrf(path: str) -> str:
    resp = client.get(path)
    match = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert match, f"no csrf token on {path}"
    return match.group(1)


def _seed() -> tuple[int, int, int]:
    repo = repo_svc.connect_repo(
        f"depsdash-{datetime.now(UTC).timestamp()}", RepoKind.LOCAL, local_path="/tmp/x"
    )
    with session_scope() as db:
        for row in db.scalars(
            select(DependencyCheck).where(DependencyCheck.repo_id == repo.id)
        ):
            row.status = RunStatus.DONE
            row.finished_at = datetime.now(UTC)
        a = Dependency(
            repo_id=repo.id, ecosystem="npm", manifest_path="package.json",
            package="left-pad", manifest_spec="^1.3.0", installed_version="1.3.0",
            latest_version="2.0.0", update_class="major", security=True,
            status=DependencyStatus.AWAITING_DECISION,
        )
        b = Dependency(
            repo_id=repo.id, ecosystem="pip", manifest_path="requirements.txt",
            package="django", manifest_spec="==4.2.0", installed_version="4.2.0",
            latest_version="4.2.1", update_class="patch",
            status=DependencyStatus.AWAITING_DECISION,
        )
        db.add(a)
        db.add(b)
        db.flush()
        report = DependencyReport(
            repo_id=repo.id, status="pending", summary="summary text",
            sections=[
                {
                    "key": "npm|package.json|left-pad", "anchor": "pkg-left-pad",
                    "package": "left-pad", "ecosystem": "npm",
                    "manifest_path": "package.json", "installed": "1.3.0",
                    "latest": "2.0.0", "update_class": "major", "security": True,
                    "advisories": [], "usage_sites": ["index.js:1"],
                    "changelog": "UNDETERMINED",
                },
                {
                    "key": "pip|requirements.txt|django", "anchor": "pkg-django",
                    "package": "django", "ecosystem": "pip",
                    "manifest_path": "requirements.txt", "installed": "4.2.0",
                    "latest": "4.2.1", "update_class": "patch", "security": False,
                    "advisories": [], "usage_sites": [],
                    "changelog": "UNDETERMINED",
                },
            ],
            undecided_keys=["npm|package.json|left-pad", "pip|requirements.txt|django"],
        )
        db.add(report)
        db.flush()
        return repo.id, a.id, b.id, report.id


def test_dependencies_tab_renders_rows_and_actions():
    _login_as(Role.OWNER)
    repo_id, _, _, report_id = _seed()
    resp = client.get(f"/repos/{repo_id}/dependencies")
    assert resp.status_code == 200
    assert "left-pad" in resp.text and "django" in resp.text
    assert "major" in resp.text and "2.0.0" in resp.text
    assert "Check updates now" in resp.text
    assert f"/repos/{repo_id}/dependencies/report/{report_id}" in resp.text
    assert "package.json" in resp.text and "requirements.txt" in resp.text


def test_check_now_enqueues_and_report_decides_with_exclusion():
    _login_as(Role.OWNER)
    repo_id, dep_a, dep_b, report_id = _seed()
    csrf = _csrf(f"/repos/{repo_id}/dependencies")
    resp = client.post(
        f"/repos/{repo_id}/dependencies/check", data={"csrf": csrf}, follow_redirects=False
    )
    assert resp.status_code == 303
    with session_scope() as db:
        check = db.scalar(
            select(DependencyCheck).where(DependencyCheck.repo_id == repo_id).order_by(
                DependencyCheck.id.desc()
            )
        )
        assert check is not None and check.status == RunStatus.RUNNING
        check.status = RunStatus.DONE  # settle: other tests enumerate checks
    resp = client.get(f"/repos/{repo_id}/dependencies/report/{report_id}")
    assert resp.status_code == 200
    assert "summary text" in resp.text and "index.js:1" in resp.text
    assert "UNDETERMINED" in resp.text
    resp = client.post(
        f"/repos/{repo_id}/dependencies/report/{report_id}/decide",
        data={"csrf": csrf, "included": ["npm|package.json|left-pad"], "reason": "ship"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    with session_scope() as db:
        assert db.get(Dependency, dep_a).status == DependencyStatus.PROPOSED
        assert db.get(Dependency, dep_b).status == DependencyStatus.DECLINED
        report = db.get(DependencyReport, report_id)
        assert report is not None and report.status == "decided"


def test_decline_ignore_unignore_roundtrip():
    _login_as(Role.MAINTAINER)
    repo_id, dep_a, _, _ = _seed()
    csrf = _csrf(f"/repos/{repo_id}/dependencies")
    for action, want in (
        ("decline", DependencyStatus.DECLINED),
        ("ignore", DependencyStatus.IGNORED),
    ):
        resp = client.post(
            f"/repos/{repo_id}/dependencies/{dep_a}/{action}",
            data={"csrf": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        with session_scope() as db:
            assert db.get(Dependency, dep_a).status == want
    resp = client.post(
        f"/repos/{repo_id}/dependencies/{dep_a}/unignore",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    with session_scope() as db:
        assert db.get(Dependency, dep_a).status == DependencyStatus.UPDATE_AVAILABLE


def test_developer_cannot_decide_or_silence():
    _login_as(Role.DEVELOPER)
    repo_id, dep_a, _, report_id = _seed()
    csrf = _csrf(f"/repos/{repo_id}/dependencies")
    resp = client.post(
        f"/repos/{repo_id}/dependencies/report/{report_id}/decide",
        data={"csrf": csrf, "included": []},
        follow_redirects=False,
    )
    assert resp.status_code == 403
    resp = client.post(
        f"/repos/{repo_id}/dependencies/{dep_a}/ignore",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 403
    resp = client.post(
        f"/repos/{repo_id}/dependencies/check", data={"csrf": csrf}, follow_redirects=False
    )
    assert resp.status_code == 303  # developers can trigger checks


def test_cross_repo_ids_are_rejected():
    """A report/dep from repo B cannot be decided via repo A's URLs."""
    _login_as(Role.OWNER)
    repo_a, _, _, _ = _seed()
    repo_b, dep_b, _, report_b = _seed()
    csrf = _csrf(f"/repos/{repo_a}/dependencies")
    resp = client.post(
        f"/repos/{repo_a}/dependencies/report/{report_b}/decide",
        data={"csrf": csrf, "included": []},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    resp = client.post(
        f"/repos/{repo_a}/dependencies/{dep_b}/ignore",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    with session_scope() as db:
        assert db.get(Dependency, dep_b).status == DependencyStatus.AWAITING_DECISION
    _ = repo_b


def test_repo_cadence_override():
    _login_as(Role.OWNER)
    repo_id, _, _, _ = _seed()
    csrf = _csrf(f"/repos/{repo_id}/dependencies")
    resp = client.post(
        f"/repos/{repo_id}/dependencies/cadence",
        data={"csrf": csrf, "mode": "never", "hours": "24"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    resp = client.get(f"/repos/{repo_id}/dependencies")
    assert "never checks automatically" in resp.text


def test_settings_dep_controls():
    _login_as(Role.OWNER)
    csrf = _csrf("/settings")
    resp = client.get("/settings")
    assert "Dependency updates" in resp.text and "every 24h" in resp.text
    resp = client.post(
        "/settings/deps/cadence", data={"csrf": csrf, "hours": "48"}, follow_redirects=False
    )
    assert resp.status_code == 303
    try:
        resp = client.get("/settings")
        assert "every 48h" in resp.text
        resp = client.post(
            "/settings/deps/budget",
            data={"csrf": csrf, "cap": "500000"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        resp = client.post(
            "/settings/deps/notify",
            data={"csrf": csrf, "enabled": "on"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
    finally:
        client.post("/settings/deps/cadence", data={"csrf": csrf, "hours": "24"})
        client.post("/settings/deps/budget", data={"csrf": csrf, "cap": "200000"})
        client.post("/settings/deps/notify", data={"csrf": csrf})


def test_notifications_pool_and_badge():
    from security_agent.control import notifications as notif

    _login_as(Role.OWNER)
    repo_id, _, _, _ = _seed()
    notif.push_notification("deps-report", "3 updates ready", repo_id=repo_id)
    resp = client.get("/notifications")
    assert resp.status_code == 200 and "3 updates ready" in resp.text
    badge = client.get("/notifications/count")
    assert badge.status_code == 200 and "Notifications" in badge.text
    csrf = _csrf("/notifications")
    resp = client.post("/notifications/read-all", data={"csrf": csrf}, follow_redirects=False)
    assert resp.status_code == 303
    badge = client.get("/notifications/count")
    assert "unread" not in badge.text
