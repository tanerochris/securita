import re

from fastapi.testclient import TestClient

from security_agent.app.main import app

client = TestClient(app, raise_server_exceptions=False)


def _csrf(path: str) -> str:
    resp = client.get(path)
    match = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert match, f"no csrf token on {path}"
    return match.group(1)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_dashboard_requires_login():
    client.cookies.clear()
    r = client.get("/dashboard")
    assert r.status_code == 401


def test_signup_login_dashboard_flow():
    from security_agent.app import accounts as svc
    from security_agent.db.models import Role

    client.cookies.clear()
    email = "flow@example.com"
    data = {"email": email, "password": "correct-horse-12", "csrf": _csrf("/signup")}
    if svc.user_count() > 0 and svc.get_user_by_email(email) is None:
        # Another suite populated accounts first; join via invite instead.
        data["token"] = svc.issue_invite(email, Role.REPORTER)
    r = client.post("/signup", data=data)
    assert r.status_code in (200, 303)
    dash = client.get("/dashboard")
    assert dash.status_code == 200
    assert "Dashboard" in dash.text
    # Logout revokes the server session, not just the cookie.
    csrf = re.search(r'name="csrf" value="([^"]+)"', dash.text)
    assert csrf
    r = client.post("/logout", data={"csrf": csrf.group(1)})
    assert r.status_code in (200, 303)
    assert client.get("/dashboard").status_code == 401


def test_csrf_required_for_posts():
    r = client.post("/login", data={"email": "x@example.com", "password": "y"})
    assert r.status_code == 403


def test_sso_unconfigured_is_501():
    assert client.get("/auth/google/start").status_code == 501
    assert client.get("/auth/microsoft/start").status_code == 501
