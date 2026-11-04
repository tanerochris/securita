"""Guest demo login: one-click Owner session, always on."""

import re

from fastapi.testclient import TestClient

from security_agent.app import accounts as accounts_svc
from security_agent.app.main import app
from security_agent.db.models import Role

client = TestClient(app, raise_server_exceptions=False)


def _csrf(path: str) -> str:
    resp = client.get(path)
    match = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert match, f"no csrf token on {path}"
    return match.group(1)


def test_login_page_offers_guest():
    resp = client.get("/login")
    assert resp.status_code == 200
    assert "/guest-login" in resp.text
    assert "guest" in resp.text.lower()
    assert resp.text.index("/guest-login") < resp.text.index('action="/login"')


def test_guest_login_creates_owner_session():
    client.cookies.clear()
    resp = client.post("/guest-login", data={"csrf": _csrf("/login")}, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard"
    assert "app_session" in resp.headers.get("set-cookie", "")
    guest = accounts_svc.get_user_by_email(accounts_svc.GUEST_EMAIL)
    assert guest is not None and guest.role == Role.OWNER
    dash = client.get("/dashboard")
    assert dash.status_code == 200
    assert accounts_svc.GUEST_EMAIL in dash.text


def test_guest_login_requires_csrf():
    client.cookies.clear()
    resp = client.post("/guest-login", data={}, follow_redirects=False)
    assert resp.status_code == 403


def test_guest_reaches_owner_only_pages():
    client.cookies.clear()
    client.post("/guest-login", data={"csrf": _csrf("/login")}, follow_redirects=False)
    resp = client.get("/accounts")
    assert resp.status_code == 200
