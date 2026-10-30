"""PAT-only provider connect: dashboard routes (PAT, picker, no OAuth)."""

import re
from datetime import UTC, datetime
from unittest import mock

from fastapi.testclient import TestClient

from security_agent.app import accounts as accounts_svc
from security_agent.app.main import app
from security_agent.control import git_providers as svc
from security_agent.db.models import Role

client = TestClient(app, raise_server_exceptions=False)


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _login_owner() -> None:
    client.cookies.clear()
    email = f"prov-ui-{datetime.now(UTC).timestamp()}@example.com"
    user = accounts_svc.create_user(email, None, Role.OWNER)
    client.cookies.set("app_session", accounts_svc.create_session(user.id))


def _csrf(path: str = "/repos") -> str:
    resp = client.get(path)
    match = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert match, f"no csrf token on {path}"
    return match.group(1)


def test_pat_connect_browse_and_pick_repo():
    _login_owner()
    with mock.patch.object(
        svc.httpx,
        "get",
        side_effect=[
            _Resp({"id": 9, "login": "octo"}),
            _Resp(
                [
                    {
                        "full_name": "octo/api",
                        "clone_url": "https://github.com/octo/api.git",
                        "private": False,
                        "default_branch": "main",
                    }
                ]
            ),
        ],
    ) as first_get:
        resp = client.post(
            "/providers/pat",
            data={"csrf": _csrf(), "provider": "github", "base_url": "", "token": "ghp_x"},
            follow_redirects=False,
        )
        assert resp.status_code == 303, first_get
        page = client.get("/repos")
        assert "octo" in page.text and "Connected accounts" in page.text

        conn_id = svc.list_connections(_current_user_id())[0].id
        browse = client.get(f"/providers/{conn_id}/repos")
        assert browse.status_code == 200 and "octo/api" in browse.text
        pick_csrf = re.search(r'name="csrf" value="([^"]+)"', browse.text)
        assert pick_csrf

        resp = client.post(
            "/repos/connect",
            data={
                "csrf": pick_csrf.group(1),
                "kind": "git",
                "name": "octo/api",
                "url": "https://github.com/octo/api.git",
                "connection_id": str(conn_id),
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303 and resp.headers["location"].startswith("/repos/")


def _current_user_id() -> int:
    from security_agent.app.dependencies import SESSION_COOKIE

    sid = client.cookies.get(SESSION_COOKIE)
    user = accounts_svc.validate_session(sid)
    assert user is not None
    return user.id


def test_oauth_routes_do_not_exist():
    _login_owner()
    for path in ("/providers/github/start", "/providers/gitlab/callback"):
        resp = client.get(path, follow_redirects=False)
        assert resp.status_code in (404, 405), (path, resp.status_code)
    page = client.get("/repos")
    assert "Connect GitHub" not in page.text and "OAuth (recommended)" not in page.text
    assert "Connect with a personal access token" in page.text
