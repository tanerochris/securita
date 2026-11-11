"""Brain provider Settings: save/load, key handling, test, model lists."""

import re
from datetime import UTC, datetime
from unittest import mock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from security_agent.app import accounts as accounts_svc
from security_agent.app.main import app
from security_agent.brain import BrainError
from security_agent.db.models import EncryptedToken, NotifyState, Role
from security_agent.db.session import session_scope

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _clean_brain_state():
    _wipe()
    yield
    _wipe()


def _wipe():
    with session_scope() as db:
        db.execute(delete(NotifyState).where(NotifyState.key.like("brain.%")))
        db.execute(delete(EncryptedToken).where(EncryptedToken.owner.like("brain:%")))


def _login_as(role: Role) -> None:
    client.cookies.clear()
    email = f"brainset-{role.value}-{datetime.now(UTC).timestamp()}@example.com"
    user = accounts_svc.create_user(email, None, role)
    sid = accounts_svc.create_session(user.id)
    client.cookies.set("app_session", sid)


def _csrf() -> str:
    resp = client.get("/settings")
    match = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert match, "no csrf token on /settings"
    return match.group(1)


def test_brain_section_renders_and_saves_as_owner():
    _login_as(Role.OWNER)
    page = client.get("/settings").text
    assert "Brain provider" in page
    assert "not configured" in page
    resp = client.post(
        "/settings/brain",
        data={
            "csrf": _csrf(),
            "strategy": "openrouter",
            "model": "x/y",
            "base_url": "",
            "price_override": "",
            "api_key": "secret-1",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200 and "Brain saved" in resp.text
    page = client.get("/settings").text
    assert "secret-1" not in page  # pasted once, never re-viewed
    assert "x/y" in page
    resp = client.post(
        "/settings/brain/key/delete",
        data={"csrf": _csrf(), "strategy": "openrouter"},
        follow_redirects=True,
    )
    assert "deleted" in resp.text


def test_brain_save_rejects_non_owner():
    _login_as(Role.MAINTAINER)
    resp = client.post(
        "/settings/brain",
        data={"csrf": _csrf(), "strategy": "openrouter", "model": "x/y"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


def test_brain_models_endpoint_serves_curated_json():
    _login_as(Role.OWNER)
    resp = client.get("/settings/brain/models", params={"strategy": "anthropic"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] == "curated"
    assert [m["id"] for m in data["models"]]


def test_brain_test_reports_probe_outcome():
    from security_agent.control.brain_settings import save_brain_config

    _login_as(Role.OWNER)
    owner = accounts_svc.create_user(
        f"braintest-{datetime.now(UTC).timestamp()}@example.com", None, Role.OWNER
    )
    save_brain_config(strategy="ollama", model="llama3", user=owner)
    with mock.patch("security_agent.brain.probe.run_probe", return_value=True):
        resp = client.post("/settings/brain/test", data={"csrf": _csrf()}, follow_redirects=True)
        assert "Brain test passed" in resp.text
    with mock.patch("security_agent.brain.probe.run_probe", side_effect=BrainError("no brain")):
        resp = client.post("/settings/brain/test", data={"csrf": _csrf()}, follow_redirects=True)
        assert "Brain test failed" in resp.text


def test_dashboard_shows_brain_empty_state():
    _login_as(Role.OWNER)
    dash = client.get("/dashboard")
    assert dash.status_code == 200
    assert "Brain not configured" in dash.text
