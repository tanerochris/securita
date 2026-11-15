"""Agent provider Settings: save/load, key handling, test, model lists."""

import re
from datetime import UTC, datetime
from unittest import mock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from security_agent.agent import AgentError
from security_agent.app import accounts as accounts_svc
from security_agent.app.main import app
from security_agent.db.models import EncryptedToken, NotifyState, Role
from security_agent.db.session import session_scope

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _clean_agent_state():
    _wipe()
    yield
    _wipe()


def _wipe():
    with session_scope() as db:
        db.execute(delete(NotifyState).where(NotifyState.key.like("agent.%")))
        db.execute(delete(EncryptedToken).where(EncryptedToken.owner.like("agent:%")))


def _login_as(role: Role) -> None:
    client.cookies.clear()
    email = f"agentset-{role.value}-{datetime.now(UTC).timestamp()}@example.com"
    user = accounts_svc.create_user(email, None, role)
    sid = accounts_svc.create_session(user.id)
    client.cookies.set("app_session", sid)


def _csrf() -> str:
    resp = client.get("/settings/agent")
    match = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert match, "no csrf token on /settings/agent"
    return match.group(1)


def test_agent_section_renders_and_saves_as_owner():
    _login_as(Role.OWNER)
    page = client.get("/settings/agent").text
    assert "Agent provider" in page
    assert "not configured" in page
    assert 'role="tablist"' in page and "agentPanelProvider" in page
    assert "agentPanelModel" in page and 'role="tooltip"' in page
    assert 'id="agentBaseWrap"' in page and '"base_url_mode": "required"' in page
    assert 'role="combobox"' in page and 'id="agentModelBox"' in page
    assert 'id="agentModelsData"' in page and "datalist" not in page
    assert 'id="agentStrategyBox"' in page and 'id="agentStrategiesData"' in page
    assert 'id="agentStrategyKey" name="strategy"' in page
    assert "DeepSeek (native)" in page
    resp = client.post(
        "/settings/agent",
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
    assert resp.status_code == 200 and "Agent saved" in resp.text
    page = client.get("/settings/agent").text
    assert "secret-1" not in page  # pasted once, never re-viewed
    assert "x/y" in page
    resp = client.post(
        "/settings/agent/key/delete",
        data={"csrf": _csrf(), "strategy": "openrouter"},
        follow_redirects=True,
    )
    assert "deleted" in resp.text


def test_agent_key_masks_immediately_after_save():
    _login_as(Role.OWNER)
    key = "sk-or-v1-83eabcdefghijklmnd776"
    resp = client.post(
        "/settings/agent",
        data={"csrf": _csrf(), "strategy": "openrouter", "model": "x/y", "api_key": key},
        follow_redirects=True,
    )
    assert resp.status_code == 200 and "Agent saved" in resp.text
    assert key not in resp.text  # masked immediately, no reveal step
    assert "sk-or-v1-83e••••••••d776" in resp.text
    assert 'id="agentKeyCopy"' in resp.text
    assert 'id="agentKeyEdit"' in resp.text and 'id="agentKeyView"' in resp.text
    fresh = client.get("/settings/agent").text
    assert key not in fresh
    assert "sk-or-v1-83e••••••••d776" in fresh


def test_agent_key_copy_returns_key_once_for_owner():
    _login_as(Role.OWNER)
    key = "sk-or-v1-copytestkey0000000000000001"
    client.post(
        "/settings/agent",
        data={"csrf": _csrf(), "strategy": "openrouter", "model": "x/y", "api_key": key},
        follow_redirects=False,
    )
    resp = client.post(
        "/settings/agent/key/copy",
        data={"csrf": _csrf(), "strategy": "openrouter"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"key": key}
    page = client.get("/settings/agent").text
    assert key not in page  # copy never renders the key into the page
    assert page.count('name="api_key"') == 1  # one key field, swapped by icons
    assert 'id="agentKeyCopy"' in page and 'id="agentKeyEdit"' in page
    assert 'id="agentKeyView"' in page
    resp = client.post(
        "/settings/agent/key/copy",
        data={"csrf": _csrf(), "strategy": "vercel"},
    )
    assert resp.status_code == 404
    _login_as(Role.MAINTAINER)
    resp = client.post(
        "/settings/agent/key/copy",
        data={"csrf": _csrf(), "strategy": "openrouter"},
    )
    assert resp.status_code == 403


def test_agent_save_without_model_shows_no_model_state():
    _login_as(Role.OWNER)
    resp = client.post(
        "/settings/agent",
        data={"csrf": _csrf(), "strategy": "custom", "model": ""},
        follow_redirects=True,
    )
    assert resp.status_code == 200 and "Agent saved" in resp.text
    assert "No model yet." in resp.text
    assert "no model" in resp.text
    resp = client.post(
        "/settings/agent",
        data={"csrf": _csrf(), "strategy": "custom", "model": "m1"},
        follow_redirects=True,
    )
    assert "No model yet." not in resp.text
    assert "m1" in resp.text


def test_agent_save_rejects_non_owner():
    _login_as(Role.MAINTAINER)
    resp = client.post(
        "/settings/agent",
        data={"csrf": _csrf(), "strategy": "openrouter", "model": "x/y"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


def test_agent_models_endpoint_serves_curated_json():
    _login_as(Role.OWNER)
    resp = client.get("/settings/agent/models", params={"strategy": "anthropic"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] == "curated"
    assert [m["id"] for m in data["models"]]


def test_agent_test_reports_probe_outcome():
    from security_agent.control.agent_settings import save_agent_config

    _login_as(Role.OWNER)
    owner = accounts_svc.create_user(
        f"agenttest-{datetime.now(UTC).timestamp()}@example.com", None, Role.OWNER
    )
    save_agent_config(strategy="ollama", model="llama3", user=owner)
    with mock.patch("security_agent.agent.probe.run_probe", return_value=True):
        resp = client.post("/settings/agent/test", data={"csrf": _csrf()}, follow_redirects=True)
        assert "Agent test passed" in resp.text
    with mock.patch("security_agent.agent.probe.run_probe", side_effect=AgentError("no agent")):
        resp = client.post("/settings/agent/test", data={"csrf": _csrf()}, follow_redirects=True)
        assert "Agent test failed" in resp.text


def test_dashboard_shows_agent_empty_state():
    _login_as(Role.OWNER)
    dash = client.get("/dashboard")
    assert dash.status_code == 200
    assert "Agent not configured" in dash.text
