"""H6 Slice A: Owner notification-settings screen (FR-12 D4)."""

import re
from datetime import UTC, datetime

from conftest import mock_notify_http
from fastapi.testclient import TestClient

from security_agent.app import accounts as accounts_svc
from security_agent.app.main import app
from security_agent.db.models import Role
from security_agent.notify import delete_channel, list_channels

client = TestClient(app, raise_server_exceptions=False)


def _login_as(role: Role) -> None:
    client.cookies.clear()
    email = f"set-{role.value}-{datetime.now(UTC).timestamp()}@example.com"
    user = accounts_svc.create_user(email, None, role)
    sid = accounts_svc.create_session(user.id)
    client.cookies.set("app_session", sid)


def _csrf() -> str:
    resp = client.get("/settings")
    match = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert match, "no csrf token on /settings"
    return match.group(1)


def _cleanup(channels_before: set[int]) -> None:
    for c in list_channels():
        if c["id"] not in channels_before:
            delete_channel(c["id"])


def test_settings_owner_only():
    _login_as(Role.REPORTER)
    assert client.get("/settings").status_code == 403
    _login_as(Role.OWNER)
    assert client.get("/settings").status_code == 200


def test_add_route_test_and_delete_webhook_channel():
    _login_as(Role.OWNER)
    before = {c["id"] for c in list_channels()}
    try:
        csrf = _csrf()
        resp = client.post(
            "/settings/channels",
            data={
                "csrf": csrf,
                "kind": "webhook",
                "name": "ops-hook",
                "url": "https://hooks.example.com/secret-path",
                "signing_key": "k",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200 and "created" in resp.text
        # Secrets never render back; only the host shows.
        page = client.get("/settings").text
        assert "secret-path" not in page and "hooks.example.com" in page
        added = [c for c in list_channels() if c["id"] not in before][0]
        resp = client.post(
            "/settings/routes",
            data={"csrf": _csrf(), "severity": "critical", "channel_ids": str(added["id"])},
            follow_redirects=True,
        )
        assert "saved" in resp.text
        with mock_notify_http() as fake:
            resp = client.post(
                f"/settings/channels/{added['id']}/test",
                data={"csrf": _csrf()},
                follow_redirects=True,
            )
            assert "Test message sent" in resp.text
            assert fake.call_count == 1
        resp = client.post(
            f"/settings/channels/{added['id']}/delete",
            data={"csrf": _csrf()},
            follow_redirects=True,
        )
        assert "deleted" in resp.text
    finally:
        _cleanup(before)


def test_add_channel_rejects_bad_shapes():
    _login_as(Role.OWNER)
    before = {c["id"] for c in list_channels()}
    try:
        resp = client.post(
            "/settings/channels",
            data={"csrf": _csrf(), "kind": "email", "name": "bad", "host": ""},
        )
        assert resp.status_code == 400
        assert {c["id"] for c in list_channels()} == before
    finally:
        _cleanup(before)


def test_digest_schedule_roundtrip():
    from security_agent.notify.digest import set_digest_schedule

    _login_as(Role.OWNER)
    try:
        resp = client.post(
            "/settings/digest",
            data={"csrf": _csrf(), "enabled": "on", "hour_utc": "6"},
            follow_redirects=True,
        )
        assert "Digest schedule saved" in resp.text
        resp = client.post(
            "/settings/digest", data={"csrf": _csrf(), "enabled": "on", "hour_utc": "99"}
        )
        assert resp.status_code == 400
    finally:
        set_digest_schedule(enabled=True, hour_utc=8)


def test_save_monthly_spend_cap_roundtrip():
    from sqlalchemy import delete

    from security_agent.control.cost import effective_spend_cap
    from security_agent.db.models import NotifyState
    from security_agent.db.session import session_scope

    _login_as(Role.OWNER)
    try:
        resp = client.post(
            "/settings/cost/spend-cap",
            data={"csrf": _csrf(), "cap": "250"},
            follow_redirects=True,
        )
        assert resp.status_code == 200 and "Monthly spend cap set to $250.00" in resp.text
        assert effective_spend_cap() == 250.0
        assert "Spend this month" in client.get("/settings").text
        resp = client.post("/settings/cost/spend-cap", data={"csrf": _csrf(), "cap": "-5"})
        assert resp.status_code == 400
        resp = client.post("/settings/cost/spend-cap", data={"csrf": _csrf(), "cap": "abc"})
        assert resp.status_code == 400
    finally:
        with session_scope() as db:
            db.execute(delete(NotifyState).where(NotifyState.key == "cost.spend_cap_monthly"))
