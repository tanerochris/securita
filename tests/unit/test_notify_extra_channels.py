"""Discord / Telegram / PagerDuty channels: validation, delivery, settings UI."""

import re
from datetime import UTC, datetime

import pytest
from conftest import mock_notify_http
from fastapi.testclient import TestClient
from sqlalchemy import select

from security_agent.app import accounts as accounts_svc
from security_agent.app.main import app
from security_agent.db.models import EncryptedToken, Role
from security_agent.db.session import session_scope
from security_agent.notify import (
    create_channel,
    delete_channel,
    list_channels,
    notify_event,
    set_routes,
    update_channel,
)
from security_agent.notify import test_send as channel_test_send

client = TestClient(app, raise_server_exceptions=False)

DISCORD_URL = "https://discord.com/api/webhooks/123456789/abcdefgh-token"
TG_TOKEN = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
TG_CHAT = "-1001234567890"
PD_KEY = "0123456789abcdef0123456789abcdef"


def test_new_kinds_reject_bad_shapes():
    with pytest.raises(ValueError, match="https"):
        create_channel("discord", "d", secret={"url": "http://discord.com/api/webhooks/1/t"})
    with pytest.raises(ValueError, match="Discord"):
        create_channel("discord", "d", secret={"url": "https://hooks.example.com/x"})
    with pytest.raises(ValueError, match="Discord"):
        create_channel("discord", "d", secret={"url": "https://discord.com/oauth2/x"})
    with pytest.raises(ValueError, match="webhook URL"):
        create_channel("discord", "d", secret={})
    with pytest.raises(ValueError, match="bot token"):
        create_channel(
            "telegram", "t", config={"chat_id": TG_CHAT}, secret={"bot_token": "not-a-token"}
        )
    with pytest.raises(ValueError, match="bot token"):
        create_channel("telegram", "t", config={"chat_id": TG_CHAT}, secret={})
    with pytest.raises(ValueError, match="chat id"):
        create_channel(
            "telegram", "t", config={"chat_id": "bad chat!"}, secret={"bot_token": TG_TOKEN}
        )
    with pytest.raises(ValueError, match="routing key"):
        create_channel("pagerduty", "p", secret={"routing_key": "short"})
    with pytest.raises(ValueError, match="routing key"):
        create_channel("pagerduty", "p", secret={})


def test_new_channel_secrets_encrypted_and_never_listed():
    d = create_channel("discord", "sec-discord", secret={"url": DISCORD_URL})
    t = create_channel(
        "telegram", "sec-tg", config={"chat_id": TG_CHAT}, secret={"bot_token": TG_TOKEN}
    )
    p = create_channel("pagerduty", "sec-pd", secret={"routing_key": PD_KEY})
    try:
        with session_scope() as db:
            blob = " ".join(r.ciphertext or "" for r in db.scalars(select(EncryptedToken)))
        assert "abcdefgh-token" not in blob
        assert TG_TOKEN not in blob
        assert PD_KEY not in blob
        listed = {c["id"]: c for c in list_channels()}
        assert "abcdefgh-token" not in str(listed[d.id])
        assert TG_TOKEN not in str(listed[t.id])
        assert PD_KEY not in str(listed[p.id])
        assert listed[d.id]["config"] == {"host": "discord.com"}
        assert listed[t.id]["config"] == {"chat_id": TG_CHAT}
        assert listed[p.id]["config"] == {"host": "events.pagerduty.com"}
        assert listed[d.id]["has_secret"] is True
        assert listed[t.id]["has_secret"] is True
        assert listed[p.id]["has_secret"] is True
    finally:
        delete_channel(d.id)
        delete_channel(t.id)
        delete_channel(p.id)


def test_discord_delivers_content_payload():
    d = create_channel("discord", "d-deliver", secret={"url": DISCORD_URL})
    set_routes("info", [d.id])
    try:
        with mock_notify_http() as fake:
            outcome = notify_event("info", "subj-d", "body-d", kind="t")
        assert outcome["sent"] == [d.id]
        (post_url,), kwargs = fake.call_args
        assert post_url == DISCORD_URL
        content = kwargs["json"]["content"]
        assert "subj-d" in content and "body-d" in content
    finally:
        delete_channel(d.id)


def test_telegram_delivers_send_message():
    t = create_channel(
        "telegram", "t-deliver", config={"chat_id": TG_CHAT}, secret={"bot_token": TG_TOKEN}
    )
    set_routes("info", [t.id])
    try:
        with mock_notify_http() as fake:
            outcome = notify_event("info", "subj-t", "body-t", kind="t")
        assert outcome["sent"] == [t.id]
        (post_url,), kwargs = fake.call_args
        assert post_url == f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
        payload = kwargs["json"]
        assert payload["chat_id"] == TG_CHAT
        assert "subj-t" in payload["text"] and "body-t" in payload["text"]
    finally:
        delete_channel(t.id)


@pytest.mark.parametrize(
    ("severity", "want"),
    [
        ("critical", "critical"),
        ("high", "error"),
        ("medium", "warning"),
        ("low", "info"),
        ("info", "info"),
    ],
)
def test_pagerduty_maps_severity(severity, want):
    p = create_channel("pagerduty", f"pd-{severity}", secret={"routing_key": PD_KEY})
    set_routes(severity, [p.id])
    try:
        with mock_notify_http() as fake:
            outcome = notify_event(severity, f"subj-{severity}", "body", kind="t")
        assert outcome["sent"] == [p.id]
        (post_url,), kwargs = fake.call_args
        assert post_url == "https://events.pagerduty.com/v2/enqueue"
        payload = kwargs["json"]
        assert payload["routing_key"] == PD_KEY
        assert payload["event_action"] == "trigger"
        assert payload["payload"]["severity"] == want
        assert f"subj-{severity}" in payload["payload"]["summary"]
    finally:
        delete_channel(p.id)


def test_new_transports_cap_message_length():
    d = create_channel("discord", "d-cap", secret={"url": DISCORD_URL})
    t = create_channel(
        "telegram", "t-cap", config={"chat_id": TG_CHAT}, secret={"bot_token": TG_TOKEN}
    )
    set_routes("info", [d.id, t.id])
    try:
        with mock_notify_http() as fake:
            notify_event("info", "s", "x" * 200_000, kind="t")
        assert fake.call_count == 2
        seen = {call[0][0]: call[1]["json"] for call in fake.call_args_list}
        assert len(seen[DISCORD_URL]["content"]) <= 2000
        assert len(seen[f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"]["text"]) <= 4096
    finally:
        delete_channel(d.id)
        delete_channel(t.id)


def test_test_send_new_kinds_ok_and_failure():
    d = create_channel("discord", "d-ts", secret={"url": DISCORD_URL})
    t = create_channel(
        "telegram", "t-ts", config={"chat_id": TG_CHAT}, secret={"bot_token": TG_TOKEN}
    )
    p = create_channel("pagerduty", "p-ts", secret={"routing_key": PD_KEY})
    try:
        with mock_notify_http():
            assert channel_test_send(d.id)["ok"] is True
            assert channel_test_send(t.id)["ok"] is True
            assert channel_test_send(p.id)["ok"] is True
        with mock_notify_http(post_side_effect=ValueError("down")):
            assert channel_test_send(d.id)["ok"] is False
    finally:
        delete_channel(d.id)
        delete_channel(t.id)
        delete_channel(p.id)


def test_update_telegram_keeps_token_and_validates():
    import security_agent.notify as notify_mod

    t = create_channel(
        "telegram", "t-upd", config={"chat_id": TG_CHAT}, secret={"bot_token": TG_TOKEN}
    )
    try:
        update_channel(t.id, "t-upd", config={"chat_id": "@ops"}, secret={"bot_token": ""})
        assert notify_mod._load_secret(t.id) == {"bot_token": TG_TOKEN}
        listed = {c["id"]: c for c in list_channels()}
        assert listed[t.id]["config"] == {"chat_id": "@ops"}
        with pytest.raises(ValueError, match="bot token"):
            update_channel(t.id, "t-upd", config={"chat_id": "@ops"}, secret={"bot_token": "bad"})
        with pytest.raises(ValueError, match="chat id"):
            update_channel(t.id, "t-upd", config={"chat_id": "??"}, secret={"bot_token": ""})
        p = create_channel("pagerduty", "p-upd", secret={"routing_key": PD_KEY})
        try:
            update_channel(p.id, "p-upd2", secret={"routing_key": ""})
            assert notify_mod._load_secret(p.id) == {"routing_key": PD_KEY}
        finally:
            delete_channel(p.id)
    finally:
        delete_channel(t.id)


def _login_owner() -> None:
    client.cookies.clear()
    email = f"extra-{datetime.now(UTC).timestamp()}@example.com"
    user = accounts_svc.create_user(email, None, Role.OWNER)
    client.cookies.set("app_session", accounts_svc.create_session(user.id))


def _csrf() -> str:
    resp = client.get("/settings")
    match = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert match, "no csrf token on /settings"
    return match.group(1)


def test_settings_add_new_kinds_and_hide_secrets():
    _login_owner()
    before = {c["id"] for c in list_channels()}
    try:
        for kind, data in (
            ("discord", {"url": DISCORD_URL}),
            ("telegram", {"bot_token": TG_TOKEN, "chat_id": TG_CHAT}),
            ("pagerduty", {"routing_key": PD_KEY}),
        ):
            resp = client.post(
                "/settings/channels",
                data={"csrf": _csrf(), "kind": kind, "name": f"ui-{kind}", **data},
                follow_redirects=True,
            )
            assert resp.status_code == 200 and "created" in resp.text, resp.text[:500]
        page = client.get("/settings").text
        assert 'value="discord"' in page
        assert 'value="telegram"' in page
        assert 'value="pagerduty"' in page
        assert "abcdefgh-token" not in page
        assert TG_TOKEN not in page
        assert PD_KEY not in page
        assert "discord.com" in page
        assert TG_CHAT in page
        assert "events.pagerduty.com" in page
        resp = client.post(
            "/settings/channels",
            data={
                "csrf": _csrf(),
                "kind": "telegram",
                "name": "bad",
                "bot_token": "x",
                "chat_id": TG_CHAT,
            },
        )
        assert resp.status_code == 400
        assert len([c for c in list_channels() if c["id"] not in before]) == 3
    finally:
        for c in list_channels():
            if c["id"] not in before:
                delete_channel(c["id"])
