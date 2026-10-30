"""H6 Slice A: channels, routing, fan-out, digests (FR-13, FR-12 D2/D4)."""

from unittest import mock

import pytest
from conftest import mock_notify_http
from sqlalchemy import select

from security_agent.db.models import EncryptedToken
from security_agent.db.session import session_scope
from security_agent.notify import (
    SEVERITIES,
    channels_for,
    create_channel,
    delete_channel,
    list_channels,
    notify_event,
    set_channel_enabled,
    set_routes,
)
from security_agent.notify import test_send as channel_test_send


def _email_channel(name="mail"):
    return create_channel(
        "email",
        name,
        config={
            "host": "smtp.example.com",
            "port": 587,
            "username": "agent",
            "from_addr": "agent@example.com",
            "to": ["ops@example.com"],
        },
        secret={"password": "s3cret"},
    )


def _webhook_channel(name="hook"):
    return create_channel(
        "webhook", name, secret={"url": "https://hooks.example.com/agent", "signing_key": "k"}
    )


def test_create_validates_shapes():
    with pytest.raises(ValueError, match="kind"):
        create_channel("pager", "x")
    with pytest.raises(ValueError, match="email host"):
        create_channel("email", "bad", config={"host": "", "from_addr": "a@b.c", "to": ["a@b.c"]})
    with pytest.raises(ValueError, match="recipient"):
        create_channel(
            "email",
            "bad",
            config={"host": "h", "from_addr": "a@b.c", "to": ["not-an-email"]},
        )
    with pytest.raises(ValueError, match="Webhook URL"):
        create_channel("slack", "bad", secret={"url": "http://hooks.example.com/x"})
    with pytest.raises(ValueError, match="webhook URL"):
        create_channel("webhook", "bad", secret={})


def test_secrets_encrypted_and_never_listed():
    ch = _email_channel("sec-mail")
    hook = _webhook_channel("sec-hook")
    with session_scope() as db:
        rows = list(db.scalars(select(EncryptedToken)))
        assert not any("s3cret" in (r.ciphertext or "") for r in rows)
        assert not any("hooks.example.com/agent" in (r.ciphertext or "") for r in rows)
    listed = {c["id"]: c for c in list_channels()}
    assert "s3cret" not in str(listed[ch.id])
    assert "hooks.example.com/agent" not in str(listed[hook.id])
    assert listed[ch.id]["has_secret"] is True
    assert listed[hook.id]["config"] == {"host": "hooks.example.com"}
    delete_channel(ch.id)
    delete_channel(hook.id)


def test_default_routes_all_severities_until_narrowed():
    ch = _webhook_channel("route-all")
    try:
        for sev in SEVERITIES:
            assert ch.id in [c.id for c in channels_for(sev)]
        set_routes("critical", [])
        assert ch.id not in [c.id for c in channels_for("critical")]
        assert ch.id in [c.id for c in channels_for("high")]
        with pytest.raises(ValueError, match="Unknown channels"):
            set_routes("high", [999999])
        with pytest.raises(ValueError, match="Unknown severity"):
            set_routes("bogus", [ch.id])
    finally:
        delete_channel(ch.id)


def test_notify_event_routes_and_isolates_failures():
    import security_agent.notify as notify_mod

    ok_ch = _webhook_channel("ev-ok")
    bad_ch = _webhook_channel("ev-bad")
    set_routes("critical", [ok_ch.id, bad_ch.id])
    set_routes("info", [ok_ch.id])
    real_load = notify_mod._load_secret
    try:
        with mock_notify_http():
            outcome = notify_event("critical", "subj", "body", kind="t")
        assert sorted(outcome["sent"]) == sorted([ok_ch.id, bad_ch.id])
        with mock_notify_http():
            outcome = notify_event("info", "subj", "body", kind="t")
        assert outcome["sent"] == [ok_ch.id]
        # A failing channel must not break its siblings.
        with (
            mock_notify_http(),
            mock.patch.object(
                notify_mod,
                "_load_secret",
                side_effect=lambda cid: {"url": "bad://x"} if cid == bad_ch.id else real_load(cid),
            ),
        ):
            outcome = notify_event("critical", "subj", "body", kind="t")
        assert outcome["sent"] == [ok_ch.id]
        assert list(outcome["failed"]) == [bad_ch.id]
    finally:
        delete_channel(ok_ch.id)
        delete_channel(bad_ch.id)


def test_fan_out_all_ignores_routing_and_disabled():
    a = _webhook_channel("fan-a")
    b = _webhook_channel("fan-b")
    set_routes("high", [a.id])
    set_channel_enabled(b.id, False)
    try:
        assert [c.id for c in channels_for("high")] == [a.id]
        all_ids = [c.id for c in channels_for("high", fan_out_all=True)]
        assert a.id in all_ids and b.id not in all_ids  # disabled stays out
    finally:
        delete_channel(a.id)
        delete_channel(b.id)


def test_test_send_reports_ok_and_failure():
    ch = _webhook_channel("ts")
    try:
        with mock_notify_http():
            assert channel_test_send(ch.id)["ok"] is True
        with mock_notify_http(post_side_effect=ValueError("down")):
            outcome = channel_test_send(ch.id)
            assert outcome["ok"] is False and "down" in outcome["detail"]
        assert channel_test_send(999999)["ok"] is False
    finally:
        delete_channel(ch.id)


def test_email_send_uses_starttls_and_auth():
    ch = _email_channel("smtp-t")
    try:
        with mock.patch("security_agent.notify.transports.smtplib.SMTP") as fake_smtp:
            server = fake_smtp.return_value.__enter__.return_value
            assert channel_test_send(ch.id)["ok"] is True
            server.starttls.assert_called_once()
            server.login.assert_called_once_with("agent", "s3cret")
            server.send_message.assert_called_once()
    finally:
        delete_channel(ch.id)


def test_webhook_signature_header_present():
    ch = _webhook_channel("sig")
    seen = {}
    try:
        with mock_notify_http() as fake:
            notify_event("info", "s", "b", kind="t")
            _, kwargs = fake.call_args
            seen.update(kwargs.get("headers", {}))
        assert seen.get("X-Agent-Signature")
        assert len(seen["X-Agent-Signature"]) == 64
    finally:
        delete_channel(ch.id)


def test_gate_request_fans_out_to_all_channels():
    from security_agent.control import repos as repo_svc
    from security_agent.control.gates import request_gate
    from security_agent.db.models import GateAction, RepoKind

    ch = _webhook_channel("gate-fan")
    set_routes("high", [])  # routing narrowed, fan-out must still reach it
    repo = repo_svc.connect_repo("gate-fan-r", RepoKind.GIT, url="https://example.com/g.git")
    try:
        with mock_notify_http() as fake:
            request_gate(repo.id, GateAction.MERGE, "https://example.com/pr/1")
            assert fake.call_count == 1
    finally:
        delete_channel(ch.id)


def test_secret_alert_fans_out_critical():
    from security_agent.worker.secrets import notify_secret_alert

    ch = _webhook_channel("sec-fan")
    set_routes("critical", [ch.id])
    try:
        with mock_notify_http() as fake:
            notify_secret_alert(1, 1, 1, "github-token", "a/b.py")
            assert fake.call_count == 1
    finally:
        delete_channel(ch.id)
