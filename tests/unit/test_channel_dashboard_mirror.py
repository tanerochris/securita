"""Channel→dashboard mirror: sent events land in the pool (D17 follow-up)."""

from datetime import UTC, datetime
from unittest import mock

from conftest import mock_notify_http

from security_agent.app import accounts as accounts_svc
from security_agent.control import notifications as notif
from security_agent.db.models import Role
from security_agent.notify import create_channel, delete_channel, notify_event, set_routes


def _user():
    return accounts_svc.create_user(
        f"mirror-{datetime.now(UTC).timestamp()}@example.com", None, Role.OWNER
    )


def _titles(user_id):
    return {n["title"]: n for n in notif.list_notifications(user_id)}


def _webhook_channel(name):
    return create_channel("webhook", name, secret={"url": "https://hooks.example.com/agent"})


def test_sent_event_mirrors_to_pool():
    user = _user()
    title = f"approval needed {datetime.now(UTC).timestamp()}"
    ch = _webhook_channel("mirror-ok")
    set_routes("high", [ch.id])
    try:
        with mock_notify_http():
            outcome = notify_event(
                "high", title, "grant it", link="/approvals", kind="approval-request"
            )
        assert outcome["sent"] == [ch.id]
        row = _titles(user.id)[title]
        assert row["kind"] == "approval-request"
        assert row["body"] == "grant it"
        assert row["link"] == "/approvals"
        assert row["read"] is False
    finally:
        delete_channel(ch.id)


def test_unsent_event_leaves_pool_empty():
    user = _user()
    title = f"phantom {datetime.now(UTC).timestamp()}"
    set_routes("low", [])  # nothing routed: the event reaches no channel
    outcome = notify_event("low", title, "body", link="/settings", kind="cost-warn")
    assert outcome["sent"] == []
    assert title not in _titles(user.id)


def test_deps_kind_sent_without_pool_double():
    user = _user()
    title = f"3 updates {datetime.now(UTC).timestamp()}"
    ch = _webhook_channel("mirror-deps")
    set_routes("medium", [ch.id])
    try:
        with mock_notify_http():
            outcome = notify_event("medium", title, "body", kind="deps-report")
        assert outcome["sent"] == [ch.id]
        assert title not in _titles(user.id)  # deps rows originate in the pool
    finally:
        delete_channel(ch.id)


def test_mirror_failure_never_breaks_delivery():
    title = f"alert {datetime.now(UTC).timestamp()}"
    ch = _webhook_channel("mirror-fail")
    set_routes("critical", [ch.id])
    try:
        with (
            mock_notify_http(),
            mock.patch.object(notif, "push_notification", side_effect=RuntimeError("db down")),
        ):
            outcome = notify_event("critical", title, "body", kind="secret-alert")
        assert outcome["sent"] == [ch.id]
    finally:
        delete_channel(ch.id)


def test_push_link_roundtrip():
    user = _user()
    linked = notif.push_notification("secret-alert", "linked", link="/repos/1")
    plain = notif.push_notification("digest", "plain")
    by_id = {n["id"]: n for n in notif.list_notifications(user.id)}
    assert by_id[linked.id]["link"] == "/repos/1"
    assert by_id[plain.id]["link"] is None


def test_push_drops_non_path_links():
    user = _user()
    for bad in (
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "https://evil.example.com/x",
        "//evil.example.com/x",
        "repos/1",
    ):
        row = notif.push_notification("secret-alert", f"bad {bad}", link=bad)
        by_id = {n["id"]: n for n in notif.list_notifications(user.id)}
        assert by_id[row.id]["link"] is None
