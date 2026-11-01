"""Notification centre pool: push, list, read state (D17)."""

from datetime import UTC, datetime

from security_agent.app import accounts as accounts_svc
from security_agent.control import notifications as notif
from security_agent.control import repos as repo_svc
from security_agent.db.models import RepoKind, Role


def _user(role=Role.OWNER):
    return accounts_svc.create_user(
        f"notif-{datetime.now(UTC).timestamp()}@example.com", None, role
    )


def test_push_list_unread_and_read():
    user, other = _user(), _user(Role.DEVELOPER)
    repo = repo_svc.connect_repo(
        f"notif-{datetime.now(UTC).timestamp()}", RepoKind.LOCAL, local_path="/tmp/x"
    )
    row = notif.push_notification(
        "deps-report", "3 updates", body="b", repo_id=repo.id, report_id=None
    )
    assert row.id
    assert notif.unread_count(user.id) >= 1
    items = notif.list_notifications(user.id)
    assert items[0]["title"] == "3 updates" and items[0]["read"] is False
    assert notif.mark_read(row.id, user.id) is True
    assert notif.mark_read(999999999, user.id) is False  # unknown row
    mine = {n["id"]: n for n in notif.list_notifications(user.id)}
    assert mine[row.id]["read"] is True
    theirs = {n["id"]: n for n in notif.list_notifications(other.id)}
    assert theirs[row.id]["read"] is False  # per-user state
    assert notif.mark_all_read(other.id) >= 1
    assert notif.unread_count(other.id) == 0
