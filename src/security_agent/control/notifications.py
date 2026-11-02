"""Dashboard notification centre pool (D16/D17).

Stored (unread/read, per user, linked to repo and report) with a header
icon + listing. Dependency events (new combined report, patch result
after an approved update, check failure) originate here; every other
channel event mirrors in from `notify_event` once it is actually sent,
so the pool matches the channel stream.

Dependency rows are dashboard-only by default; whether they also fan
out by email is a per-install opt-in on the Settings page (D16).
"""

import logging
from datetime import UTC, datetime

from sqlalchemy import select

from security_agent.db.models import DashboardNotification, NotificationRead
from security_agent.db.session import session_scope

log = logging.getLogger(__name__)

KINDS = ("deps-report", "deps-patch", "deps-failure")


def _safe_link(link: str | None) -> str | None:
    """Internal dashboard paths only; anything else renders unlinkable.

    The listing interpolates this into an href, so non-path values
    (javascript:, data:, absolute http(s), protocol-relative //) are
    dropped rather than stored.
    """
    if not link or not link.startswith("/") or link.startswith("//"):
        return None
    return link[:500]


def push_notification(
    kind: str,
    title: str,
    *,
    body: str = "",
    repo_id: int | None = None,
    report_id: int | None = None,
    check_id: int | None = None,
    link: str | None = None,
) -> DashboardNotification:
    """Append one pool record; dependency email fan-out stays opt-in (D16).

    `link` is a dashboard path for mirrored channel events; dependency
    rows leave it empty and link via repo/report instead.
    """
    with session_scope() as db:
        row = DashboardNotification(
            kind=kind[:50],
            title=title[:300],
            body=body or None,
            repo_id=repo_id,
            report_id=report_id,
            check_id=check_id,
            link=_safe_link(link),
        )
        db.add(row)
        db.flush()
        db.expunge(row)
    if kind in KINDS:
        from security_agent.control.deps import deps_notify_outbound_enabled

        if deps_notify_outbound_enabled():
            from security_agent.notify import notify_event

            link = f"/repos/{repo_id}/dependencies" if repo_id else "/repos"
            if report_id and repo_id:
                link = f"/repos/{repo_id}/dependencies/report/{report_id}"
            try:
                notify_event(
                    "medium",
                    f"dependencies: {title[:200]}",
                    body or title,
                    link=link,
                    kind=kind,
                )
            except Exception as exc:  # noqa: BLE001 - outbound never breaks the pool write
                log.warning("dependency email fan-out failed: %s", exc)
    return row


def list_notifications(user_id: int, *, limit: int = 50) -> list[dict]:
    """Newest-first pool rows with per-user read state."""
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(DashboardNotification)
                .order_by(DashboardNotification.id.desc())
                .limit(limit)
            )
        )
        read_ids = set(
            db.scalars(
                select(NotificationRead.notification_id).where(
                    NotificationRead.user_id == user_id,
                    NotificationRead.notification_id.in_([r.id for r in rows]),
                )
            )
        )
        out = [
            {
                "id": r.id,
                "kind": r.kind,
                "repo_id": r.repo_id,
                "report_id": r.report_id,
                "check_id": r.check_id,
                "title": r.title,
                "body": r.body,
                "link": r.link,
                "created_at": r.created_at,
                "read": r.id in read_ids,
            }
            for r in rows
        ]
        for r in rows:
            db.expunge(r)
        return out


def unread_count(user_id: int) -> int:
    """Pool rows without a read marker for this user (header badge)."""
    from sqlalchemy import func

    with session_scope() as db:
        read = select(NotificationRead.notification_id).where(
            NotificationRead.user_id == user_id
        )
        return int(
            db.scalar(
                select(func.count())
                .select_from(DashboardNotification)
                .where(DashboardNotification.id.notin_(read))
            )
            or 0
        )


def mark_read(notification_id: int, user_id: int) -> bool:
    """Record a read; idempotent, False when the row is unknown."""
    from sqlalchemy.exc import IntegrityError

    with session_scope() as db:
        if db.get(DashboardNotification, notification_id) is None:
            return False
        try:
            with db.begin_nested():
                db.add(
                    NotificationRead(
                        notification_id=notification_id,
                        user_id=user_id,
                        read_at=datetime.now(UTC),
                    )
                )
                db.flush()
        except IntegrityError:
            pass
        return True


def mark_all_read(user_id: int) -> int:
    """Mark every unread pool row read for this user (one bulk insert)."""
    from sqlalchemy import insert

    with session_scope() as db:
        already = select(NotificationRead.notification_id).where(
            NotificationRead.user_id == user_id
        )
        ids = list(
            db.scalars(
                select(DashboardNotification.id).where(
                    DashboardNotification.id.notin_(already)
                )
            )
        )
        if not ids:
            return 0
        now = datetime.now(UTC)
        db.execute(
            insert(NotificationRead),
            [
                {"notification_id": nid, "user_id": user_id, "read_at": now}
                for nid in ids
            ],
        )
        return len(ids)
