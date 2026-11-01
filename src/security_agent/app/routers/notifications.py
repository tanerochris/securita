"""Dashboard notification centre: pool listing + read state (D17)."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from security_agent.app.dependencies import get_current_user, make_csrf, require_csrf
from security_agent.db.models import User

router = APIRouter(prefix="/notifications")


@router.get("", response_class=HTMLResponse)
def notification_list(request: Request, user: User = Depends(get_current_user)):
    from security_agent.app.main import templates
    from security_agent.control.notifications import list_notifications

    return templates.TemplateResponse(
        request,
        "notifications.html",
        {
            "items": list_notifications(user.id),
            "csrf": make_csrf(),
        },
    )


@router.get("/count", response_class=HTMLResponse)
def unread_badge(request: Request, user: User = Depends(get_current_user)):
    """Header badge partial, loaded async so no route needs extra context."""
    from security_agent.app.main import templates
    from security_agent.control.notifications import unread_count

    return templates.TemplateResponse(
        request, "notifications_badge.html", {"unread": unread_count(user.id)}
    )


@router.post("/{notification_id}/read", dependencies=[Depends(require_csrf)])
def mark_read(notification_id: int, user: User = Depends(get_current_user)):
    from security_agent.control.notifications import mark_read as mark

    mark(notification_id, user.id)
    return RedirectResponse("/notifications", status_code=303)


@router.post("/read-all", dependencies=[Depends(require_csrf)])
def read_all(user: User = Depends(get_current_user)):
    from security_agent.control.notifications import mark_all_read

    mark_all_read(user.id)
    return RedirectResponse("/notifications", status_code=303)
