"""Owner account admin: invite-only, disable-only, last-Owner guard (FR-10)."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from security_agent.app import accounts as svc
from security_agent.app.dependencies import require_csrf, require_owner
from security_agent.db.models import Role, User

router = APIRouter(prefix="/accounts")


def _csrf() -> str:
    from security_agent.app.dependencies import make_csrf

    return make_csrf()


@router.get("", response_class=HTMLResponse)
def list_accounts(request: Request, _owner: User = Depends(require_owner)):
    from security_agent.app.main import templates

    return templates.TemplateResponse(
        request, "accounts.html", {"users": svc.list_users(), "csrf": _csrf()}
    )


@router.post("/invite", response_class=HTMLResponse, dependencies=[Depends(require_csrf)])
def invite(
    request: Request,
    email: str = Form(...),
    role: str = Form(...),
    _owner: User = Depends(require_owner),
):
    from security_agent.app.main import templates

    token = svc.issue_invite(email, Role(role))
    return templates.TemplateResponse(
        request, "invite_shown.html", {"email": email, "token": token}
    )


@router.post("/{user_id}/disable", dependencies=[Depends(require_csrf)])
def disable(user_id: int, _owner: User = Depends(require_owner)):
    try:
        svc.disable_user(user_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return RedirectResponse("/accounts", status_code=303)


@router.post("/{user_id}/role", dependencies=[Depends(require_csrf)])
def change_role(user_id: int, role: str = Form(...), _owner: User = Depends(require_owner)):
    try:
        svc.set_role(user_id, Role(role))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return RedirectResponse("/accounts", status_code=303)
