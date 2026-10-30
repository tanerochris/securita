"""Approval queue: pending gates, decisions, merge execution, delegation (FR-9)."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from security_agent.app import accounts as accounts_svc
from security_agent.app.dependencies import (
    get_current_user,
    make_csrf,
    require_csrf,
    require_owner,
)
from security_agent.control import gates
from security_agent.db.models import Role, User

router = APIRouter(prefix="/approvals")


@router.get("", response_class=HTMLResponse)
def queue(request: Request, user: User = Depends(get_current_user)):
    from security_agent.app.main import templates

    pending = gates.list_pending_gates()
    contexts = [gates.gate_context(g) for g in pending]
    for ctx in contexts:
        ctx["can_decide"] = gates.may_decide(user, ctx["gate"].action)
    history = [gates.gate_context(g) for g in gates.list_gate_history()]
    return templates.TemplateResponse(
        request,
        "approvals.html",
        {
            "pending": contexts,
            "history": history,
            "delegations": gates.list_delegations(),
            "users": accounts_svc.list_users(),
            "csrf": make_csrf(),
            "user": user,
            "is_owner": user.role == Role.OWNER,
        },
    )


def _decide(gate_id: int, user: User, approved: bool, reason: str) -> RedirectResponse:
    try:
        gates.decide_gate(gate_id, user, approved, reason=reason)
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return RedirectResponse("/approvals", status_code=303)


@router.post("/{gate_id}/approve", dependencies=[Depends(require_csrf)])
def approve(gate_id: int, reason: str = Form(""), user: User = Depends(get_current_user)):
    return _decide(gate_id, user, True, reason)


@router.post("/{gate_id}/deny", dependencies=[Depends(require_csrf)])
def deny(gate_id: int, reason: str = Form(""), user: User = Depends(get_current_user)):
    return _decide(gate_id, user, False, reason)


@router.post("/{gate_id}/merge", dependencies=[Depends(require_csrf)])
def merge_now(gate_id: int, user: User = Depends(get_current_user)):
    try:
        gates.execute_merge(gate_id, user)
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return RedirectResponse("/approvals", status_code=303)


@router.post("/delegations", dependencies=[Depends(require_csrf)])
def delegate(
    email: str = Form(...),
    classes: str = Form(""),
    owner: User = Depends(require_owner),
):
    delegate = accounts_svc.get_user_by_email(email)
    if delegate is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown user.")
    wanted = [c.strip() for c in classes.split(",") if c.strip()] or None
    try:
        gates.delegate_approval(owner.id, delegate.id, classes=wanted)
    except (PermissionError, ValueError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return RedirectResponse("/approvals", status_code=303)


@router.post("/delegations/{delegation_id}/revoke", dependencies=[Depends(require_csrf)])
def revoke(delegation_id: int, owner: User = Depends(require_owner)):
    try:
        gates.revoke_delegation(delegation_id, owner.id)
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    return RedirectResponse("/approvals", status_code=303)
