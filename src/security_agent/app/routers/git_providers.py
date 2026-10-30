"""Git provider connect routes: PAT connect, disconnect, repo picker."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from security_agent.app.dependencies import make_csrf, require_approver, require_csrf
from security_agent.control import git_providers as svc
from security_agent.db.models import GitProvider, User

router = APIRouter(prefix="/providers")


def _provider(raw: str) -> GitProvider:
    try:
        return GitProvider(raw)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown provider.") from exc


@router.post("/pat", dependencies=[Depends(require_csrf)])
def connect_pat(
    provider: str = Form(...),
    base_url: str = Form(""),
    token: str = Form(...),
    user: User = Depends(require_approver),
):
    kind = _provider(provider)
    try:
        svc.connect_pat(user.id, kind, base_url, token)
    except svc.ProviderError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return RedirectResponse("/repos", status_code=303)


@router.post("/{connection_id}/disconnect", dependencies=[Depends(require_csrf)])
def disconnect(connection_id: int, user: User = Depends(require_approver)):
    if not svc.disconnect(connection_id, user.id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown connection.")
    return RedirectResponse("/repos", status_code=303)


@router.get("/{connection_id}/repos", response_class=HTMLResponse)
def browse(request: Request, connection_id: int, user: User = Depends(require_approver)):
    from security_agent.app.main import templates

    conn = svc.get_connection(connection_id)
    if conn is None or conn.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown connection.")
    try:
        found = svc.list_provider_repos(connection_id, user.id)
    except svc.ProviderError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return templates.TemplateResponse(
        request,
        "provider_repos.html",
        {"connection": conn, "found": found, "csrf": make_csrf()},
    )
