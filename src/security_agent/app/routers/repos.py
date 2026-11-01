"""Repo + findings + patches views (FR-12)."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from security_agent.app.dependencies import (
    get_current_user,
    make_csrf,
    require_approver,
    require_csrf,
    require_developer,
    require_owner,
)
from security_agent.control import lifecycle
from security_agent.control import repos as repo_svc
from security_agent.db.models import Repo, RepoKind, Role, SecretFinding, User
from security_agent.db.session import session_scope

router = APIRouter(prefix="/repos")


def _repo_or_404(repo_id: int) -> Repo:
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        if repo is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown repo.")
        db.expunge(repo)
        return repo


@router.get("", response_class=HTMLResponse)
def repo_list(request: Request, user: User = Depends(get_current_user)):
    from security_agent.app.main import templates
    from security_agent.control import git_providers as provider_svc
    from security_agent.db.models import GitProvider

    can_manage = user.role in (Role.OWNER, Role.MAINTAINER)
    return templates.TemplateResponse(
        request,
        "repos.html",
        {
            "repos": repo_svc.list_repos(),
            "csrf": make_csrf(),
            "can_manage": can_manage,
            "notice": request.query_params.get("notice", ""),
            "connections": provider_svc.list_connections(user.id) if can_manage else [],
            "pat_scopes": {p.value: provider_svc.PAT_SCOPES[p] for p in GitProvider},
            "provider_defaults": {p.value: provider_svc.default_base_url(p) for p in GitProvider},
        },
    )


@router.post("/connect", dependencies=[Depends(require_csrf)])
def connect(
    name: str = Form(...),
    kind: str = Form(...),
    url: str = Form(""),
    local_path: str = Form(""),
    token: str = Form(""),
    connection_id: str = Form(""),
    manager: User = Depends(require_approver),
):
    linked: int | None = None
    if connection_id.strip():
        from security_agent.control import git_providers as provider_svc

        try:
            linked = int(connection_id)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Bad connection id.") from exc
        conn = provider_svc.get_connection(linked)
        if conn is None or conn.user_id != manager.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown connection.")
    try:
        repo = repo_svc.connect_repo(
            name, RepoKind(kind), url=url, local_path=local_path, token=token, connection_id=linked
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return RedirectResponse(f"/repos/{repo.id}", status_code=303)


@router.get("/{repo_id}", response_class=HTMLResponse)
def repo_detail(request: Request, repo_id: int, user: User = Depends(get_current_user)):
    from security_agent.app.main import templates

    repo = _repo_or_404(repo_id)
    active = lifecycle.list_open_findings(repo_id)
    open_secrets = lifecycle.list_open_secrets(repo_id)
    from security_agent.worker.news_intel import list_repo_news, repo_relevance_map
    from security_agent.worker.repo_profile import build_repo_profile

    repo_news = list_repo_news(repo_id)
    return templates.TemplateResponse(
        request,
        "repo.html",
        {
            "repo": repo,
            "active": active,
            "silent_count": len(lifecycle.list_silent_findings(repo_id)),
            "open_secrets": open_secrets,
            "repo_news": repo_news,
            "repo_relevance": repo_relevance_map([i.id for i in repo_news], repo_id),
            "repo_profile": build_repo_profile(repo_id),
            "proposals": lifecycle.list_repo_proposals(repo_id)[:10],
            "runs": lifecycle.list_repo_runs(repo_id),
            "csrf": make_csrf(),
            "can_scan": user.role != Role.REPORTER,
            "can_manage": user.role in (Role.OWNER, Role.MAINTAINER),
            "is_owner": user.role == Role.OWNER,
        },
    )


@router.post("/{repo_id}/disconnect", dependencies=[Depends(require_csrf)])
def disconnect(repo_id: int, _manager: User = Depends(require_approver)):
    """Disconnect a repo: local data goes, the provider repo is untouched."""
    _repo_or_404(repo_id)
    repo_svc.disconnect_repo(repo_id)
    return RedirectResponse("/repos", status_code=303)


@router.post("/{repo_id}/scan", dependencies=[Depends(require_csrf)])
def scan_now(repo_id: int, _user: User = Depends(require_developer)):
    from security_agent.worker.scheduler import trigger_manual_scan

    _repo_or_404(repo_id)
    trigger_manual_scan(repo_id)
    return RedirectResponse(f"/repos/{repo_id}", status_code=303)


@router.post("/{repo_id}/merge-token", dependencies=[Depends(require_csrf)])
def save_merge_token(repo_id: int, token: str = Form(...), _owner: User = Depends(require_owner)):
    _repo_or_404(repo_id)
    repo_svc.store_merge_token(repo_id, token)
    return RedirectResponse(f"/repos/{repo_id}", status_code=303)


@router.post("/{repo_id}/token", dependencies=[Depends(require_csrf)])
def rotate_token(repo_id: int, token: str = Form(...), _owner: User = Depends(require_owner)):
    """Rotate the provider token used for clone/push/API (GIT repos only)."""
    repo = _repo_or_404(repo_id)
    if repo.kind != RepoKind.GIT:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Local repos take no token.")
    repo_svc.store_repo_token(repo_id, token)
    return RedirectResponse(f"/repos/{repo_id}", status_code=303)


@router.post(
    "/{repo_id}/webhook-secret", response_class=HTMLResponse, dependencies=[Depends(require_csrf)]
)
def new_webhook_secret(request: Request, repo_id: int, _owner: User = Depends(require_owner)):
    from security_agent.app.main import templates

    _repo_or_404(repo_id)
    secret = repo_svc.issue_webhook_secret(repo_id)
    return templates.TemplateResponse(
        request, "secret_shown.html", {"repo_id": repo_id, "secret": secret}
    )


@router.get("/{repo_id}/findings", response_class=HTMLResponse)
def findings_view(request: Request, repo_id: int, user: User = Depends(get_current_user)):
    from security_agent.app.main import templates

    repo = _repo_or_404(repo_id)
    active = lifecycle.list_open_findings(repo_id)
    silent = lifecycle.list_silent_findings(repo_id)
    return templates.TemplateResponse(
        request,
        "findings.html",
        {
            "repo": repo,
            "active": active,
            "silent": silent,
            "secrets": lifecycle.list_repo_secrets(repo_id),
            "can_rotate": user.role in (Role.OWNER, Role.MAINTAINER),
            "csrf": make_csrf(),
        },
    )


@router.post("/{repo_id}/secrets/{secret_id}/rotated", dependencies=[Depends(require_csrf)])
def confirm_rotated(repo_id: int, secret_id: int, user: User = Depends(require_approver)):
    """Human rotation confirmation (FR-8 D7): awaiting-rotation only."""
    _repo_or_404(repo_id)
    with session_scope() as db:
        row = db.get(SecretFinding, secret_id)
        if row is None or row.repo_id != repo_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown secret finding.")
    try:
        lifecycle.mark_secret_rotated(secret_id, user)
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return RedirectResponse(f"/repos/{repo_id}/findings", status_code=303)


@router.get("/{repo_id}/patches", response_class=HTMLResponse)
def patches_view(request: Request, repo_id: int, user: User = Depends(get_current_user)):
    from security_agent.app.main import templates

    repo = _repo_or_404(repo_id)
    return templates.TemplateResponse(
        request,
        "patches.html",
        {"repo": repo, "proposals": lifecycle.list_repo_proposals(repo_id)},
    )


@router.get("/{repo_id}/runs/{run_id}", response_class=HTMLResponse)
def run_detail(request: Request, repo_id: int, run_id: int, user: User = Depends(get_current_user)):
    from security_agent.app.main import templates

    repo = _repo_or_404(repo_id)
    run = lifecycle.get_run(run_id)
    if run is None or run.repo_id != repo_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown run.")
    duration = None
    if run.started_at and run.finished_at:
        duration = (run.finished_at - run.started_at).total_seconds()
    reachable, verdicts = lifecycle.count_run_verdicts(run_id)
    usage = lifecycle.list_run_usage(run_id)
    return templates.TemplateResponse(
        request,
        "run.html",
        {
            "repo": repo,
            "run": run,
            "duration_seconds": duration,
            "findings": lifecycle.list_run_findings(run_id),
            "secrets": lifecycle.list_run_secrets(run_id),
            "reachable": reachable,
            "verdicts": verdicts,
            "usage": usage,
            "usage_tokens": sum(u.total_tokens for u in usage),
            "usage_cost": sum(u.cost_usd for u in usage),
        },
    )
