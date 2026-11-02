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
    run = trigger_manual_scan(repo_id)
    return RedirectResponse(f"/repos/{repo_id}/runs/{run.id}", status_code=303)


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


def _dependencies_page(request: Request, repo_id: int, user: User, *, notice: str = ""):
    from security_agent.app.main import templates
    from security_agent.control import deps as deps_svc
    from security_agent.db.models import DependencyCheck

    repo = _repo_or_404(repo_id)
    rows = deps_svc.list_repo_dependencies(repo_id)
    grouped: list[tuple[str, list]] = []
    for row in rows:
        if grouped and grouped[-1][0] == row.manifest_path:
            grouped[-1][1].append(row)
        else:
            grouped.append((row.manifest_path, [row]))
    with session_scope() as db:
        from sqlalchemy import select

        checks = list(
            db.scalars(
                select(DependencyCheck)
                .where(DependencyCheck.repo_id == repo_id)
                .order_by(DependencyCheck.id.desc())
                .limit(10)
            )
        )
        for c in checks:
            db.expunge(c)
    latest = deps_svc.latest_report(repo_id)
    anchors: dict[str, str] = {}
    if latest is not None:
        for section in latest.sections or []:
            if section.get("key") and section.get("anchor"):
                anchors[section["key"]] = section["anchor"]
    cap_note = ""
    if checks and checks[0].manifests is not None:
        failed = [m for m in checks[0].manifests if m.get("status") != "ok"]
        if failed:
            cap_note = "; ".join(
                f"{m.get('manifest')}: {m.get('error', 'check failed')}" for m in failed
            )
    truncated_note = ""
    if checks and checks[0].notes and "capped" in (checks[0].notes or ""):
        truncated_note = "Manifest walk hit the safety cap; some manifests were not checked."
    return templates.TemplateResponse(
        request,
        "dependencies.html",
        {
            "repo": repo,
            "grouped": grouped,
            "report": latest,
            "anchors": anchors,
            "checks": checks,
            "cap_note": cap_note,
            "truncated_note": truncated_note,
            "interval": deps_svc.effective_dep_interval(repo),
            "override": repo.dep_schedule_hours,
            "global_hours": deps_svc.get_dep_check_hours(),
            "budget": deps_svc.deps_budget_state(),
            "notice": notice,
            "csrf": make_csrf(),
            "can_check": user.role != Role.REPORTER,
            "can_decide": user.role in (Role.OWNER, Role.MAINTAINER),
        },
    )


@router.get("/{repo_id}/dependencies", response_class=HTMLResponse)
def dependencies_view(request: Request, repo_id: int, user: User = Depends(get_current_user)):
    return _dependencies_page(
        request, repo_id, user, notice=request.query_params.get("notice", "")
    )


@router.post("/{repo_id}/dependencies/check", dependencies=[Depends(require_csrf)])
def dependencies_check(repo_id: int, _user: User = Depends(require_developer)):
    from security_agent.db.models import RunTrigger
    from security_agent.worker.deps_check import enqueue_dependency_check

    _repo_or_404(repo_id)
    enqueue_dependency_check(repo_id, RunTrigger.MANUAL)
    return RedirectResponse(f"/repos/{repo_id}/dependencies", status_code=303)


@router.post("/{repo_id}/dependencies/report", dependencies=[Depends(require_csrf)])
def dependencies_force_report(repo_id: int, _user: User = Depends(require_developer)):
    """Manual "Generate report": forces a combined report on the next check run."""
    from security_agent.db.models import RunTrigger
    from security_agent.worker.deps_check import enqueue_dependency_check

    _repo_or_404(repo_id)
    enqueue_dependency_check(repo_id, RunTrigger.MANUAL, notes="force-report")
    return RedirectResponse(f"/repos/{repo_id}/dependencies", status_code=303)


@router.get("/{repo_id}/dependencies/report/latest", response_class=HTMLResponse)
def dependencies_latest_report(
    request: Request, repo_id: int, user: User = Depends(get_current_user)
):
    from security_agent.control import deps as deps_svc

    _repo_or_404(repo_id)
    report = deps_svc.latest_report(repo_id)
    if report is None:
        return _dependencies_page(request, repo_id, user, notice="No impact report yet.")
    return _report_page(request, repo_id, user, report.id)


@router.get("/{repo_id}/dependencies/report/{report_id}", response_class=HTMLResponse)
def dependencies_report_view(
    request: Request, repo_id: int, report_id: int, user: User = Depends(get_current_user)
):
    return _report_page(request, repo_id, user, report_id)


def _report_page(request: Request, repo_id: int, user: User, report_id: int):
    from security_agent.app.main import templates
    from security_agent.control import deps as deps_svc

    repo = _repo_or_404(repo_id)
    report = deps_svc.get_report(report_id)
    if report is None or report.repo_id != repo_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown report.")
    decider = None
    if report.decided_by is not None:
        with session_scope() as db:
            decider = db.get(User, report.decided_by)
            if decider is not None:
                db.expunge(decider)
    return templates.TemplateResponse(
        request,
        "dep_report.html",
        {
            "repo": repo,
            "report": report,
            "decider": decider,
            "csrf": make_csrf(),
            "can_decide": user.role in (Role.OWNER, Role.MAINTAINER),
            "notice": request.query_params.get("notice", ""),
        },
    )


@router.post(
    "/{repo_id}/dependencies/report/{report_id}/decide", dependencies=[Depends(require_csrf)]
)
def dependencies_decide(
    repo_id: int,
    report_id: int,
    included: list[str] = Form(default=[]),
    reason: str = Form(""),
    user: User = Depends(require_approver),
):
    """One decision on the combined report: ticked go to patching (D7/D10)."""
    from security_agent.control import deps as deps_svc

    _repo_or_404(repo_id)
    try:
        deps_svc.decide_report(report_id, user, included, reason=reason, repo_id=repo_id)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return RedirectResponse(
        f"/repos/{repo_id}/dependencies/report/{report_id}", status_code=303
    )


@router.post("/{repo_id}/dependencies/{dep_id}/decline", dependencies=[Depends(require_csrf)])
def dependencies_decline(
    repo_id: int, dep_id: int, reason: str = Form(""), user: User = Depends(require_approver)
):
    from security_agent.control import deps as deps_svc

    _repo_or_404(repo_id)
    try:
        deps_svc.decline_version(dep_id, user, reason=reason, repo_id=repo_id)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return RedirectResponse(f"/repos/{repo_id}/dependencies", status_code=303)


@router.post("/{repo_id}/dependencies/{dep_id}/ignore", dependencies=[Depends(require_csrf)])
def dependencies_ignore(
    repo_id: int, dep_id: int, reason: str = Form(""), user: User = Depends(require_approver)
):
    from security_agent.control import deps as deps_svc

    _repo_or_404(repo_id)
    try:
        deps_svc.ignore_package(dep_id, user, reason=reason, repo_id=repo_id)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return RedirectResponse(f"/repos/{repo_id}/dependencies", status_code=303)


@router.post("/{repo_id}/dependencies/{dep_id}/unignore", dependencies=[Depends(require_csrf)])
def dependencies_unignore(repo_id: int, dep_id: int, user: User = Depends(require_approver)):
    from security_agent.control import deps as deps_svc

    _repo_or_404(repo_id)
    try:
        deps_svc.unignore_package(dep_id, user, repo_id=repo_id)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return RedirectResponse(f"/repos/{repo_id}/dependencies", status_code=303)


@router.post("/{repo_id}/dependencies/cadence", dependencies=[Depends(require_csrf)])
def dependencies_cadence(
    repo_id: int,
    mode: str = Form(...),
    hours: str = Form("24"),
    user: User = Depends(require_approver),
):
    """Per-repo cadence override: inherit, never, or every N hours (D15)."""
    from security_agent.control import deps as deps_svc

    _repo_or_404(repo_id)
    try:
        if mode == "inherit":
            value = None
        elif mode == "never":
            value = 0
        elif mode == "hours":
            value = int(hours)
            if value < 1:
                raise ValueError("Interval must be at least 1 hour.")
        else:
            raise ValueError("Unknown cadence mode.")
        deps_svc.set_repo_dep_interval(repo_id, value, user)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return RedirectResponse(f"/repos/{repo_id}/dependencies", status_code=303)


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
