"""Auth routes: Owner-first signup, login/logout, reset, dashboard (FR-10)."""

import logging

from argon2 import PasswordHasher
from fastapi import APIRouter, Cookie, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from security_agent.app import accounts as svc
from security_agent.app import ratelimit
from security_agent.app.dependencies import (
    SESSION_COOKIE,
    get_current_user,
    make_csrf,
    require_csrf,
)
from security_agent.config import get_settings
from security_agent.db.models import User

router = APIRouter()

log = logging.getLogger(__name__)

# Dummy hash equalizes login timing for unknown emails (no enumeration oracle).
_DUMMY_HASH = PasswordHasher().hash("not-a-real-password-12")


def _session_response(user_id: int) -> RedirectResponse:
    resp = RedirectResponse("/dashboard", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE,
        svc.create_session(user_id),
        httponly=True,
        samesite="lax",
        secure=get_settings().is_prod,
        max_age=24 * 3600,
    )
    return resp


def _check_rate(request: Request, path: str) -> None:
    ip = request.client.host if request.client else "unknown"
    if not ratelimit.allow(ip, path):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Slow down.")


@router.get("/")
def index(session: str | None = Cookie(default=None, alias=SESSION_COOKIE)):
    """Landing route: dashboard for signed-in users, login for everyone else."""
    if session and svc.validate_session(session) is not None:
        return RedirectResponse("/dashboard", status_code=303)
    return RedirectResponse("/login", status_code=303)


@router.get("/signup", response_class=HTMLResponse)
def signup_form(request: Request, token: str = ""):
    from security_agent.app.main import templates

    return templates.TemplateResponse(
        request, "signup.html", {"token": token, "open": svc.user_count() == 0, "csrf": make_csrf()}
    )


@router.post("/signup", dependencies=[Depends(require_csrf)])
def signup(
    request: Request, email: str = Form(...), password: str = Form(...), token: str = Form("")
):
    _check_rate(request, "/signup")
    if svc.user_count() == 0:
        role = svc.first_user_role(0)
    else:
        invite = svc.redeem_invite(token) if token else None
        if invite is None or invite.email.lower() != email.lower():
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Invite required.")
        role = invite.role
    try:
        password_hash = svc.hash_password(password)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    user = svc.create_user(email, password_hash, role)
    return _session_response(user.id)


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, expired: str = ""):
    from security_agent.app.main import templates

    return templates.TemplateResponse(
        request, "login.html", {"csrf": make_csrf(), "expired": expired == "1"}
    )


@router.post("/login", dependencies=[Depends(require_csrf)])
def login(
    request: Request, email: str = Form(...), password: str = Form(...), totp: str = Form("")
):
    _check_rate(request, "/login")
    user = svc.get_user_by_email(email)
    stored = user.password_hash if user and user.password_hash else _DUMMY_HASH
    password_ok = svc.verify_password(stored, password)
    if user is None or user.disabled or not password_ok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials.")
    if user.totp_secret:
        if not totp or not svc.verify_totp_or_backup(user, totp):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Second factor required.")
    return _session_response(user.id)


@router.post("/guest-login", dependencies=[Depends(require_csrf)])
def guest_login(request: Request):
    """One-click demo login: always-on Owner guest session."""
    _check_rate(request, "/guest-login")
    guest = svc.ensure_guest_user()
    return _session_response(guest.id)


@router.post("/logout", dependencies=[Depends(require_csrf)])
def logout(session: str | None = Cookie(default=None, alias=SESSION_COOKIE)):
    if session:
        svc.revoke_session(session)
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@router.get("/profile", response_class=HTMLResponse)
def profile(
    request: Request,
    user: User = Depends(get_current_user),
    session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
):
    from security_agent.app.main import templates

    sessions = [
        {
            "created_at": s.created_at,
            "last_seen_at": s.last_seen_at,
            "current": s.session_id == session,
        }
        for s in svc.list_user_sessions(user.id)
    ]
    return templates.TemplateResponse(
        request,
        "profile.html",
        {
            "user": user,
            "csrf": make_csrf(),
            "sessions": sessions,
            "has_password": bool(user.password_hash),
            "totp_on": bool(user.totp_secret),
        },
    )


@router.get("/reset", response_class=HTMLResponse)
def reset_request_form(request: Request):
    from security_agent.app.main import templates

    return templates.TemplateResponse(request, "reset_request.html", {"csrf": make_csrf()})


@router.post("/reset", response_class=HTMLResponse, dependencies=[Depends(require_csrf)])
def reset_request(request: Request, email: str = Form(...)):
    from security_agent.app.main import templates

    _check_rate(request, "/reset")
    token = svc.issue_reset(email)
    if token:  # delivered by FR-13 email in Phase 5; operator-visible log for now
        log.warning(
            "Password reset for %s: %s/reset/confirm?token=%s",
            email,
            get_settings().public_url,
            token,
        )
    return templates.TemplateResponse(request, "reset_sent.html", {})


@router.get("/reset/confirm", response_class=HTMLResponse)
def reset_confirm_form(request: Request, token: str = ""):
    from security_agent.app.main import templates

    return templates.TemplateResponse(
        request, "reset_confirm.html", {"token": token, "csrf": make_csrf()}
    )


@router.post("/reset/confirm", dependencies=[Depends(require_csrf)])
def reset_confirm(token: str = Form(...), password: str = Form(...)):
    try:
        new_hash = svc.hash_password(password)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if not svc.redeem_reset(token, new_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired reset link.")
    return RedirectResponse("/login", status_code=303)


def _dashboard_context() -> dict:
    """Live control-plane counts + previews for the dashboard (FR-12)."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import func, nulls_last, or_, select

    from security_agent.db.models import (
        Approval,
        Dependency,
        DependencyStatus,
        Finding,
        FindingStatus,
        GateStatus,
        Repo,
        RunStatus,
        ScanRun,
        SecretFinding,
        SecretStatus,
        Verdict,
    )
    from security_agent.db.session import session_scope

    active = [FindingStatus.OPEN, FindingStatus.PROPOSED]
    open_secret_states = [
        SecretStatus.OPEN,
        SecretStatus.PROPOSED,
        SecretStatus.AWAITING_ROTATION,
    ]
    with session_scope() as db:
        bind = db.get_bind()
        is_sqlite = bind is not None and bind.dialect.name == "sqlite"
        day_ago = datetime.now(UTC) - timedelta(hours=24)
        sql_day_ago = day_ago.replace(tzinfo=None) if is_sqlite else day_ago
        repo_count = db.scalar(select(func.count()).select_from(Repo)) or 0
        open_findings = (
            db.scalar(
                select(func.count()).select_from(Finding).where(Finding.status.in_(active))
            )
            or 0
        )
        kev_count = (
            db.scalar(
                select(func.count())
                .select_from(Finding)
                .where(Finding.status.in_(active), Finding.kev_exploited.is_(True))
            )
            or 0
        )
        open_count = (
            db.scalar(
                select(func.count())
                .select_from(Finding)
                .where(Finding.status == FindingStatus.OPEN)
            )
            or 0
        )
        proposed_count = (
            db.scalar(
                select(func.count())
                .select_from(Finding)
                .where(Finding.status == FindingStatus.PROPOSED)
            )
            or 0
        )
        pending_approvals = (
            db.scalar(
                select(func.count())
                .select_from(Approval)
                .where(Approval.status == GateStatus.PENDING)
            )
            or 0
        )
        open_secrets = (
            db.scalar(
                select(func.count())
                .select_from(SecretFinding)
                .where(SecretFinding.status.in_(open_secret_states))
            )
            or 0
        )
        top_findings = list(
            db.scalars(
                select(Finding)
                .where(Finding.status.in_(active))
                .order_by(
                    Finding.kev_exploited.desc(),
                    nulls_last(Finding.severity_score.desc()),
                    Finding.id.desc(),
                )
                .limit(6)
            )
        )
        for finding_row in top_findings:
            db.expunge(finding_row)
        gates = list(
            db.scalars(
                select(Approval)
                .where(Approval.status == GateStatus.PENDING)
                .order_by(Approval.expires_at, Approval.id)
                .limit(5)
            )
        )
        pending_preview = []
        for gate in gates:
            repo = db.get(Repo, gate.repo_id)
            pending_preview.append(
                {
                    "id": gate.id,
                    "action": gate.action,
                    "target": gate.target,
                    "expires_at": gate.expires_at,
                    "repo_name": repo.name if repo else f"repo#{gate.repo_id}",
                }
            )
        recent_repos = list(db.scalars(select(Repo).order_by(Repo.id.desc()).limit(5)))
        for repo_row in recent_repos:
            db.expunge(repo_row)
        # Scan health: in-flight runs (parked ones surface via the cost
        # queue instead) and runs that failed in the last 24h.
        running_runs = []
        for run_row in db.scalars(
            select(ScanRun)
            .where(
                ScanRun.status.in_([RunStatus.QUEUED, RunStatus.RUNNING]),
                ScanRun.parked.is_(False),
            )
            .order_by(ScanRun.started_at.desc())
            .limit(10)
        ):
            repo = db.get(Repo, run_row.repo_id)
            running_runs.append(
                {
                    "id": run_row.id,
                    "repo_id": run_row.repo_id,
                    "repo_name": repo.name if repo else f"repo#{run_row.repo_id}",
                    "trigger": run_row.trigger,
                    "started_at": run_row.started_at,
                }
            )
        failed_runs = []
        for run_row in db.scalars(
            select(ScanRun)
            .where(
                ScanRun.status == RunStatus.FAILED,
                or_(
                    ScanRun.started_at >= sql_day_ago,
                    ScanRun.finished_at >= sql_day_ago,
                ),
            )
            .order_by(ScanRun.id.desc())
            .limit(10)
        ):
            repo = db.get(Repo, run_row.repo_id)
            failed_runs.append(
                {
                    "id": run_row.id,
                    "repo_id": run_row.repo_id,
                    "repo_name": repo.name if repo else f"repo#{run_row.repo_id}",
                    "trigger": run_row.trigger,
                    "finished_at": run_row.finished_at or run_row.started_at,
                }
            )
        # Secrets preview: live/unknown first (fail-open alerting), dead last.
        top_secrets = []
        for secret_row in db.scalars(
            select(SecretFinding)
            .where(SecretFinding.status.in_(open_secret_states))
            .order_by((SecretFinding.liveness == "dead"), SecretFinding.id.desc())
            .limit(5)
        ):
            repo = db.get(Repo, secret_row.repo_id)
            top_secrets.append(
                {
                    "repo_id": secret_row.repo_id,
                    "repo_name": repo.name if repo else f"repo#{secret_row.repo_id}",
                    "rule_id": secret_row.rule_id,
                    "path": secret_row.path,
                    "liveness": secret_row.liveness,
                    "status": secret_row.status,
                }
            )
        # Dependencies with security fixes awaiting a human decision.
        dep_actionable = [
            DependencyStatus.UPDATE_AVAILABLE,
            DependencyStatus.AWAITING_DECISION,
        ]
        deps_security_count = (
            db.scalar(
                select(func.count())
                .select_from(Dependency)
                .where(
                    Dependency.security.is_(True),
                    Dependency.status.in_(dep_actionable),
                )
            )
            or 0
        )
        deps_security_top = []
        for dep_row in db.scalars(
            select(Dependency)
            .where(
                Dependency.security.is_(True),
                Dependency.status.in_(dep_actionable),
            )
            .order_by(Dependency.id.desc())
            .limit(5)
        ):
            repo = db.get(Repo, dep_row.repo_id)
            deps_security_top.append(
                {
                    "repo_id": dep_row.repo_id,
                    "repo_name": repo.name if repo else f"repo#{dep_row.repo_id}",
                    "package": dep_row.package,
                    "installed_version": dep_row.installed_version,
                    "latest_version": dep_row.latest_version,
                    "update_class": dep_row.update_class,
                    "status": dep_row.status,
                }
            )
        # Repo names + latest reachability verdict for the top findings.
        finding_repos = {}
        for finding_row in top_findings:
            repo = db.get(Repo, finding_row.repo_id)
            finding_repos[finding_row.id] = {
                "id": finding_row.repo_id,
                "name": repo.name if repo else f"repo#{finding_row.repo_id}",
            }
        finding_reachable: dict = {f.id: None for f in top_findings}
        if top_findings:
            seen: set = set()
            for finding_id, reachable in db.execute(
                select(Verdict.finding_id, Verdict.reachable)
                .where(Verdict.finding_id.in_([f.id for f in top_findings]))
                .order_by(Verdict.id.desc())
            ).all():
                if finding_id not in seen:
                    seen.add(finding_id)
                    finding_reachable[finding_id] = reachable
        # Findings opened per day, last 7 days (area-chart series).
        today = datetime.now(UTC).date()
        days = [today - timedelta(days=6 - i) for i in range(7)]
        start = datetime.combine(days[0], datetime.min.time(), tzinfo=UTC)
        per_day = dict.fromkeys(days, 0)
        sql_start = start.replace(tzinfo=None) if is_sqlite else start
        for (created,) in db.execute(
            select(Finding.created_at).where(Finding.created_at >= sql_start)
        ).all():
            day = (created if created.tzinfo else created.replace(tzinfo=UTC)).date()
            if day in per_day:
                per_day[day] += 1

    counts = [per_day[d] for d in days]
    trend_total = sum(counts)
    peak = max(counts) if counts else 0
    xs = [60 + i * 90 for i in range(7)]
    dots = []
    for day, count, x in zip(days, counts, xs, strict=True):
        y = 150 - round(120 * count / peak) if peak else 150
        dots.append(
            {
                "x": x,
                "y": y,
                "count": count,
                "label": day.strftime("%a %b %d"),
                "short": day.strftime("%a"),
            }
        )
    trend_points = " ".join(f"{d['x']},{d['y']}" for d in dots)
    trend_area = (
        f"M {xs[0]},150 L "
        + " L ".join(f"{d['x']},{d['y']}" for d in dots)
        + f" L {xs[-1]},150 Z"
    )

    def _pct(part: int) -> int:
        return round(100 * part / open_findings) if open_findings else 0

    from security_agent.control.brain_settings import brain_status
    from security_agent.control.cost import (
        effective_run_cap,
        list_parked_runs,
        spend_cap_state,
        spend_today,
        usage_summary,
    )
    from security_agent.policy.rules import list_rules
    from security_agent.worker.news_intel import list_feed

    return {
        "repo_count": repo_count,
        "open_findings": open_findings,
        "kev_count": kev_count,
        "pending_approvals": pending_approvals,
        "open_secrets": open_secrets,
        "top_findings": top_findings,
        "finding_repos": finding_repos,
        "finding_reachable": finding_reachable,
        "pending_preview": pending_preview,
        "recent_repos": recent_repos,
        "running_runs": running_runs,
        "failed_runs": failed_runs,
        "spend_today": spend_today(),
        "run_spend_cap": effective_run_cap(),
        "brain": brain_status(),
        "ai_usage": usage_summary(),
        "spend_cap": spend_cap_state(),
        "parked_runs": list_parked_runs(),
        "top_secrets": top_secrets,
        "deps_security_count": deps_security_count,
        "deps_security_top": deps_security_top,
        "latest_news": list_feed(limit=5),
        "pending_rules": len(list_rules(status="pending")),
        "trend_total": trend_total,
        "trend_points": trend_points,
        "trend_area": trend_area,
        "trend_dots": dots,
        "breakdown": {
            "open": open_count,
            "proposed": proposed_count,
            "kev": kev_count,
            "open_pct": _pct(open_count),
            "proposed_pct": _pct(proposed_count),
            "kev_pct": _pct(kev_count),
        },
    }


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user: User = Depends(get_current_user)):
    from security_agent.app.main import templates

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"user": user, "csrf": make_csrf(), **_dashboard_context()},
    )
