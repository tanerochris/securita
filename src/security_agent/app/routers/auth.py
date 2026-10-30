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
def login_form(request: Request):
    from security_agent.app.main import templates

    return templates.TemplateResponse(request, "login.html", {"csrf": make_csrf()})


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


@router.post("/logout", dependencies=[Depends(require_csrf)])
def logout(session: str | None = Cookie(default=None, alias=SESSION_COOKIE)):
    if session:
        svc.revoke_session(session)
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


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

    from sqlalchemy import func, nulls_last, select

    from security_agent.db.models import (
        Approval,
        Finding,
        FindingStatus,
        GateStatus,
        Repo,
        SecretFinding,
        SecretStatus,
    )
    from security_agent.db.session import session_scope

    active = [FindingStatus.OPEN, FindingStatus.PROPOSED]
    with session_scope() as db:
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
        boosted = (
            db.scalar(
                select(func.count())
                .select_from(Finding)
                .where(Finding.status.in_(active), Finding.news_weight > 0)
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
                .where(
                    SecretFinding.status.in_(
                        [
                            SecretStatus.OPEN,
                            SecretStatus.PROPOSED,
                            SecretStatus.AWAITING_ROTATION,
                        ]
                    )
                )
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
                    Finding.news_weight.desc(),
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
        # Findings opened per day, last 7 days (area-chart series).
        today = datetime.now(UTC).date()
        days = [today - timedelta(days=6 - i) for i in range(7)]
        start = datetime.combine(days[0], datetime.min.time(), tzinfo=UTC)
        per_day = dict.fromkeys(days, 0)
        bind = db.get_bind()
        is_sqlite = bind is not None and bind.dialect.name == "sqlite"
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

    return {
        "repo_count": repo_count,
        "open_findings": open_findings,
        "kev_count": kev_count,
        "pending_approvals": pending_approvals,
        "open_secrets": open_secrets,
        "top_findings": top_findings,
        "pending_preview": pending_preview,
        "recent_repos": recent_repos,
        "trend_total": trend_total,
        "trend_points": trend_points,
        "trend_area": trend_area,
        "trend_dots": dots,
        "breakdown": {
            "open": open_count,
            "proposed": proposed_count,
            "kev": kev_count,
            "boosted": boosted,
            "open_pct": _pct(open_count),
            "proposed_pct": _pct(proposed_count),
            "kev_pct": _pct(kev_count),
            "boosted_pct": _pct(boosted),
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
