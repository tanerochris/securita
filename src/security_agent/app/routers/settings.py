"""Notification settings: channels, routing, test-send, digest (FR-12 D4).

Owners manage channels, routing, and the digest; Maintainers share the
cost-cap and parked-resume queue (FR-9 D7).
"""

import csv
import io

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from security_agent.app.dependencies import require_approver, require_csrf, require_owner
from security_agent.db.models import Role, User
from security_agent.notify import SEVERITIES

router = APIRouter(prefix="/settings")


def _page(request: Request, *, notice: str = "", is_owner: bool = True):
    from security_agent.app.main import templates
    from security_agent.config import get_settings
    from security_agent.control.cost import (
        effective_run_cap,
        list_parked_runs,
        spend_cap_state,
        spend_today,
    )
    from security_agent.control.deps import (
        deps_budget_state,
        deps_notify_email_enabled,
        get_dep_check_hours,
    )
    from security_agent.notify import list_channels
    from security_agent.notify.digest import get_digest_schedule

    channels = list_channels()
    routes = {c["id"]: set(c["severities"]) for c in channels}
    route_ids = {
        sev: ",".join(str(c["id"]) for c in channels if sev in routes[c["id"]])
        for sev in SEVERITIES
    }
    settings = get_settings()
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "channels": channels,
            "routes": routes,
            "route_ids": route_ids,
            "severities": SEVERITIES,
            "digest": get_digest_schedule(),
            "cap": effective_run_cap(),
            "spend": spend_today(),
            "warn_usd": settings.spend_warn_daily_usd,
            "critical_usd": settings.spend_critical_daily_usd,
            "spend_cap": spend_cap_state(),
            "parked": list_parked_runs(),
            "dep_hours": get_dep_check_hours(),
            "dep_budget": deps_budget_state(),
            "dep_email": deps_notify_email_enabled(),
            "notice": notice,
            "is_owner": is_owner,
            "csrf": __import__(
                "security_agent.app.dependencies", fromlist=["make_csrf"]
            ).make_csrf(),
        },
    )


@router.get("", response_class=HTMLResponse)
def settings(request: Request, user: User = Depends(require_approver)):
    notice = request.query_params.get("notice", "")
    return _page(request, notice=notice, is_owner=user.role == Role.OWNER)


def _summary_csv(summary: dict) -> str:
    """Flatten top findings/secrets into one CSV with a header row."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["section", "repo", "package_or_rule", "advisory_or_path", "kev", "severity", "status"]
    )
    for item in summary["top_findings"]:
        writer.writerow(
            [
                "finding",
                item["repo"],
                item["package"],
                item["advisory"],
                "yes" if item["kev"] else "",
                item["severity"] if item["severity"] is not None else "",
                item["status"],
            ]
        )
    for item in summary["top_secrets"]:
        writer.writerow(["secret", item["repo"], item["rule"], item["path"], "", "", ""])
    return buf.getvalue()


@router.get("/reports/export")
def export_reports(format: str = "json", _owner: User = Depends(require_owner)):
    """Owner-only risk snapshot download: the digest summary as JSON or CSV."""
    from security_agent.notify.digest import build_summary

    if format == "json":
        return JSONResponse(
            build_summary(),
            headers={"Content-Disposition": 'attachment; filename="reports.json"'},
        )
    if format == "csv":
        return Response(
            _summary_csv(build_summary()),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="reports.csv"'},
        )
    raise HTTPException(status.HTTP_400_BAD_REQUEST, "format must be json or csv.")


def _redirect(notice: str) -> RedirectResponse:
    from urllib.parse import quote

    return RedirectResponse(f"/settings?notice={quote(notice)}", status_code=303)


@router.post("/channels", dependencies=[Depends(require_csrf)])
def add_channel(
    kind: str = Form(...),
    name: str = Form(...),
    host: str = Form(""),
    port: str = Form("587"),
    username: str = Form(""),
    from_addr: str = Form(""),
    to: str = Form(""),
    password: str = Form(""),
    url: str = Form(""),
    signing_key: str = Form(""),
    bot_token: str = Form(""),
    chat_id: str = Form(""),
    routing_key: str = Form(""),
    _owner: User = Depends(require_owner),
):
    from security_agent.notify import create_channel

    try:
        if kind == "email":
            config = {
                "host": host,
                "port": int(port or 587),
                "username": username,
                "from_addr": from_addr,
                "to": [a.strip() for a in to.split(",") if a.strip()],
            }
            secret = {"password": password}
        elif kind in ("slack", "discord", "webhook"):
            config, secret = {}, {"url": url, "signing_key": signing_key}
        elif kind == "telegram":
            config, secret = {"chat_id": chat_id}, {"bot_token": bot_token}
        elif kind == "pagerduty":
            config, secret = {}, {"routing_key": routing_key}
        else:
            raise ValueError(f"Unknown channel kind {kind!r}.")
        channel = create_channel(kind, name, config=config, secret=secret)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect(f"Channel #{channel.id} created.")


@router.post("/channels/{channel_id}", dependencies=[Depends(require_csrf)])
def edit_channel(
    channel_id: int,
    name: str = Form(...),
    host: str = Form(""),
    port: str = Form("587"),
    username: str = Form(""),
    from_addr: str = Form(""),
    to: str = Form(""),
    password: str = Form(""),
    url: str = Form(""),
    signing_key: str = Form(""),
    bot_token: str = Form(""),
    chat_id: str = Form(""),
    routing_key: str = Form(""),
    _owner: User = Depends(require_owner),
):
    """Owner-only channel update; kind is immutable, blank secrets are kept."""
    from security_agent.notify import update_channel

    try:
        config = {
            "host": host,
            "port": int(port or 587),
            "username": username,
            "from_addr": from_addr,
            "to": [a.strip() for a in to.split(",") if a.strip()],
            "chat_id": chat_id,
        }
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email port must be a number.") from exc
    secret = {
        "password": password,
        "url": url,
        "signing_key": signing_key,
        "bot_token": bot_token,
        "routing_key": routing_key,
    }
    try:
        update_channel(channel_id, name, config=config, secret=secret)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown channel.") from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect(f"Channel #{channel_id} updated.")


@router.post("/channels/{channel_id}/delete", dependencies=[Depends(require_csrf)])
def remove_channel(channel_id: int, _owner: User = Depends(require_owner)):
    from security_agent.notify import delete_channel

    if not delete_channel(channel_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown channel.")
    return _redirect(f"Channel #{channel_id} deleted.")


@router.post("/channels/{channel_id}/toggle", dependencies=[Depends(require_csrf)])
def toggle_channel(channel_id: int, _owner: User = Depends(require_owner)):
    from security_agent.notify import list_channels, set_channel_enabled

    current = next((c for c in list_channels() if c["id"] == channel_id), None)
    if current is None or not set_channel_enabled(channel_id, not current["enabled"]):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown channel.")
    return _redirect(f"Channel #{channel_id} {'disabled' if current['enabled'] else 'enabled'}.")


@router.post("/channels/{channel_id}/test", dependencies=[Depends(require_csrf)])
def test_channel(channel_id: int, _owner: User = Depends(require_owner)):
    from security_agent.notify import test_send

    outcome = test_send(channel_id)
    return _redirect(outcome["detail"])


@router.post("/routes", dependencies=[Depends(require_csrf)])
def save_routes(
    severity: str = Form(...),
    channel_ids: str = Form(""),
    _owner: User = Depends(require_owner),
):
    from security_agent.notify import set_routes

    try:
        ids = [int(p) for p in channel_ids.split(",") if p.strip()]
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Channel ids must be numbers.") from exc
    try:
        set_routes(severity, ids)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect(f"Routes for {severity} saved.")


@router.post("/digest", dependencies=[Depends(require_csrf)])
def save_digest(
    enabled: str = Form(""),
    hour_utc: str = Form("8"),
    _owner: User = Depends(require_owner),
):
    from security_agent.notify.digest import set_digest_schedule

    try:
        set_digest_schedule(enabled=enabled == "on", hour_utc=int(hour_utc))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect("Digest schedule saved.")


@router.post("/cost/cap", dependencies=[Depends(require_csrf)])
def save_cap(cap: str = Form(...), user: User = Depends(require_approver)):
    from security_agent.control.cost import format_usd, set_run_cap

    try:
        value = set_run_cap(float(cap), user)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if value <= 0:
        return _redirect("Per-run cap disabled.")
    return _redirect(f"Per-run cap set to {format_usd(value)}.")


@router.post("/cost/spend-cap", dependencies=[Depends(require_csrf)])
def save_spend_cap(cap: str = Form(...), user: User = Depends(require_approver)):
    from security_agent.control.cost import set_spend_cap

    try:
        value = set_spend_cap(float(cap), user)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if value <= 0:
        return _redirect("Monthly spend cap disabled.")
    return _redirect(f"Monthly spend cap set to ${value:.2f}.")


@router.post("/cost/resume", dependencies=[Depends(require_csrf)])
def resume(
    run_id: str = Form(...),
    new_cap: str = Form(""),
    owner: User = Depends(require_approver),
):
    from security_agent.control.cost import format_usd, resume_run

    try:
        outcome = resume_run(
            int(run_id), owner, new_cap=float(new_cap) if new_cap.strip() else None
        )
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if outcome["cap"] > 0:
        return _redirect(f"Run {outcome['run_id']} resumed under cap {format_usd(outcome['cap'])}.")
    return _redirect(f"Run {outcome['run_id']} resumed (no per-run cap set).")


@router.post("/deps/cadence", dependencies=[Depends(require_csrf)])
def save_dep_cadence(hours: str = Form(...), user: User = Depends(require_approver)):
    """Install-wide dependency-check interval (D15); repos may override."""
    from security_agent.control.deps import set_dep_check_hours

    try:
        value = set_dep_check_hours(int(hours), user)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect(f"Dependency checks every {value}h.")


@router.post("/deps/budget", dependencies=[Depends(require_csrf)])
def save_dep_budget(cap: str = Form(...), user: User = Depends(require_approver)):
    """Separate dependency spend budget in USD (D23); parked reports resume on raise."""
    from security_agent.control.cost import format_usd
    from security_agent.control.deps import set_deps_spend_cap

    try:
        value = set_deps_spend_cap(float(cap), user)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if value <= 0:
        return _redirect("Dependency budget disabled.")
    return _redirect(f"Dependency budget set to {format_usd(value)}/24h.")


@router.post("/deps/notify", dependencies=[Depends(require_csrf)])
def save_dep_notify(enabled: str = Form(""), _owner: User = Depends(require_owner)):
    """Opt dependency pool entries into email fan-out (D16, default off)."""
    from security_agent.control.deps import set_deps_notify_email

    try:
        set_deps_notify_email(enabled == "on", _owner)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect("Dependency notification delivery saved.")
