"""Settings: agent, channels, routing, test-send, digest (FR-12 D4).

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


def _context(*, notice: str = "", is_owner: bool = True, section: str = "agent") -> dict:
    from security_agent.agent.providers import (
        NATIVE_PRICE_TABLE_VERSION,
        STRATEGIES,
        STRATEGY_ORDER,
    )
    from security_agent.config import get_settings
    from security_agent.control.agent_settings import agent_status, list_models
    from security_agent.control.cost import (
        chat_spend_today,
        effective_chat_cap,
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
    agent = agent_status()
    agent_models = list_models(agent["strategy"], base_url=agent["base_url"], refresh=False)
    return {
        "section": section,
        "agent": agent,
        "agent_models": agent_models,
        "agent_strategies": [
            {
                "key": s.key,
                "label": s.label,
                "blurb": s.blurb,
                "needs_key": s.needs_key,
                "default_base_url": s.default_base_url,
                "base_url_mode": s.base_url_mode,
            }
            for k in STRATEGY_ORDER
            for s in [STRATEGIES[k]]
        ],
        "native_price_version": NATIVE_PRICE_TABLE_VERSION,
        "channels": channels,
        "routes": routes,
        "route_ids": route_ids,
        "severities": SEVERITIES,
        "digest": get_digest_schedule(),
        "cap": effective_run_cap(),
        "spend": spend_today(),
        "chat_cap": effective_chat_cap(),
        "chat_spend": chat_spend_today(),
        "warn_usd": settings.spend_warn_daily_usd,
        "critical_usd": settings.spend_critical_daily_usd,
        "spend_cap": spend_cap_state(),
        "parked": list_parked_runs(),
        "dep_hours": get_dep_check_hours(),
        "dep_budget": deps_budget_state(),
        "dep_email": deps_notify_email_enabled(),
        "notice": notice,
        "is_owner": is_owner,
        "csrf": __import__("security_agent.app.dependencies", fromlist=["make_csrf"]).make_csrf(),
    }


def _render(request: Request, section: str, *, notice: str = "", is_owner: bool = True):
    from security_agent.app.main import templates

    return templates.TemplateResponse(
        request,
        f"settings_{section}.html",
        _context(notice=notice, is_owner=is_owner, section=section),
    )


@router.get("", response_class=HTMLResponse)
def settings(user: User = Depends(require_approver)):
    return RedirectResponse("/settings/agent", status_code=303)


@router.get("/agent", response_class=HTMLResponse)
def settings_agent(request: Request, user: User = Depends(require_approver)):
    notice = request.query_params.get("notice", "")
    return _render(request, "agent", notice=notice, is_owner=user.role == Role.OWNER)


@router.get("/notifications", response_class=HTMLResponse)
def settings_notifications(request: Request, user: User = Depends(require_approver)):
    notice = request.query_params.get("notice", "")
    return _render(request, "notifications", notice=notice, is_owner=user.role == Role.OWNER)


@router.get("/reports", response_class=HTMLResponse)
def settings_reports(request: Request, _owner: User = Depends(require_owner)):
    notice = request.query_params.get("notice", "")
    return _render(request, "reports", notice=notice, is_owner=True)


@router.get("/cost", response_class=HTMLResponse)
def settings_cost(request: Request, user: User = Depends(require_approver)):
    notice = request.query_params.get("notice", "")
    return _render(request, "cost", notice=notice, is_owner=user.role == Role.OWNER)


@router.get("/dependencies", response_class=HTMLResponse)
def settings_dependencies(request: Request, user: User = Depends(require_approver)):
    notice = request.query_params.get("notice", "")
    return _render(request, "dependencies", notice=notice, is_owner=user.role == Role.OWNER)


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


def _redirect(notice: str, section: str) -> RedirectResponse:
    from urllib.parse import quote

    return RedirectResponse(f"/settings/{section}?notice={quote(notice)}", status_code=303)


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
    return _redirect(f"Channel #{channel.id} created.", "notifications")


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
    return _redirect(f"Channel #{channel_id} updated.", "notifications")


@router.post("/channels/{channel_id}/delete", dependencies=[Depends(require_csrf)])
def remove_channel(channel_id: int, _owner: User = Depends(require_owner)):
    from security_agent.notify import delete_channel

    if not delete_channel(channel_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown channel.")
    return _redirect(f"Channel #{channel_id} deleted.", "notifications")


@router.post("/channels/{channel_id}/toggle", dependencies=[Depends(require_csrf)])
def toggle_channel(channel_id: int, _owner: User = Depends(require_owner)):
    from security_agent.notify import list_channels, set_channel_enabled

    current = next((c for c in list_channels() if c["id"] == channel_id), None)
    if current is None or not set_channel_enabled(channel_id, not current["enabled"]):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown channel.")
    verb = "disabled" if current["enabled"] else "enabled"
    return _redirect(f"Channel #{channel_id} {verb}.", "notifications")


@router.post("/channels/{channel_id}/test", dependencies=[Depends(require_csrf)])
def test_channel(channel_id: int, _owner: User = Depends(require_owner)):
    from security_agent.notify import test_send

    outcome = test_send(channel_id)
    return _redirect(outcome["detail"], "notifications")


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
    return _redirect(f"Routes for {severity} saved.", "notifications")


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
    return _redirect("Digest schedule saved.", "notifications")


@router.post("/cost/cap", dependencies=[Depends(require_csrf)])
def save_cap(cap: str = Form(...), user: User = Depends(require_approver)):
    from security_agent.control.cost import format_usd, set_run_cap

    try:
        value = set_run_cap(float(cap), user)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if value <= 0:
        return _redirect("Per-run cap disabled.", "cost")
    return _redirect(f"Per-run cap set to {format_usd(value)}.", "cost")


@router.post("/cost/spend-cap", dependencies=[Depends(require_csrf)])
def save_spend_cap(cap: str = Form(...), user: User = Depends(require_approver)):
    from security_agent.control.cost import set_spend_cap

    try:
        value = set_spend_cap(float(cap), user)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if value <= 0:
        return _redirect("Monthly spend cap disabled.", "cost")
    return _redirect(f"Monthly spend cap set to ${value:.2f}.", "cost")


@router.post("/cost/chat-cap", dependencies=[Depends(require_csrf)])
def save_chat_cap(cap: str = Form(...), user: User = Depends(require_approver)):
    from security_agent.control.cost import set_chat_cap

    try:
        value = set_chat_cap(float(cap), user)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if value <= 0:
        return _redirect("Chat daily cap disabled.", "cost")
    return _redirect(f"Chat daily cap set to ${value:.2f}.", "cost")


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
        cap = format_usd(outcome["cap"])
        return _redirect(f"Run {outcome['run_id']} resumed under cap {cap}.", "cost")
    return _redirect(f"Run {outcome['run_id']} resumed (no per-run cap set).", "cost")


@router.post("/deps/cadence", dependencies=[Depends(require_csrf)])
def save_dep_cadence(hours: str = Form(...), user: User = Depends(require_approver)):
    """Install-wide dependency-check interval (D15); repos may override."""
    from security_agent.control.deps import set_dep_check_hours

    try:
        value = set_dep_check_hours(int(hours), user)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect(f"Dependency checks every {value}h.", "dependencies")


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
        return _redirect("Dependency budget disabled.", "dependencies")
    return _redirect(f"Dependency budget set to {format_usd(value)}/24h.", "dependencies")


@router.post("/deps/notify", dependencies=[Depends(require_csrf)])
def save_dep_notify(enabled: str = Form(""), _owner: User = Depends(require_owner)):
    """Opt dependency pool entries into email fan-out (D16, default off)."""
    from security_agent.control.deps import set_deps_notify_email

    try:
        set_deps_notify_email(enabled == "on", _owner)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect("Dependency notification delivery saved.", "dependencies")


@router.get("/agent/models")
def agent_models(strategy: str = "", base_url: str = "", _user: User = Depends(require_approver)):
    """Model options for one strategy (live, cached, or curated + free text)."""
    from security_agent.control.agent_settings import list_models

    return JSONResponse(list_models(strategy, base_url=base_url))


@router.post("/agent", dependencies=[Depends(require_csrf)])
def save_agent(
    strategy: str = Form(...),
    model: str = Form(""),
    base_url: str = Form(""),
    price_override: str = Form(""),
    api_key: str = Form(""),
    owner: User = Depends(require_owner),
):
    """Owner-only agent save. Stores as-is (D5): no probe on save — use Test."""
    from security_agent.control.agent_settings import save_agent_config

    try:
        cfg = save_agent_config(
            strategy=strategy,
            model=model,
            base_url=base_url,
            price_override=price_override,
            api_key=api_key,
            user=owner,
        )
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    label = cfg["strategy"] or "unconfigured"
    notice = f"Agent saved: {label} / {cfg['model'] or '—'}."
    return _redirect(notice, "agent")


@router.post("/agent/key/copy", dependencies=[Depends(require_csrf)])
def copy_agent_key(strategy: str = Form(...), owner: User = Depends(require_owner)):
    """Owner-only clipboard copy: decrypts for the response body only.

    The key is never rendered into a page; the frontend writes the JSON
    value straight to the clipboard. Every copy is audit-logged.
    """
    from security_agent.control.agent_settings import get_agent_key

    key = get_agent_key((strategy or "").strip() or "custom")
    if not key:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No stored key.")
    from security_agent.audit import get_shared_log

    get_shared_log().append(
        action_class="credential",
        decision="allow",
        line=f"agent:{(strategy or '').strip() or 'custom'} key copied by={owner.id}",
    )
    return JSONResponse({"key": key})


@router.post("/agent/key/delete", dependencies=[Depends(require_csrf)])
def delete_agent_key(strategy: str = Form(...), owner: User = Depends(require_owner)):
    from security_agent.control.agent_settings import delete_agent_key as _delete

    try:
        removed = _delete(strategy, owner)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if not removed:
        return _redirect(f"No stored key for {strategy or 'that strategy'}.", "agent")
    return _redirect(f"Agent key for {strategy} deleted.", "agent")


@router.post("/agent/test", dependencies=[Depends(require_csrf)])
def test_agent(_owner: User = Depends(require_owner)):
    """Manual probe against the saved agent config (D5: the only check)."""
    from security_agent.agent import AgentError
    from security_agent.agent.probe import run_probe
    from security_agent.control.agent_settings import agent_status

    try:
        ok = run_probe()
    except AgentError as exc:
        return _redirect(f"Agent test failed: {exc}", "agent")
    except Exception as exc:  # noqa: BLE001 - test outcome is the notice
        return _redirect(f"Agent test failed: {exc}", "agent")
    status = agent_status()
    if not ok:
        return _redirect("Agent test failed: no native tool call came back.", "agent")
    return _redirect(f"Agent test passed: {status['label']} / {status['model']}.", "agent")
