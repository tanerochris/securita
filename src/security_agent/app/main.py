"""FastAPI presentation + control app (Jinja + HTMX base)."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from security_agent.app.timefmt import user_time as _user_time
from security_agent.control.cost import format_usd as _format_usd

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))
templates.env.filters["user_time"] = _user_time
templates.env.filters["usd"] = _format_usd

_base_template_response = templates.TemplateResponse


_NAV_PREFIXES = (
    ("/repos", "repos"),
    ("/providers", "repos"),
    ("/dashboard", "dashboard"),
    ("/news", "news"),
    ("/notifications", "notifications"),
    ("/policies", "policies"),
    ("/approvals", "approvals"),
    ("/accounts", "accounts"),
    ("/settings", "settings"),
)


def _active_nav(path: str) -> str | None:
    """Sidebar section for a URL path; None for pages outside sections."""
    for prefix, section in _NAV_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return section
    return None


def _template_response_with_globals(request, name, context=None, *args, **kwargs):
    """Every page render carries `user` + `csrf` + `active_nav`, so the
    header identity, bell, avatar menu, and sidebar highlight render
    identically on all pages instead of only the views that pass them."""
    from security_agent.app.dependencies import SESSION_COOKIE, make_csrf

    ctx = dict(context or {})
    if "active_nav" not in ctx:
        ctx["active_nav"] = _active_nav(request.url.path)
    if "user" not in ctx:
        user = getattr(request.state, "user", None)
        if user is None:
            try:
                from security_agent.app import accounts as accounts_svc

                sid = request.cookies.get(SESSION_COOKIE)
                user = accounts_svc.validate_session(sid) if sid else None
                request.state.user = user
            except Exception:  # noqa: BLE001 - header identity is best-effort
                user = None
        ctx["user"] = user
    if "csrf" not in ctx:
        ctx["csrf"] = make_csrf()
    return _base_template_response(request, name, ctx, *args, **kwargs)


templates.TemplateResponse = _template_response_with_globals  # type: ignore[method-assign]


def run_migrations() -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")


@asynccontextmanager
async def lifespan(app: FastAPI):
    from security_agent.config import get_settings
    from security_agent.db.keys import ensure_master_key

    s = get_settings()
    if s.is_prod and s.public_url.startswith("http://"):
        raise RuntimeError("Refusing prod boot: PUBLIC_URL must be https (NFR-3).")
    ensure_master_key()  # prints once if generated
    # Fail fast on broken schema: silently serving without the DB breaks auth.
    if s.database_url.startswith("postgresql"):
        run_migrations()
    else:
        from security_agent.db.models import Base
        from security_agent.db.session import get_engine

        Base.metadata.create_all(get_engine())
    yield


def create_app() -> FastAPI:
    from security_agent.app.routers import (
        accounts,
        approvals,
        auth,
        git_providers,
        health,
        news,
        notifications,
        policies,
        repos,
        settings,
        sso,
        webhooks,
    )
    from security_agent.db.keys import get_signing_key

    app = FastAPI(title="Securita", lifespan=lifespan)
    app.add_middleware(SessionMiddleware, secret_key=get_signing_key())

    @app.exception_handler(HTTPException)
    async def _html_auth_redirect(request: Request, exc: HTTPException):
        """Send expired browser sessions back to the login page.

        Browser navigations accept HTML; API clients (health checks,
        webhooks, test clients sending */*) keep the JSON error untouched.
        Only the two session 401s redirect — a failed login POST keeps its
        "invalid credentials" response, and POSTs get 303 so the follow-up
        is always a GET.
        """
        if (
            exc.status_code == 401
            and exc.detail in ("Login required.", "Session expired.")
            and "text/html" in request.headers.get("accept", "")
        ):
            target = "/login?expired=1" if exc.detail == "Session expired." else "/login"
            return RedirectResponse(target, status_code=303)
        if exc.status_code == 404 and "text/html" in request.headers.get("accept", ""):
            return templates.TemplateResponse(request, "404.html", {}, status_code=404)
        return JSONResponse(
            {"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers
        )

    @app.exception_handler(StarletteHTTPException)
    async def _not_found_page(request: Request, exc: StarletteHTTPException):
        """Branded 404 page for browsers; JSON stays for API clients."""
        if exc.status_code == 404 and "text/html" in request.headers.get("accept", ""):
            return templates.TemplateResponse(request, "404.html", {}, status_code=404)
        return JSONResponse(
            {"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers
        )

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(accounts.router)
    app.include_router(sso.router)
    app.include_router(webhooks.router)
    app.include_router(git_providers.router)
    app.include_router(repos.router)
    app.include_router(notifications.router)
    app.include_router(news.router)
    app.include_router(policies.router)
    app.include_router(approvals.router)
    app.include_router(settings.router)
    static_dir = BASE / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    return app


app = create_app()
