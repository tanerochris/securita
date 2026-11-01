"""FastAPI presentation + control app (Jinja + HTMX base)."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))


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
