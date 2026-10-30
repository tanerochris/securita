"""FastAPI presentation + control app (Jinja + HTMX base)."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
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
        repos,
        settings,
        sso,
        webhooks,
    )
    from security_agent.db.keys import get_signing_key

    app = FastAPI(title="AI Security Agent", lifespan=lifespan)
    app.add_middleware(SessionMiddleware, secret_key=get_signing_key())
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(accounts.router)
    app.include_router(sso.router)
    app.include_router(webhooks.router)
    app.include_router(git_providers.router)
    app.include_router(repos.router)
    app.include_router(approvals.router)
    app.include_router(settings.router)
    static_dir = BASE / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    return app


app = create_app()
