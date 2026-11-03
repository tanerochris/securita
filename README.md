# AI Security Agent

Self-hosted Docker security agent. Own harness on LangGraph plus LangChain, Muse Spark as hosted API brain. Repo-agnostic (GitHub, GitLab, any git URL, local). Dashboard with Owner-managed accounts plus Google and Microsoft SSO.

See [architecture.md](docs/architecture.md) and [implementation plan](docs/plans/2026-10-29-implementation-plan.md).

## H1 foundation (Phase 0)

FastAPI app, LangGraph worker, Compose (app, worker, db, sandbox runner), Postgres with encrypted fields, Muse Spark probe gate, sandbox execution policy, dashboard skeleton with Owner-first signup, accounts, Google/Microsoft SSO stubs, roles, TLS note.

### Start (Docker, recommended)

```bash
cp .env.example .env
# set MASTER_KEY and MODEL_API_KEY in .env, then:
docker compose up --build
```

For live reload during development (`./src` syncs + restarts, dependency-file edits rebuild):

```bash
docker compose up --watch
```

Open http://localhost:8000/dashboard in a browser (first signup becomes Owner). Health: http://localhost:8000/health

For demos, the login page offers **Continue as guest** — one click, no password, full Owner access to explore the live install.

> TLS everywhere in production; plain HTTP on localhost only (NFR-3).
> Terminate TLS at your reverse proxy and set `PUBLIC_URL=https://…`; the app
> refuses prod boot on plain-http `PUBLIC_URL`.

### First boot

- The app runs Alembic migrations on startup (`alembic upgrade head`).
- The first `up --build` also builds the sandbox image (`sandbox-runner`
  service, exits 0 after a scanner smoke check) — executors refuse to
  boot without that image. Rebuild just it with
  `docker compose build sandbox-runner`.
- With no `MASTER_KEY` set, it generates one and prints it **once** — store it
  outside the install; loss means encrypted fields are unrecoverable (NFR-9 D2).
- Register SSO redirect URIs at your providers:
  `$PUBLIC_URL/auth/google/callback` and `$PUBLIC_URL/auth/microsoft/callback`.

### Start (local Python, uv-managed env)

The environment lives in the project (`.venv`) via uv — never the system interpreter.

```bash
uv sync
uv run uvicorn security_agent.app.main:app --host 127.0.0.1 --port 8000
```

Probe gate (no Phase 1 without a pass):

```bash
uv run security-agent-probe
```

### Test / lint

```bash
uv run pytest
uv run ruff check src tests
uv run ruff format --check src tests
```

## Layout (src layout)

```
pyproject.toml        # PEP 621 manifest (hatchling, uv)
compose.yaml          # Compose Specification services
Dockerfile            # uv python:3.12 image
src/security_agent/   # app, worker, brain, sandbox, db, audit, config, crypto
tests/                # unit + integration
docs/                 # architecture + plans
```
