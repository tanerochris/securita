# Scurita

Self-hosted security agent. Connect a repo and it scans for vulnerable
dependencies, judges reachability in your own code, generates verified
patches, opens PRs, tracks leaked secrets, watches security news, and
answers questions in a dashboard chat — with human approval gates before
anything privileged happens.

Own LangGraph + LangChain harness, FastAPI + HTMX dashboard, Postgres,
disposable Docker sandboxes per run. The model brain is Owner-configured
in Settings → Brain (OpenRouter, Vercel AI Gateway, local Ollama, any
custom OpenAI-compatible URL, native Google Gemini, or native Anthropic).

## Prerequisites

- Docker + Docker Compose (the application runs in Compose; there is no
  supported bare-metal path).
- A brain provider API key, if you want AI features (patch adaptation,
  PR summaries, news intel, chat). Without one the app still boots and
  scans; AI steps fail loud and runs park until a provider is configured.
- Python 3.12+ with [uv](https://docs.astral.sh/uv/) only for running the
  test/lint suite from your checkout (see Development).

## Quickstart

```bash
git clone https://github.com/tanerochris/securita.git
cd securita
cp .env.example .env
```

Edit `.env`:

- Database: comment out the SQLite `DATABASE_URL` and uncomment the
  Postgres line (`postgresql+psycopg://agent:agent@db:5432/agent`).
- `MASTER_KEY` may be left blank on first boot (one is generated and
  shown once — store it outside the install, then set it in `.env`).

Then:

```bash
docker compose up --build -d
```

First boot runs Postgres migrations and builds the `sandbox-runner`
image (scanner smoke check included) — executors refuse to boot without
that image. Open http://localhost:8000/dashboard and sign up (first
signup becomes Owner), or click **Continue as guest** for one-click
Owner access. Health: http://localhost:8000/health

Next, configure the brain: Settings → Brain, pick a strategy, paste its
key, pick a model, Save, then Test. Verify from the repo:

```bash
docker compose exec app security-agent-probe
```

## Using it

- **Connect a repo:** Repos → Connect. GitHub/GitLab via personal access
  token (any github.com, Enterprise, or self-hosted instance — see
  [git-providers.md](docs/git-providers.md)), any git URL, or a local path.
  The first scan enqueues on connect; later scans run on schedule.
- **Review:** findings with reachability verdicts, patch proposals, secret
  findings, dependency updates, and news relevance all land in the dashboard.
- **Approve:** merge/rotation/publish wait in the approvals queue (Owner or
  Maintainer, single approver suffices). PRs themselves open autonomously.
- **Chat:** the dashboard widget answers questions through tools and shows
  confirm cards for anything that writes.
- **Policies:** upload `sample-policy.md` / `sample-policy-strict.md` to try
  the policy RAG + guardrail flow end to end.

Worker topology: exactly one `orchestrator` (schedules, never executes)
plus any number of `executor`s (claim and run the queue):

```bash
docker compose up --scale executor=3 -d
```

Optional Compose profiles:

```bash
# Heavier Ollama embeddings instead of in-process ONNX (default):
EMBEDDING_PROVIDER=ollama docker compose --profile ollama up -d
# Loki audit backend (default is in-memory):
docker compose --profile ops up -d   # then AUDIT_BACKEND=loki in .env
```

## Configuration

Everything lives in `.env` (see `.env.example`); the knobs most installs
touch:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Must be the Postgres URL under Compose. |
| `MASTER_KEY` | Per-install 32-byte key (base64). Loss means encrypted fields are unrecoverable. |
| `PUBLIC_URL` | Public base URL. Must be `https://…` in prod or the app refuses to boot. |
| `GOOGLE_CLIENT_ID` / `MICROSOFT_CLIENT_ID` (+ secrets) | Operator-created SSO clients; register `$PUBLIC_URL/auth/{google,microsoft}/callback`. |
| `NEWS_RSS_FEEDS` | Extra outlet feeds for news intel. |
| `RUN_SPEND_CAP_USD` / `SPEND_CAP_MONTHLY_USD` | Per-run and monthly AI spend caps (adjustable in Settings). |
| `BACKUP_DIR` | Where backups land (bind mount). |

Spend caps, notification channels, digest schedule, and the dependency
budget are managed live in Settings; the brain provider only in
Settings → Brain.

## Operations

```bash
docker compose logs -f app orchestrator executor   # logs
docker compose exec app security-agent-backup      # timestamped backup → BACKUP_DIR
docker compose exec app security-agent-probe       # brain gate: auth + chat + tool_calls
docker compose build sandbox-runner                # rebuild just the sandbox image
```

- Runbooks: [backup / key ceremony / restore](docs/runbooks/backup-restore.md),
  [brain key rotation](docs/runbooks/brain-key-rotation.md).
- Backups hold the database as-stored plus a non-secret config snapshot;
  the master key is never in a backup.
- Brain keys are pasted once in Settings → Brain and never re-viewed —
  not in the UI, API, logs, or backups.

Production notes: terminate TLS at your reverse proxy, set
`PUBLIC_URL=https://…`, keep `APP_ENV=prod` (host sandbox execution is
banned there), and store `MASTER_KEY` outside the install.

## Development

Live reload (`./src` syncs + restarts, dependency edits rebuild):

```bash
docker compose up --watch
```

Tests and linters run from your checkout (no Compose needed):

```bash
uv sync
uv run pytest
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
```

Layout:

```
pyproject.toml        # PEP 621 manifest (hatchling, uv)
compose.yaml          # app, orchestrator, executor(s), db, sandbox-runner (+ ollama, loki profiles)
Dockerfile            # app/worker image (uv python:3.12)
Dockerfile.sandbox    # disposable per-run tool image (scanners live here only)
src/security_agent/   # app, worker, brain, sandbox, db, audit, config, crypto
tests/                # unit + integration + e2e
docs/                 # architecture.md, git-providers.md, runbooks, plans
```

Further reading: [architecture.md](docs/architecture.md),
[git-providers.md](docs/git-providers.md).
