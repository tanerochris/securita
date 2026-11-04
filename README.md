# Scurita – AI Security Agent

> **Meta Global AI Developer Hackathon submission** (Meta + Cerebral Valley, Oct 26 – Nov 4, 2026).
> **Track:** Indie Developer · **Category:** Build For Your World.
> Self-hosted security agent (runs locally or in Docker): own LangGraph + LangChain harness
> with Muse Spark as the hosted API brain. Repo-agnostic (GitHub, GitLab, any git URL,
> local).
>
> **Demo video (≤ 3:00):** ([Scurita DEMO](https://www.youtube.com/watch?v=IkJMa8_Lq8o))

Scurita is a self-hosted AI security agent that finds, triages, and fixes
vulnerabilities before attackers can exploit them.

The problem is that every project depends on hundreds of open-source packages,
ships fast, and leaks secrets by accident. Developers get CVE alerts with no
context, fear breaking changes so they freeze updates, drown in irrelevant
security news, and use scanners that report problems but never fix them. As a
result, known vulnerabilities stay open for months.

Scurita solves this by connecting to any git repo and working continuously. It
scans code and dependencies against vulnerability databases including OSV, GHSA,
KEV, and NVD. It tracks security updates for every dependency, showing what
each patch fixes and what might break. It hunts for exposed secrets in code and
history. It filters global threat news down to what is actionable for your
specific tech stack. It then combines all of these signals and uses Muse Spark
to draft real pull requests and patches with clear titles, explanations, and
impact summaries, while sending prompt alerts to your channels with the fix
attached where possible. You stay in control through natural-language policies
that customize agent behavior, defining what to auto-fix and what needs
approval, with every action reviewable and auditable in the dashboard. It is
fully self-hosted, running locally or in Docker with your code and keys never
leaving your infrastructure, works with GitHub, GitLab, any git URL, or local
repos, and is powered at runtime entirely by Meta models.

## What existed before vs. built during the event

Nothing pre-existed. The project was designed and built entirely during the hackathon window:
planning docs from Oct 27 (`docs/plans/`), first code commit Oct 30, all work committed Oct 30 –
Nov 4 (see `git log`). There are no pre-existing-code dependencies and no unbuilt features shown —
everything below runs from this repo.

## Meta models used (all runtime, all do real work)

Every model the project calls at runtime is a Meta model, served through the Meta Model API.
No other model family is called at runtime; the app ships deterministic fallbacks (templates,
keyword retrieval, parked runs) when no key is configured.

- **Muse Spark** (`MODEL_NAME=muse-spark`, default) — runs on the Meta Model API,
  server-side only. Core brain across the workflow:
  - Patch adaptation
  - Model-written PR titles/bodies
  - News classification + per-repo relevance
  - Dependency impact summaries
  - Policy extraction
  - Dashboard chat agent with native tool calls


## Setup for judges (two ways to run, no outside accounts needed)

There are two ways to run the project from this repo. Both need no accounts, no SSO
registration, and no API keys except the Meta Model API key below (and both boot keyless —
see notes).

> **Note:** Running with Docker (Option 2) will guarantee full functionality.

### Option 1 — Local, no Docker

Prerequisites: Python 3.12+ and [uv](https://docs.astral.sh/uv/). SQLite is the zero-config
database (`./agent.db`), and embeddings run in-process. Two terminals: the first boots the
dashboard, the second runs scans.

**Terminal 1 — boot the dashboard:**

```bash
git clone https://github.com/tanerochris/securita.git
cd securita
cp .env.example .env
# Edit .env and set MODEL_API_KEY to a Meta Model API key
# (create one at https://dev.meta.ai — Start building — then paste the key).
# Keep the SQLite DATABASE_URL as-is. MASTER_KEY may be left blank
# (one is generated on first boot).
uv sync
uv run uvicorn security_agent.app.main:app --host 127.0.0.1 --port 8000
```

Then open http://127.0.0.1:8000/dashboard in a browser and click **Continue as guest** —
one click, no password, full Owner access to explore the live install. Health:
http://127.0.0.1:8000/health

**Terminal 2 — host tools + scan worker:**

Scans need the sandbox tools on the host and the worker process running. Install them
with:

```bash
uv run security-agent-install-tools   # git, ripgrep, node + pinned scanners
uv run security-agent-doctor          # preflight: fails loud with install hints
uv run python -m security_agent.worker.main
```

The doctor requires `git`, `rg` (ripgrep), `osv-scanner`, and `betterleaks` on PATH —
scans fail loud without them. Node/npm only matter for JS repos (lockfile generation).

On Windows, run the same steps inside WSL2 (Ubuntu) — `security-agent-install-tools`
prints the setup guide on native Windows. On macOS the everyday tools come from Homebrew,
on Linux from apt/dnf/pacman/apk; the scanners always download the pinned,
checksum-verified release assets into `~/.local/bin`.

### Option 2 — Docker (recommended)

Prerequisites: Docker + Docker Compose only.

```bash
git clone https://github.com/tanerochris/securita.git
cd securita
cp .env.example .env
# Edit .env and set MODEL_API_KEY as above. For the database, comment out
# the SQLite line and uncomment the Postgres DATABASE_URL (Compose
# service "db"). MASTER_KEY may be left blank.
docker compose up --build
```

Then open http://localhost:8000/dashboard and click **Continue as guest** as above.
Health: http://localhost:8000/health

Verify live Meta model calls from the repo (probe gate: auth + chat + native `tool_calls`
round-trip against the configured Meta model):

```bash
uv run security-agent-probe
```

Notes (both options):

- Without `MODEL_API_KEY`, the app still boots and runs: model-backed steps fall back to
  deterministic templates/keyword retrieval or park with an alert, so judges can click through
  everything keyless and then add a key to see live Muse Spark calls.
- Key handling: the key lives only in the server-side `MODEL_API_KEY` env var (loaded via
  `src/security_agent/config.py`). It never appears in client code, templates, logs, or the repo
  (`.env` and `.env.*` are git-ignored; only `.env.example` is committed, with an empty value).
- Docker first boot runs Alembic migrations and builds the `sandbox-runner` image; see
  "First boot" below for details.

## Third-party / non-Meta components (labels)

No browser/OS voices, no text-to-speech, no third-party LLM APIs. Non-model third parties:

- **Scanners (pinned + checksum-verified):** `osv-scanner` v2.7.0 (Google),
  `betterleaks` v2.0.0-rc.1 — in the sandbox image (Docker path, see `Dockerfile.sandbox`)
  or installed to `~/.local/bin` by `security-agent-install-tools` (local path).
- **Policy RAG embeddings (optional, operator's choice via `EMBEDDING_PROVIDER`):**
  default `local` runs `BAAI/bge-small-en-v1.5` ONNX in-process via fastembed (no extra service);
  `ollama` uses `nomic-embed-text`; `hosted` is any OpenAI-compatible `/embeddings` API;
  `off` is keyword retrieval only. Vectors are never required — chunks without embeddings still
  serve via keyword matching. See `src/security_agent/brain/embeddings.py`.
- **Vulnerability/threat data:** OSV, GHSA, KEV, NVD feeds (via osv-scanner + KEV join); news
  boosters from the HN Algolia API + operator-configured RSS/Atom feeds (`NEWS_*` in `.env.example`).
- **Auth:** Google/Microsoft OIDC SSO are operator-created-client stubs; guest + local accounts
  need no outside account.
- **Frameworks/infra:** FastAPI, LangGraph + LangChain (`ChatOpenAI` with `base_url` override,
  Chat Completions + native tool calls only), SQLite (local default) or Postgres (Docker),
  Jinja + HTMX dashboard.


---

## Project details

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

The default path needs no Docker: SQLite is the zero-config database
(`./agent.db`), the sandbox falls back to host execution, and embeddings
run in-process. The environment lives in the project (`.venv`) via uv —
never the system interpreter.

```bash
uv sync
uv run security-agent-install-tools   # git, ripgrep, node + pinned scanners
uv run security-agent-doctor          # preflight: fails loud with install hints
uv run uvicorn security_agent.app.main:app --host 127.0.0.1 --port 8000
uv run python -m security_agent.worker.main   # second terminal: scans/checks
```

Then open http://127.0.0.1:8000/dashboard and click **Continue as guest**.

Windows runs inside WSL2 (Ubuntu): `wsl --install -d Ubuntu`, then follow
the same steps in the Ubuntu shell — `security-agent-install-tools` prints
this guide and exits if run on native Windows. macOS uses Homebrew for the
everyday tools; Linux uses apt/dnf/pacman/apk. Scanners always download the
pinned, checksum-verified release assets (same pins as `Dockerfile.sandbox`)
into `~/.local/bin` (override with `security-agent-install-tools --dir ...`;
use `--tools git,ripgrep,...` for a subset).

The doctor requires `git`, `rg` (ripgrep), `osv-scanner`, and `betterleaks`
on PATH — scans fail loud without them. Node/npm only matter for JS repos
(lockfile generation); `MODEL_API_KEY` only gates AI-written text (patches,
summaries, chat), everything else runs keyless. Local Postgres is optional:
set `DATABASE_URL` to point at it. Production (`APP_ENV=prod`) still
requires the Docker sandbox.

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
