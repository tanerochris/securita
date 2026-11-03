# Solution Architecture — AI Security Agent

Status: proposal. Derived from `docs/plans/2026-10-27-ai-security-agent.md` (parent) plus sub-plans FR-2/3/4/5/8/9/10/12/15 and NFR recovery/cost/hardening.

## Overview

Self-hosted Docker security agent. Own harness on LangGraph plus LangChain, Muse Spark as hosted API brain. Repo-agnostic (GitHub, GitLab, any git URL, local). Dashboard with Owner-managed accounts plus Google and Microsoft SSO.

Pipeline: signals → sandbox clone → reachability → patch → deliver → approve. Secrets loop parallel. Dashboard owns accounts, reports, approvals, notification settings.

```text
Scheduler/Triggers -> Worker (LangGraph) -> Sandbox Runner -> App (FastAPI) -> Dashboard
                          |                      |               |
                     Model Brain            Scanners/tools   Postgres + Loki + Backups
```

## Principles (from plans)

- Zero host-executed agent commands; every scan in a fresh disposable sandbox (NFR-1).
- Sandbox is the approval boundary: in-sandbox work autonomous, merge/rotate/publish gated (FR-9).
- Proposals free, merges gated: PR/MR/issue creation needs no approval; agent cannot merge (FR-9, FR-5).
- Boundary validation + injection fixture suite gating releases (NFR-5).
- Hard cost caps with park + alert (NFR-8, FR-15 D4).

## Top-level deployment (NFR-10)

Compose services on the operator network: `app`, `worker`, `db`, `sandbox runner`.

Six logical planes mapped onto those services:

| Plane | Compose home | Plans |
|---|---|---|
| Orchestration (scheduler, pipeline, brain) | worker | FR-2, FR-3, FR-4, FR-8, FR-15 |
| Execution (sandbox lifecycle, tools) | sandbox runner | FR-14, NFR-1, NFR-2 |
| Control (findings, delivery, approvals) | app | FR-5, FR-9, FR-12 D1 |
| Presentation + Identity | app | FR-10, FR-11, FR-12 |
| Data, Audit, Recovery | db + app + log store | NFR-4, NFR-8, NFR-9, FR-9 D6/D8 |
| Integrations | app + worker | FR-6, FR-13, FR-2 D3 |

## 1. Orchestration Plane (Worker)

### 1a. Scan Scheduler (FR-2 D2/D3, FR-8 D6)

- Per-repo schedule + state (last scan, last findings for diff). One scheduler process fans out; each run gets its own disposable sandbox.
- Triggers: 6h poll default (per-repo configurable) + scan-on-connect + manual scan-now + optional GitHub/GitLab webhooks (push/PR, per-repo URL + secret, signature-verified). Local-path repos poll-only.
- "Tier 1" names the trigger-signal set (OSV/GHSA/KEV/NVD via osv-scanner + KEV join); Tier 2 is news boosters (FR-6).
- Secrets scan piggybacks the same run and triggers; rule updates trigger a one-off history re-baseline.

### 1b. LangGraph Pipeline (FR-2/3/4/5/8)

- State graph. Nodes: fetch signals, sandbox scan, reachability, patch, deliver, notify. Edges carry typed state. Approval gates are checkpoints between nodes, never mid-shell.
- Scan (FR-2): osv-scanner on the lockfile, generated in-sandbox (`npm install --package-lock-only`, scripts disabled) when absent. Transitive + dev deps in scope, scope-labeled; dev-only lower priority, never silent. KEV joined by CVE as exploitation flag.
- Finding record (FR-2 D4/D6): one finding per (package, canonical advisory ID); canonical prefers CVE, else GHSA, else OSV ID, aliases collapse. Carries repo, package + version, severity (max CVSS, fail loud on conflict), KEV flag, dependency path, prod/dev scope, fixed versions, citations, run id. Single normalization point; FR-3/FR-4 never re-fetch OSV.
- Reachability (FR-3): import-based static import/require graph from first-party code, transitive; unresolvable dynamic imports count as reachable; test-only counts as reachable. Runs in-sandbox (narrow tool and/or ripgrep + JS parser). Verdict: reachable flag + import-chain evidence (file:line hops) or fail-open marker; unreachable carries reason code. Recomputed every scan; flips drive reopen/park.
- Patch (FR-4): bump-first + model adaptation (advisory fixed version, else next fixed; docs/changelog checked; adaptation in same patch). Verify via repo tests if present, else static analysis; propose only on pass. Related-test failures only (agent judges relatedness, discloses ignored); scoped test edits only; 3 repair rounds then report-only; unpatchable → guidance + filed issue.
- Secrets branch (FR-8): Betterleaks in the same sandbox run (default rules + install allowlist; liveness validation on, analysis off). History baselined once at connect, new-only after. Response: notify + auto removal-PR (redact, env reference) + rotation guidance/alert. No auto-rotation in v1. Closure: HEAD-clean AND (human marks rotated OR re-validation shows dead).

### 1c. Model Brain (FR-15)

- Muse Spark default via hosted OpenAI-compatible API (`https://api.meta.ai/v1`); LangChain `ChatOpenAI` with `base_url` override; Chat Completions + native tool calls only.
- Full probe (auth, chat, native `tool_calls` round-trip) before serving work gates Phase 1; every configured model re-probes. Portability constraint: no Responses-API-specific code, no prompt-emulated or chat-only path in v1.
- Dashboard-configurable per-task models + substitution model; any family allowed if OpenAI-compatible shape holds; training-on-data tiers need Owner opt-in.
- Runtime: bounded retry with backoff within per-run caps, then park under backpressure + alert. Recovery replays completed tool results from logs (no re-execution of side-effecting tools), reconstructs context from run logs/summaries, resumes via LangGraph checkpoint. Substitution applies to new runs, not mid-run.

## 2. Execution Plane (Sandbox Runner)

### 2a. Sandbox Lifecycle (NFR-1/2)

- Fresh disposable container per run; clone there; run every command there; destroy after. Patch leaves as diff only.
- No secrets mounted inside. Least-privilege sandbox token (read + open PRs/issues; no merge/rotate/publish). Egress restricted to feed and API hosts as a technical guardrail (no approval involved).

### 2b. Tool Manifest (FR-14, NFR-5)

- Narrow `@tool` wrappers with allowlisted argv (`shell=False`) for osv-scanner, Betterleaks, search/parse helpers.
- Ad-hoc investigation via `ShellToolMiddleware` + `DockerExecutionPolicy` (fresh container per run). Host policy banned in prod.
- Tool router governs sandbox-external tools; calls outside the manifest fail closed. Structured schema checks on all tool args; every in-sandbox shell line audit-logged.

## 3. Control Plane (App/Backend)

### 3a. Findings Lifecycle (FR-12 D1, FR-3 D4, FR-8 D7)

- Unified lifecycle: open → proposed → resolved → closed, plus terminal unpatchable (report-only + issue) and silent-with-reason; secrets add awaiting-rotation before closed. Rescan can reopen.
- Silenced findings visible in silent-with-reason, excluded from default active filters, counted separately in reports.

### 3b. Delivery Executor (FR-5, FR-9)

- Autonomous, approval-free: open ready-for-review PR/MR (no drafts v1); one PR per patched package, grouped when related (overlapping code or dependency edge; agent judges, discloses reason); bot identity with SSH-signed commits from per-install key; target = repo default branch unless overridden per repo; minimal template (package x→y, advisory IDs, KEV flag, verification line, grouping/ignored-tests pointers, dashboard link). Local: new `security/<package>-<advisory>` branch (working branch untouched) + `git format-patch` files. Unpatchable/report-only: provider issue with guidance + dashboard link, never a PR.
- Privileged post-approval only: merge/rotation/publish execute from the backend, never from the sandbox.
- Provider state sync: webhook-instant reconcile where configured (FR-2 receiver reused, merge/close events) + resync piggybacked on every scheduled scan. No dedicated poller.

### 3c. Approval Gates (FR-9)

- Pre-execution checkpoints between graph nodes. Triggers: merge, rotation, publish only. In-sandbox work (including external API calls) and PR/MR/issue creation are free.
- Owner and Maintainer approve, single approver suffices. Developer triggers scans, approves nothing. Reporter view-only.
- Sources: dashboard queue + provider-side (approving/merging the PR counts). Requests fan out to all notification channels; granting stays dashboard + provider-side, plus the chat agent's approve/decline cards (chat override of FR-9 D5, see `docs/plans/2026-11-02-chat-agent.md`): same RBAC, same `decide_gate` core, explicit per-gate confirmation.
- Timeout: deny after configurable window (default 72h); agent auto re-queues with note. No standing bypass; Owner may delegate to Developer (time-boxed 24h default, revocable, optionally class-narrowed, fully audited).
- Audit: full decision context (timestamp, run id, actor + role, action + target, decision + decider + source, reason). Retention per install policy, default 1 year.

## 4. Presentation + Identity Plane (Dashboard)

### 4a. Accounts and Auth (FR-10, FR-11)

- First signup is Owner; then invite-only. Owner enters email + role; single-use invite link (72h default, configurable); user sets password or links SSO.
- Passwords: min 12 chars, no forced complexity classes, breach-check rejects, Argon2id. Reset via emailed single-use link.
- MFA opt-in for all: TOTP + backup codes v1; WebAuthn deferred; SSO defers to IdP.
- Sessions server-side; 24h absolute, 30min idle; immediate revoke on disable/role-change/reset; concurrent allowed with per-session revoke list.
- Disable-only v1 (login blocked, sessions revoked, audit kept); cannot disable/demote last Owner. TLS everywhere; plain HTTP localhost only.

### 4b. Views (FR-12)

- Findings, patches + approval queue (split views, grouped by repo, needs-action first, KEV/severity/recency ordering), reports, notification settings screen.
- Patches view: proposals with verification result, grouping pointers, PR/MR link + provider state, finding links (observe + link out, no merge button). Approval queue: pending gates with full decision context, Approve/Deny, delegation, timeout countdown, decided history.
- Reports: on-screen run summaries + outstanding-risk view, JSON/CSV export, scheduled PDF/email digests via FR-13 channels.
- Notification settings screen owned by FR-12 (channel list, per-severity routing, test-send, digest schedule); delivery mechanics owned by FR-13.
- Stack: Jinja + HTMX base, FastAPI-only routing; lazy React islands only where justified (never blocking first paint); Node build for island bundles only. Chat agent shipped as a floating widget on every dashboard page (see `docs/plans/2026-11-02-chat-agent.md`; the standalone `/chat` page was removed): backend-direct UI-parity tools plus sandbox-mediated repo inspection, per-day chat cap, injection-suite-gated.

## 5. Data, Audit, Recovery Plane

### 5a. State and Audit

- Postgres: repos, findings, verdicts, proposals, approvals, accounts. Encrypted token fields (AES-256-GCM under per-install master key; audit on decrypt; values never re-viewed).
- Pluggable `LogStore` (append/query/retention-purge); Loki ships as v1 default. Low-cardinality labels (tenant, action class, decision); run id in line content.

### 5b. Cost and Recovery (NFR-8/9, FR-15 D4)

- Cost: per-run $2.00 spend-cap default with 80% warning (0 disables); daily spend alerts warn $25 / critical $100; monthly spend cap alert-only; dependency budget $0.40/24h; all Owner-configurable. Hard stop at per-run cap (parked, alert fires, resumes only under raised cap); Owner/Maintainer may raise and resume. Queue backpressure.
- Backup: Postgres dumps (+ config + encrypted fields as-stored) to operator-provided path via Compose bind mount (default `./backups`); key material separate, never in same backup.
- Key ceremony: app-generated on first boot, shown once for operator-held storage outside the install; loss means encrypted fields unrecoverable, tokens re-entered.
- Restore proof: proven pre-launch and re-proven on every release touching storage/encryption/backup; scratch-stack pass = boots, Owner login works, sample findings/approvals read, secret decrypt fires audit entry.

## 6. Integration Plane

- Notifications (FR-13, FR-9 D5): email, Slack, Discord, Telegram, PagerDuty, generic webhook; per-severity routing; test-send per channel. Approval requests fan out to all channels.
- Provider webhooks (FR-2 D3, FR-5 D5): one signature-verified receiver reused for scan triggers and merge/close reconcile.
- Signals (FR-6, FR-2): Tier 1 triggers OSV/GHSA/KEV/NVD; Tier 2 HN API + outlet RSS match the stack and raise priority; boost never triggers action alone. Polite scrape fallback only.

## Build order

1. Phase 0: scaffold (FastAPI app, LangGraph worker, compose), Muse Spark probe, execution policy, dashboard skeleton + SSO, Postgres with encrypted fields.
2. Phase 1: Node.js vuln loop (scheduler, sandbox scan, reachability, patch, delivery, findings + approval queue).
3. Phase 2: news signals.
4. Phase 3: Python reachability (same graph, Python nodes).
5. Phase 4: secrets loop.
6. Phase 5: notifications + injection suite + backup/restore runbook.

## Open seams (no sub-plan yet)

FR-1 intake details, FR-6 stack matcher, FR-7 Python parsers, FR-11 OIDC client setup, FR-13 channel mechanics, FR-14 tool argv allowlists.
