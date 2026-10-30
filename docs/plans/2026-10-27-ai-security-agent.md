# AI Security Agent — Plan v7

Status: draft. v15 applies the accepted NFR sub-plan (backup ceremony, cost numbers, boundary validation, gated injection suite); v14 applied FR-15 (portable model policy, dashboard-configurable models, re-probe gate, log-summary recovery with replay); v13 applied FR-3 (import-based graph, visible silence, verdict evidence, every-scan recompute with flip reopen); v12 applied FR-12, v11 FR-10, v10 FR-8, v9 FR-5, v8 FR-2, v7 FR-4. Expand and improve here.

## Goal

Self-hosted Docker security agent. Own harness on LangGraph plus LangChain, Muse Spark as hosted API brain. Repo-agnostic (GitHub, GitLab, any git URL, local). Dashboard with Owner-managed accounts plus Google and Microsoft SSO. Email, Slack, and webhook (covers pagers) notifications. Every tool runs in a sandbox. Human approves before anything goes live. First targets: Node.js and Python.

## Success Criteria

- Compose up gives dashboard plus workers on your network.
- First signup becomes Owner; Owner creates accounts; SSO login works.
- Any repo URL or local path scans; findings, patches, approvals all visible in dashboard.
- News boosts priority but never triggers action alone.
- Zero host-executed agent commands; all scans in disposable sandboxes.
- Zero merges, rotations, or publishes without approval.

## Functional Requirements

Each requirement gets its own sub-plan later. Numbering is stable; reference it (FR-9, NFR-3) from sub-plans.

- **FR-1 Repo intake:** scan any GitHub repo, GitLab repo, arbitrary git URL, or local path.
- **FR-2 Vuln detection (Node.js):** osv-scanner in a per-repo sandbox scan over the lockfile (generated in-sandbox when absent), covering transitive and dev deps with prod/dev scope labels; KEV joined by CVE as exploitation flag. Findings are per (package, advisory) with dependency paths, handed to FR-3 as typed records. Triggers: 6h poll default (per-repo configurable) + scan-on-connect + manual + optional GitHub/GitLab webhooks; local repos poll-only. Full rules: FR-2 sub-plan.
- **FR-3 Reachability analysis:** import-based static import/require graph from first-party code (transitive; dynamic fail-open to reachable; in-sandbox per FR-14) decides patch versus silent-with-reason. Consumes the FR-2 typed finding record. Verdicts carry import-chain evidence or reason codes (test-only counts as reachable); silenced findings show in silent-with-reason out of default filters; verdicts recompute every scan with flips driving reopen. Full rules: FR-3 sub-plan.
- **FR-4 Patch generation:** LangGraph patch node takes the advisory fixed version (else next fixed), implements + adapts with docs in sandbox, verifies (tests or static analysis), and proposes only on pass. Related-test failures only; scoped test edits; 3 repair rounds then report-only; unpatchable → guidance + filed issue. Full rules: FR-4 sub-plan.
- **FR-5 Patch delivery:** GitHub PR, GitLab MR, local branch plus patch files. Proposals open ready-for-review (no drafts); one PR per patched package, grouped when related with reason disclosed. Bot identity, SSH-signed commits. Default branch unless overridden per repo. Provider merge state via webhooks where configured plus resync on every scan. Local: new `security/<package>-<advisory>` branch plus format-patch files, working branch untouched. Fixed minimal template with dashboard link; unpatchable cases file issues, never PRs. Opening proposals needs no approval; the agent cannot merge; provider-side approval counts. Full rules: FR-5 sub-plan.
- **FR-6 News boosting:** HN plus RSS pollers match the stack and raise priority. Boost never triggers action alone.
- **FR-7 Python reachability:** same detect→reach→patch loop for Python targets.
- **FR-8 Secrets loop:** Betterleaks in sandbox (default rules + install allowlist; liveness validation on, analysis off), history baselined once at connect then new-only, piggybacking the FR-2 scheduler. Detection → notify + auto removal-PR + rotation guidance/alert; no auto-rotation in v1 (staged design deferred). Findings close on HEAD-clean + rotation confirmed. Secrets consumed by reference via env, never read. Full rules: FR-8 sub-plan.
- **FR-9 Approval gates:** pre-execution checkpoints for merge, rotation, and publish only. In-sandbox work (including external API calls) is autonomous; PR/MR/issue creation is free. Owner and Maintainer approve, single approver suffices; granting via dashboard or provider-side. Full rules: FR-9 sub-plan.
- **FR-10 Dashboard accounts:** first signup is Owner; Owner creates accounts via single-use invite link (72h default; user sets password or links SSO) and disables accounts (disable-only v1, instant session revoke, audit kept; last-Owner guard); roles are Owner, Maintainer, Developer, Reporter. Passwords: min 12 chars, breach-check, Argon2id. MFA opt-in for all (TOTP + backup codes v1; WebAuthn deferred; SSO defers to IdP). Sessions server-side, 24h absolute, 30min idle. Full rules: FR-10 sub-plan.
- **FR-11 SSO:** Google plus Microsoft login via standard OIDC at launch.
- **FR-12 Dashboard views:** findings (unified lifecycle: open → proposed → resolved → closed plus terminal unpatchable / silent-with-reason; secrets add awaiting-rotation; rescan reopens), patches + approval queue (split views grouped by repo, needs-action first), reports (on-screen summaries + outstanding-risk + JSON/CSV export + scheduled PDF/email digests via FR-13), notification settings screen (FR-13 owns delivery). Stack: Jinja + HTMX, FastAPI-only routing, lazy React islands where justified. Chat deferred past v1. Full rules: FR-12 sub-plan.
- **FR-13 Notifications:** email, Slack, and generic webhook channels; per-severity routing; test-send per channel.
- **FR-14 CLI execution:** scanners as narrow `@tool` wrappers; ad-hoc shell via `ShellToolMiddleware` with `DockerExecutionPolicy`.
- **FR-15 Model brain:** Muse Spark default via hosted OpenAI-compatible API (`https://api.meta.ai/v1`); dashboard-configurable per-task models plus substitution model; any family allowed if OpenAI-compatible Chat Completions with native tool calls; full probe (auth, chat, native tool call) before serving work gates Phase 1; training-on-data tiers need Owner opt-in; no prompt-emulated or chat-only path in v1. Runtime: bounded retry within caps, then park + alert; recovery replays tool results from logs with run-log summaries. Full rules: FR-15 sub-plan.

## Non-Functional Requirements

- **NFR-1 Containment:** zero host-executed agent commands; every scan in a fresh disposable sandbox; host execution policy banned in prod.
- **NFR-2 Sandbox hygiene:** no secrets mounted inside; sandbox token least-privilege (read + open PRs/issues; no merge/rotate/publish); firewall restricts egress as a technical guardrail with no approval involved; sandbox destroyed after run.
- **NFR-3 Transport security:** TLS everywhere; plain HTTP on localhost only.
- **NFR-4 Secret storage:** AES-256-GCM field encryption under a per-install master key; audit log on decrypt; admins never re-view secrets.
- **NFR-5 Prompt-injection resistance:** repo code, feeds, news, and tool output are data, never orders; model output validated at the boundary (schema checks, manifest fail-closed, sandbox containment, diff-scoped patches) before commands, patches, or rotations; approval points unchanged; findings cite sources; injection fixture suite gates releases.
- **NFR-6 Autonomy:** in-sandbox sequences run with zero approval prompts.
- **NFR-7 Approval integrity:** zero merges or rotations without approval; audit log shows request→approve→execute.
- **NFR-8 Cost control:** per-run token caps (1M default, 80% warning), daily spend alerts (warn $25 / critical $100, Owner-configurable), queue backpressure; hard stop at cap, Owner or Maintainer raises and resumes.
- **NFR-9 Recoverability:** Postgres dumps + config to a shared container↔host bind mount (default `./backups`), key material separate; app-generated key shown once, operator-held, loss means re-entering tokens; restore proven pre-launch and on storage/encryption/backup releases against scratch-stack criteria.
- **NFR-10 Deployability:** self-hosted via Compose (app, worker, db, sandbox runner) on the operator network.
- **NFR-11 Implementation constraint:** Python for agent plus backend in v1 (LangGraph has no Go runtime).
- **NFR-12 Audit storage:** separate pluggable log store behind a `LogStore` interface; Loki ships as the v1 default.

## Approach

**Pipeline:** signals → sandbox clone → reachability → patch → deliver → approve. Secrets loop parallel. Dashboard owns accounts, reports, approvals, notification settings.

**Key decisions:**

1. **Muse Spark via hosted API, orchestrated by LangGraph.** LangChain's `ChatOpenAI` supports tool calling, structured output, and `base_url` override for OpenAI-compatible endpoints. Primary docs confirm the endpoint is OpenAI-compatible at `https://api.meta.ai/v1`, so Phase 0's probe script confirms auth, chat, and a native `tool_calls` round-trip before any harness code depends on it. The Responses API is deferred; the harness stays on ChatOpenAI/Chat Completions for portability (FR-15 sub-plan). Rejected custom loop first (LangGraph gives graph checkpoints free) and Hermes (operator call).
2. **Harness: loop plus graph.** LangGraph state graph. Nodes: fetch signals, sandbox scan, reachability, patch, deliver, rotate, notify. Edges carry typed state. Approval gates are graph checkpoints. The tool router governs sandbox-external tools; in-sandbox shell is free under least-privilege credentials, and calls outside the tool manifest fail closed.
3. **Sandbox everything.** Each scan gets a fresh sandbox. Clone there. Run every command there. No secrets mounted inside. Egress restricted to feed and API hosts. Destroy after. Patch leaves as diff only. New tools install inside sandbox freely; host and guardrail config changes need Owner approval.
4. **Auth: admin-first plus SSO.** First account is Owner. Owner creates and disables accounts. Google and Microsoft SSO at launch via standard OIDC. Roles: Owner, Maintainer, Developer, Reporter. Serve over TLS; plain HTTP localhost only, since passwords and tokens cross the wire.
5. **Notifications day one: email, Slack, generic webhook.** Webhook covers pager event APIs without naming one; named pager templates later. Users pick channels per severity. Test-send button per channel.
6. **Signals:** OSV, GitHub Advisory, CISA KEV, NVD as triggers; HN API and outlet RSS as boosters; scrape fallback polite-only. HackerNoon has no public API found, stays fallback.
7. **Encryption:** TLS transit, AES-256-GCM field encryption for stored tokens under a per-install master key, audit log on decrypt, secret values never re-viewed.
8. **Prompt-injection hardening:** repo code, feeds, news, and tool output are data, never orders. Instructions only from our code and the operator. Model output validated before it becomes a command, patch, or rotation. Findings cite sources.
9. **Command execution: narrow tools plus sandboxed shell.** Each scanner is a narrow `@tool` with allowlisted argv (`shell=False`); ad-hoc investigation uses LangChain's `ShellToolMiddleware` with `DockerExecutionPolicy` (fresh container per run) inside the disposable sandbox. Persistent shell sessions do not support interrupts, so human approval stays as LangGraph checkpoints *between* nodes, never as mid-shell-session interrupts. All approvals are pre-execution: the graph pauses at a checkpoint, presents the pending command(s) with context, and only on approval does the execution node run. Containment is the approval boundary: every command that runs fully inside the sandbox — reads, writes, installs, scans — runs autonomously with no approval, since the sandbox is disposable and the agent must stay autonomous. Approval is required only for merge, rotation, and publish; in-sandbox work including external API calls is free, and secrets are consumed by reference, never read. Approval is granted from the dashboard or provider-side; requests fan out to all notification channels. (Full rules: FR-9 sub-plan.) Creating a diff, opening a PR/MR, or filing an issue needs no approval: proposals are free, and the agent cannot merge — the merge is the gated action. Host execution policy is banned in prod.
10. **Language: Python for agent and backend (v1).** LangGraph ships officially for Python and JavaScript only; Go has only the community `langchaingo` port (chains plus basic ReAct agents, no graph orchestration, checkpoints, or durable execution), so a Go harness would mean reimplementing LangGraph. Scanners run as CLI subprocesses in sandboxes anyway, so Python constrains nothing. Dashboard/API also Python (FastAPI) in v1 to keep one runtime; Go stays an option later for isolated services (e.g. sandbox runner) behind HTTP.

## Steps

**Phase 0 — Scaffold, probe, auth.** Python repo (FastAPI app, LangGraph worker), Dockerfile, compose (app, worker, db, sandbox runner). Muse Spark probe: auth, chat, tool call. Command-execution setup: narrow `@tool` wrappers, `ShellToolMiddleware` with `DockerExecutionPolicy`, approval checkpoints between nodes. Dashboard skeleton: Owner-first signup, account CRUD, Google/Microsoft SSO, roles, TLS. Postgres with encrypted token fields.

**Phase 1 — Node.js vuln loop.** Tier 1 watcher (per-repo scan scheduler; Tier 1 = trigger-signal set OSV/GHSA/KEV/NVD, Tier 2 = news boosters in FR-6). Sandbox clone and scan. Lockfile reachability. LangGraph patch node. Deliver GitHub PR, GitLab MR, local branch plus patch files. Dashboard findings and approval queue.

**Phase 2 — News signals.** HN and RSS pollers, stack matcher, priority boost, polite scraper fallback.

**Phase 3 — Python reachability.** Same graph, Python nodes.

**Phase 4 — Secrets loop.** Betterleaks in sandbox, history baseline, notify + removal-PR + rotation guidance (auto-rotation deferred past v1).

**Phase 5 — Notifications and hardening.** Email, Slack, webhook channels with per-severity routing. Injection fixture suite gating releases. Backup and restore runbook carrying the backup/key/restore ceremony. OSS docs.

## Validation Plan

- **Probe:** script round-trips a native `tool_calls` call via ChatOpenAI at `https://api.meta.ai/v1`. No probe pass, no Phase 1; every configured model re-probes before serving work.
- **Auth:** first signup is Owner; Owner creates a Developer; SSO login works for both providers; Developer/Reporter cannot reach Owner routes; passwords never cross plain HTTP off localhost. Invite expiry enforced; disabled accounts lose sessions immediately; last Owner cannot be disabled or demoted.
- **Sandbox:** scan a hostile fixture (malicious scripts, exfil attempts); assert nothing runs on host, no secret leaks, egress blocked except feeds.
- **Injection suite:** hostile fixtures (injected content, malicious tool output, poisoned feeds, exfil attempts, gate-bypass lures) run in CI; failures block release.
- **Execution policy:** prod config uses `DockerExecutionPolicy`, host policy absent; hostile fixture cannot touch host filesystem or env.
- **Reachability:** importing fixture gets a patch; non-importing fixture stays silent with reason. Oracle: direct OSV API / npm audit cross-check agrees (osv-scanner is now the scanner itself, per FR-2 sub-plan). Unused-package fixture silenced with reason code; import-added fixture reopens with chain evidence.
- **Patch verification:** failing-verification case yields report-only with reason, never a PR; unrelated-failure fixture still proposes with disclosure; test-gutting attempt rejected; unpatchable fixture yields guidance + issue.
- **News boost:** known-discussed CVE rises with story link; rumor-only input yields no patch.
- **Approval gates (highest risk):** withhold approval; assert zero merges, zero rotations, all logged. Assert autonomy: a full in-sandbox scan-to-PR sequence completes with zero approval prompts and the PR opens unmerged. Assert ordering: a gated action (merge/rotation/publish) never starts before its approval; audit log shows request→approve→execute. Approve once; exactly one sandbox rotation lands. Timeout denies and the agent re-queues; delegated approvals audit fully; provider-side merges are observed and reconciled.
- **Audit log:** every gate writes full decision context to the pluggable log store (Loki default); records prove request→approve→execute.
- **Notifications:** test-send reaches email, Slack, webhook; severity routing respected.
- **Dashboard:** lifecycle transitions and reopen verified on fixtures; scheduled digests delivered on schedule.

## Risks / Open Questions

- **Muse Spark endpoint shape** confirmed from primary docs (OpenAI-compatible Chat Completions). On a shape mismatch the fallback is a thin shape-preserving LangChain adapter, otherwise Phase 1 stays gated. Harness gotchas: strict tool-history pairing (unpaired history returns 400), function names with more than one dot return 400, unsupported params (`stop`, `n>1`) rejected.
- **SSO app registration:** needs Google and Microsoft OAuth clients for your domain. Operator creates these; plan documents exact redirect URIs.
- **Shell interrupts unsupported:** persistent shell sessions don't work with LangGraph interrupts, so approvals live at checkpoints between nodes (decision 9), never inside a shell session.
- **Pager pick deferred:** webhook first. Name the pager later and it becomes a template.
- **Risk:** sandbox escape. Mitigate: minimal image, no secrets inside, egress deny-by-default, destroy after run.
- **Risk:** master key loss. Mitigate: app-generated key shown once for operator-held storage; consequence stated (no recovery, tokens re-entered); restore proven per NFR-9 in Phase 5.
- **Risk:** model cost spike. Mitigate: per-run token caps, spend alerts, queue backpressure.

## Sources

- https://google.github.io/osv.dev/api/
- https://ossf.github.io/osv-schema/
- https://docs.github.com/en/rest/security-advisories/global-advisories
- https://google.github.io/osv-scanner/usage/
- https://github.com/betterleaks/betterleaks
- https://cli.github.com/manual/gh_pr_create
- https://docs.gitlab.com/api/merge_requests/
- https://docs.railway.com/integrations/api/manage-variables
- https://vercel.com/docs/rest-api/reference/endpoints/projects/create-one-or-more-environment-variables
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1
- https://github.com/HackerNews/API
- https://www.bleepingcomputer.com/feed/
- https://docs.langchain.com/oss/python/integrations/chat/openai
- https://docs.langchain.com/oss/python/langchain/tools
- https://docs.langchain.com/oss/python/langchain/middleware/built-in
- https://docs.langchain.com/oss/python/langgraph/overview
- https://github.com/tmc/langchaingo
