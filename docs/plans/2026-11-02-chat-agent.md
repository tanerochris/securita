# Chat Agent — platform-wide conversational operator

Status: **Final** (accepted 2026-11-02; grill complete, 8/8 decisions settled).
Target: plan the chat agent; execution of the scope boundary below authorized.

## Goal (accepted)

A chat interface in the dashboard through which the agent can do whatever is
currently possible via the UI: run vulnerability scans, query findings /
patches / runs / news / policies / reports, and act through custom tools
with the same backend capabilities the UI uses.

## Settled decisions

1. **Approval gates are decidable in chat (2026-11-02).** The agent surfaces
   each pending gate in the chat UI with approve / decline options; the user
   decides in chat and that decision executes. This overrides FR-9 D5
   (no-in-chat-approve v1). Same RBAC (Owner / Maintainer approve,
   single approver suffices) and full audit context as the dashboard queue.

2. **In-chat execution scope (2026-11-02).** Chat executes approval-gate
   decisions plus operational writes (scan-now, dependency decisions, policy
   rules, notification routes / digests, cost caps, delegations), each with
   an explicit confirmation step. Dashboard-only: user-admin
   (invite / disable / role change) and all raw credential entry (tokens,
   PATs, webhook secrets, passwords) — the agent explains and links out.
   Rationale: raw secret material must never enter chat history or model
   context; account changes keep the dashboard's ceremony.

3. **Identity: act as the logged-in user (2026-11-02).** Chat endpoints use
   the existing session + CSRF; every tool call enforces the same role checks
   as its dashboard counterpart (Developer triggers scans and approves
   nothing; Reporter read-only, including in chat). No separate agent
   identity, no elevation, no step-up beyond the dashboard's own ceremony.

4. **Scan UX: async with progress in chat (2026-11-02).** "Scan repo X"
   triggers scan-now and replies immediately with the run link; milestones
   stream into the conversation and a findings summary with links posts on
   completion. Reuses the existing run + live-event machinery.

5. **Chat surface: full page + widget, one backend (2026-11-02).**
   Dedicated /chat page plus a floating widget on dashboard pages, sharing
   one backend and one persistent per-user history (Postgres). Repo context
   selector (one repo or all repos); approve / decline and confirmation
   cards render inline in both surfaces.

6. **Tool execution: two classes (2026-11-02).** Backend-direct tools reuse
   the routers' control functions for all UI-parity reads / writes
   (identical behavior + RBAC). Sandbox-mediated tools (fresh disposable
   container per investigation, same execution policy as the worker) answer
   live repo-content questions (grep, file reads, import chains). Zero
   host-executed agent commands preserved (NFR-1).

7. **Model + cost: reuse the brain, chat-shaped cap (2026-11-02).** Chat
   gets its own "chat" slot in the dashboard-configurable per-task model
   matrix (substitution applies, probe-gated, OpenAI-compatible only).
   Daily spend alerts apply, plus a dedicated Owner-configurable per-day
   chat cap with hard stop + in-chat notice at the cap.

8. **Injection armor: strict boundaries, suite-gated (2026-11-02).**
   Untrusted content (repo code, news, policy docs, provider data) enters
   chat context only as labeled data blocks, never instructions.
   Write-confirmation cards render exact action + target from structured
   tool args, never model prose. The injection fixture suite gains chat
   scenarios and gates the chat release (NFR-5).

## Unresolved questions

None — decision tree exhausted. Scope contract below awaits explicit acceptance.
3. Model + cost: reuse per-task brain models and per-run caps for chat turns?
4. Injection handling: untrusted repo / news / policy content rendered in chat?

## Scope contract (proposed — awaits explicit acceptance)

**Artifact boundary — in scope:** new chat router + templates (full page +
widget), chat agent graph + backend-direct and sandbox-mediated tool modules,
conversation-history tables + migration, per-day chat cap wiring, chat
injection fixtures, and updates to `docs/architecture.md` (FR-9 D5 override,
FR-12 chat note).

**Out of scope:** user-admin in chat, raw secret/credential entry in chat,
React islands or other new frontend builds, worker pipeline behavior changes,
multi-tenancy, voice / non-dashboard surfaces.

**Done means:** /chat page + widget live sharing one history; all 8 settled
behaviors demonstrated; unit + injection-suite + e2e tests pass; ruff and
mypy clean. Nothing outside this checklist is a completion dependency.

**Acceptance:** user replied "go" (chat, 2026-11-02) — scope accepted and
execution of this boundary only authorized.
