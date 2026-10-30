# FR-12 Dashboard Views — Sub-Plan

Status: **Final** (accepted 2026-10-27).

Parent: [2026-10-27-ai-security-agent.md](/Users/f3lx/Documents/projects/meta/docs/plans/2026-10-27-ai-security-agent.md) (v11) — FR-12, FR-10 (accounts/roles), FR-9 (approval queue/audit), FR-2/FR-4/FR-5 (findings/patches), FR-8 (secrets closure).

## Parent constraints (carried in, not re-decided here)

- Dashboard shows findings, patches, approval queue, reports, notification settings (FR-12).
- Findings arrive as FR-2 typed records: package, advisory, severity, KEV flag, dependency path, prod/dev scope, fixed versions, citations, run id (FR-2 D6).
- Full evidence and disclosures live in the dashboard; proposals link back to the finding (FR-5 D7).
- Approval queue grants merge/rotation/publish; provider-side approval counts; 72h timeout re-queues; delegation audited (FR-9 D1b/D2c/D4/D5/D7).
- Secrets findings close on HEAD-clean + rotation confirmed (FR-8 D7).
- Roles Owner/Maintainer/Developer/Reporter with differentiated rights (FR-9 D1b, FR-10).
- Backend is FastAPI; Python one-runtime in v1 (decision 10, NFR-11).
- FR-3 (reachability verdicts, silenced-finding visibility) and FR-13 (notification channels) are open dependencies, decided in their own interviews.

## Settled decisions

None yet — each answer below is recorded here as it settles.

- **D1. Findings lifecycle states:** _settled_ — unified: open → proposed → resolved → closed, plus terminal unpatchable (report-only + issue) and silent-with-reason; secrets add awaiting-rotation before closed; rescan can reopen.
- **D2. "Reports" definition:** _settled_ — full reporting in v1: on-screen run summaries + outstanding-risk view, JSON/CSV export of findings and audit log, plus scheduled PDF/email digests (delivered via FR-13 channels; schedule per install).
- **D3. Patches + approval queue views:** _settled_ — split views, grouped by repository. Patches view: proposals with verification result, grouping pointers, PR/MR link + provider state, finding links (observe + link out, no merge button). Approval queue: pending merge/rotation/publish gates with full decision context, Approve/Deny (Owner/Maintainer), Owner delegation, timeout countdown, decided-gate history. Within each repo, sections put needs-action first (pending gates / attention-needed), then open proposals, then recent history; ordering is most-relevant-first (KEV-exploited, then severity, then newest).
- **D4. Notification settings screen boundary:** _settled_ — FR-12 owns the settings screen (channel list, per-severity routing, test-send buttons, digest schedule); FR-13 owns channel delivery mechanics.
- **D5. Frontend stack:** _settled_ — hybrid: Jinja + HTMX base with FastAPI-only routing; React islands only where justified (streaming chat, rich interactive widgets), lazy-loaded so first paint stays server-HTML fast; no island may block initial render. Node build exists only for island bundles.
- **D6. Chat view scope:** _settled_ — deferred past v1: no chat view. React islands reserved for future widgets (chat is the expected first candidate). Graphs live under reports/findings views.

## Pending parent amendments

- **FR-12** findings lifecycle: unified open → proposed → resolved → closed plus terminal unpatchable / silent-with-reason; secrets add awaiting-rotation; rescan reopens (D1).
- **FR-12** reports: on-screen run summaries + outstanding-risk view + JSON/CSV export + scheduled PDF/email digests via FR-13 channels (D2).
- **FR-12** patches + approval queue: split views grouped by repository, needs-action sections first, KEV/severity/recency ordering (D3).
- **FR-12** owns the notification settings screen; FR-13 owns delivery mechanics (D4).
- **FR-12** stack: Jinja + HTMX with FastAPI-only routing; lazy React islands where justified; Node build for island bundles only (D5).
- **FR-12** chat view deferred past v1; graphs live under reports/findings (D6).
- **Validation** gains dashboard checks: lifecycle transitions and reopen verified; digests delivered on schedule.

## Scope contract (accepted 2026-10-27)

- **Artifact boundary:** this sub-plan file plus the listed parent-plan amendments (applied to the parent upon acceptance). Out of scope: runtime code, tests, other FR sub-plans, follow-on specs.
- **Done means:** every D-item above is settled or explicitly marked unresolved, and the user accepts this contract in writing. Accepted with "Accept." (chat, 2026-10-27).
