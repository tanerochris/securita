# FR-8 Secrets Loop — Sub-Plan

Status: **Final** (accepted 2026-10-27).

Parent: [2026-10-27-ai-security-agent.md](/Users/f3lx/Documents/projects/meta/docs/plans/2026-10-27-ai-security-agent.md) (v9) — FR-8, FR-9 (rotation gating, secrets-by-reference), NFR-4 (secret storage), FR-2 (scheduler reuse), FR-5 (proposal delivery), FR-13 (notifications).

## Parent constraints (carried in, not re-decided here)

- Betterleaks (replaces Gitleaks per D2) runs in-sandbox; history baseline exists (FR-8).
- Staged Railway and Vercel rotations happen behind approval (FR-8, FR-9).
- Rotation is gated: Owner/Maintainer approve, single approver suffices; zero rotations without approval; audit shows request→approve→execute (FR-9 D1b, NFR-7).
- Gated actions run only from the privileged backend post-approval; sandbox token cannot rotate (FR-9 D3).
- Secret values consumed by reference via env, never read; admins never re-view secrets (FR-9 D2b/D3, NFR-4).
- PR/MR/issue creation is free (no approval to propose); agent cannot merge (FR-9).
- Every scan in a fresh disposable sandbox; no secrets mounted inside (NFR-1, NFR-2).

## Settled decisions

None yet — each answer below is recorded here as it settles.

- **D1. Detection response ladder:** _settled_ — notify immediately (FR-13 routing) + auto-open removal PR (redact, replace with env reference; approval-free) + rotation guidance with alert. No automatic rotation execution in v1 (see D4); the FR-9 rotation gate stays defined but unused until staged rotation ships. No unapproved revoke/rotate.
- **D2. Secret types in scope:** _settled_ — Betterleaks replaces Gitleaks as the v1 scanner (same-team lineage, Go binary, in-sandbox CLI; pin a stable release, v2 migration revisited at build time). Default rules plus install-level allowlist (Expr/BPE filtering available for noise); custom rules deferred.
- **D3. Rotation mechanics:** _deferred past v1_ — was settled as a dual-value staged flow (provision new → stage alongside → redeploy → verify → revoke → confirm, abort-safe), parked by the D4 guidance-only decision. No auto-rotation in v1.
- **D4. Rotation eligibility:** _settled_ — guidance + alert for everything in v1 (via enabled FR-13 channels); no automatic rotation execution. The human rotates by hand following provider-specific guidance.
- **D5. History handling:** _settled_ — full-history scan once at connect (baseline), new-commits-only per run after. Historical hits reported once: live ones alert normally, dead ones informational, never re-alerted. History rewrite/purge out of v1; guidance-led rotation kills the value instead.
- **D6. Scan scheduling:** _settled_ — piggyback the FR-2 scheduler: Betterleaks runs in the same sandbox run under the same triggers (6h poll + connect + manual + webhooks); rule updates trigger a one-off history re-baseline.
- **D7. Finding closure:** _settled_ — two-part: HEAD rescans clean AND (human marks rotated in the dashboard OR scheduled re-validation shows the secret dead). A merged removal PR alone never closes a live-secret finding.
- **D8. Live validation / analysis posture:** _settled_ — validate on wherever the matched rule supports it (liveness verdict stored on the finding); analyze off in v1; built-in revocation not used — rotation flows only through the approval-gated D3 staged flow.

## Pending parent amendments

- **FR-8** detection responds with notify + auto removal-PR + rotation guidance/alert; no auto-rotation in v1 (D1, D4).
- **FR-8 / Phase 4 / sources** swap Gitleaks for Betterleaks (D2).
- **FR-8** liveness validation on where the rule supports it; analysis off; no scanner-side revocation (D8).
- **FR-8** staged-rotation design deferred past v1; parent "staged rotations behind approval" becomes guidance + alert (D3).
- **FR-8** history baselined once at connect, new-only after; live history hits alert once; no purge in v1 (D5).
- **FR-8** secrets scan piggybacks the FR-2 scheduler/run; re-baseline on rule updates (D6).
- **FR-8** findings close on HEAD-clean + rotation confirmed (human or re-validated dead) (D7).

## Scope contract (proposed — not yet accepted)

- **Artifact boundary:** this sub-plan file plus the listed parent-plan amendments (applied to the parent upon acceptance). Out of scope: runtime code, tests, other FR sub-plans, follow-on specs.
- **Done means:** every D-item above is settled or explicitly marked unresolved, and the user accepts this contract in writing. No D-item remains unresolved. Accepted (chat, 2026-10-27).
