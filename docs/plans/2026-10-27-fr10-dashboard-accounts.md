# FR-10 Dashboard Accounts — Sub-Plan

Status: **Final** (accepted 2026-10-27).

Parent: [2026-10-27-ai-security-agent.md](/Users/f3lx/Documents/projects/meta/docs/plans/2026-10-27-ai-security-agent.md) (v10) — FR-10, FR-11 (SSO), FR-9 (roles/approval rights), NFR-3 (transport), NFR-4 (secret storage).

## Parent constraints (carried in, not re-decided here)

- First signup is Owner; Owner creates and disables accounts (FR-10).
- Roles are Owner, Maintainer, Developer, Reporter; Owner and Maintainer approve (single approver suffices); Developer triggers scans and views findings, approves nothing; Reporter is view-only (FR-9 D1a/D1b).
- Google plus Microsoft login via standard OIDC at launch (FR-11).
- TLS everywhere; plain HTTP on localhost only; passwords and tokens cross the wire (NFR-3, decision 4).
- Passwords never cross plain HTTP off localhost (Validation: Auth).
- Account actions are audited with actor + role (FR-9 D6); admins never re-view secrets (NFR-4).
- Accounts live in the FastAPI app + Postgres (Phase 0).

## Settled decisions

None yet — each answer below is recorded here as it settles.

- **D1. Invitation / provisioning flow:** _settled_ — Owner enters email + role; system emails a single-use invite link (default 72h expiry, configurable; expired links need a fresh invite). User completes setup via the link: sets own password or links SSO. Link expires on use; invite tokens never re-viewable. Self-signup closed after first Owner except via invite.
- **D2. Password policy + storage:** _settled_ — min 12 chars, no forced complexity classes, reject known-breached passwords; Argon2id hash. Applies to password users only (SSO-only accounts have no local password). Change anytime; reset via emailed single-use link.
- **D3. MFA policy:** _settled_ — optional for all roles, opt-in; method per D3a.
- **D3a. MFA method:** _settled_ — TOTP with single-use backup codes in v1; WebAuthn deferred; SSO defers to IdP, no second local factor.
- **D4. Session handling:** _settled_ — server-side sessions; absolute 24h, idle 30min; immediate revoke on disable / role change / password reset; concurrent sessions allowed with per-session revoke list.
- **D5. Disable / remove semantics + Owner bootstrap lock:** _settled_ — disable-only in v1 (login blocked, sessions revoked, audit kept); hard delete deferred. Cannot disable or demote the last Owner. Open registration until the first Owner exists, invite-only after.

## Pending parent amendments

- **FR-10** invitation flow: Owner enters email + role, single-use invite link (72h default), user sets password or links SSO (D1).
- **FR-10** password policy: min 12 chars, no complexity classes, breach-check, Argon2id; password users only (D2).
- **FR-10** MFA: optional for all, opt-in; TOTP + backup codes in v1, WebAuthn deferred, SSO defers to IdP (D3/D3a).
- **FR-10** sessions: server-side, 24h absolute, 30min idle, immediate revoke on disable/role-change/reset, concurrent allowed with revoke list (D4).
- **FR-10** disable-only v1, delete deferred; last-Owner guard; registration closes after first Owner (D5).
- **Validation Auth** gains checks: invite expiry enforced, disabled account loses sessions immediately, last Owner cannot be disabled/demoted.

## Scope contract (accepted 2026-10-27)

- **Artifact boundary:** this sub-plan file plus the listed parent-plan amendments (applied to the parent upon acceptance). Out of scope: runtime code, tests, other FR sub-plans, follow-on specs.
- **Done means:** every D-item above is settled or explicitly marked unresolved, and the user accepts this contract in writing. Accepted with "Accept" (chat, 2026-10-27).
