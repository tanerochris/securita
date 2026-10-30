# Phase 0 Audit — Deferred Low / Minor Findings

Status: accepted deferrals from the Phase 0 security/perf review (2026-10-29).
All Medium/High items were patched in code; the items below are intentionally
deferred and revisited at the stated triggers.

Parent: [2026-10-29-implementation-plan.md](/Users/f3lx/Documents/projects/meta/docs/plans/2026-10-29-implementation-plan.md).

## Low (deferred)

- **L1 — Database grows without bound.** Expired sessions and used/expired
  invites/resets are deleted only lazily on access; no periodic sweep exists.
  Location: `sessions`, `invites`, `password_resets` tables. Revisit: with the
  worker scheduler (H2) or Phase 5 hardening — add a periodic purge of rows
  past expiry/idle TTL.
- **L2 — Race windows on account bootstrap.** Concurrent first-signups can
  both observe `user_count() == 0` and create two Owners; concurrent invite
  redemptions use check-then-set and could double-spend an invite under
  parallel requests. Locations:
  [auth.py](/Users/f3lx/Documents/projects/meta/src/security_agent/app/routers/auth.py)
  (`signup`), `redeem_invite` in `accounts.py` service. Revisit: before any
  multi-instance or multi-operator deployment — use an atomic conditional
  `UPDATE … WHERE used_at IS NULL` and serialization (advisory lock or unique
  constraint) for first-Owner creation. Single-container Phase 0 impact is
  small, hence deferred.
- **L3 — Offline migrations unsupported.** [env.py](/Users/f3lx/Documents/projects/meta/migrations/env.py)
  only supports online (live DB) upgrades; `alembic upgrade --sql` does not
  work. Revisit: when the backup/restore runbook (H6/Phase 5) needs offline
  SQL generation.

## Minor (deferred)

- **M1 — HTMX from CDN without SRI.** [base.html](/Users/f3lx/Documents/projects/meta/src/security_agent/app/templates/base.html)
  loads `htmx.org` from unpkg with no integrity hash; breaks offline installs
  and trusts the CDN. Revisit: before first production release — self-host
  the asset under `static/`.
- **M2 — TRY003 lint noise (14 findings).** Long messages inline at `raise`
  sites instead of named exception classes; style only, no behavior change.
  Revisit: opportunistically as modules gain exception taxonomies.
- **M3 — Magic value in key-length check.** The `32` (AES-256 key bytes) in
  `crypto.py` key decoding should be a named constant. Revisit: next crypto
  touch.
- **M4 — All-interfaces bind default.** `APP_HOST=0.0.0.0` in
  [config.py](/Users/f3lx/Documents/projects/meta/src/security_agent/config.py)
  is intentional inside containers (Compose maps the port); not a finding in
  deployment, noted so it is never exposed without the proxy/TLS posture in
  the README.
