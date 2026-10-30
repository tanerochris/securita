# Security Audit Follow-ups — Low / Minor (deferred)

Patched this run (medium-high): TOTP/subkey encryption, HKDF session signing,
editable dev image, SSO `(provider, sub)` check + verified-email gate, logout
revoke, password reset, CSRF, login rate limit + timing equalization, audit
retention purge, session-touch throttle, HIBP backoff cache, tool timeout +
output cap + concurrency cap, single-session owner guard, fail-fast
migrations, DB-aware `/health`, mypy gate. Regression tests in
`tests/unit/test_audit_patches.py` (37 passed total).

The items below were audited, risk-accepted for now, and parked for a later
pass. Each entry gives location, risk, and the intended fix.

## Low

### L1 — DB grows without bound (expired sessions/invites/resets)
- Where: `src/security_agent/app/accounts.py` — `validate_session`,
  `redeem_invite`, `redeem_reset` delete lazily on access only.
- Risk: expired rows accumulate; table bloat over months.
- Fix: periodic sweep (`DELETE FROM sessions WHERE ...`, same for invites
  and `password_resets`), e.g. hourly worker task or Postgres `pg_cron`.
  Add a test that seeds expired rows, runs the sweep, and asserts removal.

### L2a — Concurrent first-signups can both create Owners
- Where: `src/security_agent/app/routers/auth.py` (`/signup`) +
  `src/security_agent/app/accounts.py` (`user_count`, `create_user`).
- Risk: two simultaneous first signups both see count 0 and become Owner.
- Fix: serialize first-Owner creation (advisory lock or unique partial
  index + catch-and-retry as Reporter). Test with two concurrent signups,
  assert exactly one Owner.

### L2b — Concurrent invite redemptions can double-spend
- Where: `src/security_agent/app/accounts.py` (`redeem_invite`,
  check-then-set on `used_at`).
- Risk: two redemptions of the same token both succeed under race.
- Fix: atomic `UPDATE invites SET used_at=now() WHERE token_hash=:h AND
  used_at IS NULL AND expires_at > now()`; treat rowcount 0 as invalid.
  Same pattern for `redeem_reset`. Test with concurrent threads, assert
  exactly one success.

### L3 — Extended lint rulesets not yet enabled
- Where: repo-wide. Configured `E,F,I,UP,B,S` pass; `TRY, PERF, RET, SIM,
  PLR` would add ~23 findings (mostly TRY003 long-message style).
- Risk: style-only; no known exploitable finding in the extra set.
  Noted sub-items: `assert` already absent from prod code (tests only);
  S324 SHA-1 is HIBP-mandated with `usedforsecurity=False`; S603
  subprocess is manifest-allowlisted with `shell=False`; S104 bind is a
  documented container default.
- Fix: enable incrementally (`TRY` first with `TRY003` waived or fixed),
  then `PERF/RET/SIM`. Keep `S` (or bandit) as the release gate.

## Minor

### M1 — HTMX loaded from CDN without SRI
- Where: `src/security_agent/app/templates/base.html:3`
  (`https://unpkg.com/htmx.org@2.0.4`).
- Risk: supply-chain tampering; availability depends on third party.
- Fix: vendor `htmx.min.js` under `src/security_agent/app/static/` and
  serve via the existing `/static` mount (see `main.py`), or pin with an
  SRI hash. Test that no template references an external script URL.

## Re-check procedure
1. Implement one item at a time with a regression test.
2. Run `.venv/bin/python -m pytest -q`,
   `.venv/bin/python -m ruff check .`,
   `.venv/bin/python -m ruff format --check .`, and mypy (`mypy src`).
3. Move the entry out of this file into the patched list at the top.
