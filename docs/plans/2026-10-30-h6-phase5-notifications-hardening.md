# H6 — Phase 5: Notifications, Hardening, Recovery (detailed sub-plan)

Status: done (2026-10-30). Parent: [implementation plan](2026-10-29-implementation-plan.md)
plus the NFR recovery/cost/hardening sub-plan, FR-9 (D5 fan-out), FR-12
(D2 reports/digests, D4 settings screen), FR-15 (D4 park/alert), and
[architecture.md](../architecture.md) (Phase 5, Integration + Data planes).
Pulls in follow-ups [#14 (scheduler N+1, SQL pushdown), #16 (key-ceremony
log disclosure), #31 (atomic run claim/lease)](../cross-phase-followups.md).

## Goal

Operators hear about every risk on their own channels; model spend is
capped with park + alert + resume; hostile inputs are proven inert by a
fixture suite that gates releases; backup/key-ceremony/restore is a
tested runbook. Per H6 validation: test-send per channel; injection
suite red blocks release; scratch-stack restore boots with login +
findings + decrypt audit.

## Just-in-time closures (decided here; FR-13 had no sub-plan)

- **C1. Channels (FR-13).** Email (SMTP+STARTTLS), Slack (incoming
  webhook), generic webhook (JSON POST, optional HMAC signature header).
  Bounded payloads/timeouts; failures audit-warn and never break the
  calling pipeline (H3/H5 isolation precedent); notifications fire
  after commit, never inside the transaction (H5 G8 precedent).
- **C2. Routing.** Per-severity routing to channel sets; severities are
  declared at the call site (secret-alert=critical, approval-request fans
  out to ALL channels per FR-9 D5, parked-cap=high, spend
  warn/critical=medium/high, new KEV=high, new reachable=medium,
  digest/test=info). Approval fan-out bypasses routing.
- **C3. Settings screen (FR-12 D4).** Owner-only router: channel CRUD,
  per-severity routing, test-send per channel, digest schedule, cost
  caps. Channel secrets (SMTP password, webhook URLs) live encrypted
  (`notify-channel:{id}` owners) and are never re-viewed (NFR-4 reuse).
- **C4. Digest (FR-12 D2).** Scheduled outstanding-risk digest per
  install (default daily 08:00 UTC) via email with a minimal
  dependency-free PDF attachment + text body; JSON/CSV export rides the
  same summary builder on-screen.
- **C5. Cost (NFR-8 D4/D5, FR-15 D4).** Token ledger per (run, task)
  from `usage_metadata` with a char-based fallback estimate; blended
  price `MODEL_PRICE_PER_MTOK_USD` (default $2.00, Owner-tunable
  estimate). Per-run cap 1M tokens (80% warn, once per run); hard stop
  parks the run (`parked` flag + reason, alert fires); worker skips
  parked runs; Owner/Maintainer raises the cap and resumes from the
  dashboard. Daily spend alerts warn $25 / critical $100 (once per
  level per day). Parked boolean (not a new enum value) keeps the
  migration portable across SQLite/Postgres.
- **C6. Injection suite (NFR-5 D7).** `tests/security/` fixtures:
  injected repo content, malicious tool output, poisoned feeds/news,
  exfil attempts, approval-bypass lures. Runs under pytest (CI gate);
  red blocks release. Boundary fixes land where the suite finds gaps.
- **C7. Backup/restore (NFR-9 D1/D3).** `security-agent-backup` +
  `security-agent-restore` entrypoints: pg_dump/pg_restore on Postgres,
  file-copy on SQLite; manifest JSON with sha256; retention prune.
  Backup dir `BACKUP_DIR` (default `./backups` bind mount, D1).
- **C8. Key ceremony (NFR-9 D2, #16).** Generated keys never touch the
  logging stream: emit to `/dev/tty` when present, else a 0600 file at
  `MASTER_KEY_FILE` (default `./master.key`) with a loud move-it
  warning. Runbook carries the ceremony.
- **C9. Scheduler (#14).** `due_repos` becomes one SQL query
  (NOT EXISTS running + dialect-portable due predicate); `reap` becomes
  one UPDATE; indexes on `(status, started_at)` and `last_scan_at`.
- **C10. Claim/lease (#31).** `claimed_by`/`claimed_at` on scan_runs;
  `claim_pending_runs(worker_id)` atomically claims via guarded UPDATE
  (rowcount==1 wins); 10-minute lease; worker id is a per-process uuid.
  Compose stays single-replica by default; scale-out is now safe.

## Slices (build order; each lands tested)

- **A. Notifications core.** Tables `notify_channels`, `notify_routes`,
  `notify_state`; transports; routing; `notify_event` seam; settings
  router + template; test-send; graph `notify` node goes real
  (run-summary event); `request_gate` + `notify_secret_alert` fan out.
  Done when: test-send per channel green (mock transports); routing
  respected; approval request reaches all channels.
- **B. Cost caps.** `model_usage` ledger; tracked brain invoke;
  per-run cap/warn/park; spend alerts; cap raise + resume (dashboard);
  worker skips parked. Done when: cap parks with alert; resume under
  raised cap works; spend alerts fire once per level per day.
- **C. Injection suite.** `tests/security/test_injection_suite.py` +
  fixtures; boundary fixes for gaps found. Done when: suite green and
  every hostile class is asserted inert (no host exec, no exfil, no
  auto-approve, no action from news/data).
- **D. Backup/restore.** Entrypoints; manifest; ceremony fix;
  `docs/runbooks/backup-restore.md`; scratch-stack proof test (seed →
  backup → wipe → restore → login + findings + decrypt audit). Done
  when: proof green; no key bytes in any log capture.
- **E. Scheduler + claim.** Migration 0011 (all H6 schema incl. A/B
  tables); SQL pushdown; atomic claim; worker adoption. Done when:
  concurrent claims serialize (two workers, one winner per run);
  due/reap covered by SQL-level tests.
- **F. Validation.** H6 e2e (offline, mock transports): fan-out,
  digest on schedule, park/resume, restore proof, injection gate.
  Full suite + ruff + format + mypy green. Done when: H6 validation
  sentence holds end to end.

Dependencies: E's migration first (schema for A/B); A gates F's
fan-out/digest; B gates F's park/resume; C/D independent after E.

## Non-goals (deferred)

Named pager templates (webhook covers), in-chat/in-email approve
(FR-9 D5 stands), rich PDF layout (minimal text PDF), per-task model
routing UI (FR-15 D3 dashboard part), auto-rotation, multi-replica
Compose default, L1/L2a/L2b/M1 audit items (separate pass).
`ruff format` stays green; new tables are covered by the migration test.

## Risks

- SMTP delivery variance across providers (mitigated: STARTTLS +
  plain fallback off; test-send proves the channel before use).
- Token-usage metadata absent from some model servers (mitigated:
  char-based fallback estimate, disclosed in the ledger).
- pg_dump/pg_restore availability in the app image (mitigated: entry
  points fail loud with install hints; SQLite path fully tested).
