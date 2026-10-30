# H5 — Phase 4: Secrets Loop (detailed sub-plan)

Status: done (2026-10-30). Parent: [implementation plan](2026-10-29-implementation-plan.md)
plus the FR-8 sub-plan and [architecture.md](../architecture.md) (Phase 4,
Secrets branch). Pulls in [follow-up #17](../cross-phase-followups.md)
(diff secret-scan marker coverage, assigned to H5).

## Goal

Live secrets alert with a removal PR and rotation guidance; history is
baselined once and never re-alerts; a merged removal PR alone never closes;
closure needs HEAD-clean plus rotation confirmed. Per H5 validation: live
secret alerts + removal-PR; merged PR alone never closes; closure needs
HEAD-clean + rotation confirmed.

## FR-8 closure (just-in-time, decided here)

- **C1. Scanner invocation (Betterleaks v2, verified against upstream
  docs).** HEAD worktree: `betterleaks fs <workdir> --validate --output -`;
  history baseline: `betterleaks git <workdir> --validate --output -`.
  `--validate` on (D8), `--analyze` off, `revoke` never invoked. Runs
  unredacted: exact secret bytes are needed for surgical redaction, so
  output is treated as sensitive in memory and only
  rule/path/line/fingerprint/liveness are ever persisted — secret values
  never touch the DB, run notes, or the audit log (asserted by tests).
  The H1 manifest prefix `["betterleaks", "scan"]` does not exist in the
  v2 CLI and is corrected to `["betterleaks"]` with per-call subcommands.
- **C2. Baseline + new-only (D5/D6).** First secrets run per repo, or a
  rule-config change (`config_hash` from the report), does a full-history
  `betterleaks git` scan and records HEAD + config hash. Later runs scan
  the HEAD worktree (`fs`) in the same `run_scan` workdir (D6 piggyback:
  same sandbox run, same triggers; an `unshallow` fetch upgrades the
  depth-1 clone only on baseline runs). New-only is enforced by
  fingerprint dedup on (rule, path, fingerprint): history hits are
  reported once and never re-alerted. A full commit-range incremental
  (`--revision=base..HEAD`) is deferred as an optimization: the known gap
  is add-then-removed-between-runs dead secrets (→ follow-up).
- **C3. Liveness (D8).** `analysis.status` maps to live (`valid`), dead
  (`invalid`/`revoked`), unknown (anything else or absent). Unknown is
  treated as live for alerting (fail open); a dead verdict is sticky once
  observed and feeds closure (C6).
- **C4. Finding model.** New `secret_findings` table with its own
  lifecycle `open → proposed → awaiting_rotation → closed`, plus terminal
  `informational`. Live history-only hits (not at HEAD) go straight to
  `awaiting_rotation` with alert + guidance and no removal PR (history
  purge is out of v1, D5); dead baseline hits go `informational` with no
  alert and no PR; HEAD hits go `open` with alert + removal PR.
- **C5. Response (D1).** Alert = audit `secret-alert` entry + run note +
  OPEN finding (dashboard needs-action first). Channel fan-out stays in
  H6 behind the `notify_secret_alert` seam. Removal redacts the matched
  bytes: `KEY=value` lines become `KEY=${KEY}` (env reference), anything
  else becomes `***REMOVED***`; diff-scope validation (only secret lines
  change) plus a rescan-verify (fingerprint gone) gate the Proposal,
  which delivers through the existing deliver path with a secrets title,
  branch, and body. No diff is stored on the Proposal: a unified diff
  would rest the secret bytes in the DB via its `-` lines, so delivery
  re-derives the removal from current HEAD (also immune to stale
  patches). Removal PRs request MERGE gates like vuln PRs; the merge
  sync transitions no secret state.
- **C6. Closure (D7).** HEAD-clean (fingerprint absent from the `fs` scan)
  AND (human marks rotated in the dashboard — Owner/Maintainer, audited —
  OR a sticky dead verdict). Mark-rotated is only offered in
  `awaiting_rotation`, so a merged removal PR alone can never close.
- **C7. Failure posture.** The secrets stage never fails the vuln run
  (H3 `fetch_signals` isolation precedent): a missing binary or a scanner
  error lands as a loud run note + audit warning and the scan continues.
- **C8. Follow-up #17.** Patch diff secret checks run Betterleaks over
  the diff blob when the binary is present, with the 8-marker heuristic
  kept as the fallback when it is absent or errors.

## Slices (build order; each lands tested)

- **A. Data + lifecycle.** Tables: secret_findings, secret_baselines;
  `Proposal.secret_finding_id`; SecretStatus transitions incl.
  mark-rotated (approver-only, audited). Done when: migration 0008
  round-trips, lifecycle unit tests green.
- **B. Scanner adapter.** Manifest fix, fs/git invocation with
  `--validate`, JSON report parse (rule/path/line/fingerprint/liveness/
  config_hash), output caps, secret-bytes no-store discipline. Done when:
  recorded report fixtures yield canonical drafts; stored fields provably
  contain no secret bytes.
- **C. Baseline + new-only + closure engine.** Secrets stage in
  `run_scan` (same workdir, unshallow on baseline), history-once,
  fingerprint dedup, HEAD-clean detection, liveness updates,
  dead→informational, history-only-live→awaiting. Done when: fixture
  runs alert once, never re-alert, and drive HEAD-clean transitions.
- **D. Removal PR + delivery.** Redact + env-ref rewrite, diff-scope
  validate, rescan-verify, Proposal + deliver integration with secrets
  title/branch/body. Done when: live HEAD secret yields a removal PR;
  history-only yields none with reason.
- **E. Dashboard + #17.** Secrets in findings views with guidance,
  mark-rotated button, closure rule incl. merged-PR-never-closes;
  Betterleaks-backed diff secret check with marker fallback. Done when:
  rotated click closes an awaiting finding; merged PR alone does not.
- **F. Validation.** `secret-app` fixture + recorded Betterleaks JSON;
  e2e mirrors the H5 checks (alert + removal-PR / merged PR never closes
  / HEAD-clean + rotated closes / dead baseline informational /
  history-only awaiting). Offline only, plus a skip-if-missing live
  probe when the binary is on PATH.

Dependencies: A gates everything; B gates C; C gates D; D gates E; F last.

## Non-goals (deferred, see cross-phase follow-ups)

Channel delivery (H6 owns FR-13 fan-out), automatic rotation execution
(D4 guidance-only stands), history rewrite/purge (D5), commit-range
incremental scans, HMAC-keyed fingerprints (needs first-class secret
plumbing: the child-env sanitizer refuses secret-pattern keys),
managed-secret-provider integrations.

## Risks

- Betterleaks v2 CLI drift (mitigated: pinned invocation verified
  against upstream docs; unknown report shapes fail loud, never silent).
- Validation egress blocked by sandbox policy (mitigated: unknown
  liveness fails open toward alerting, never toward silence).
- Unredacted scanner output in worker memory (mitigated: memory-only,
  spooled to unlinked temp files, no-store asserted by tests; the clone
  itself already contains the secret).
