# H5 — Phase 4 (Secrets Loop) Implementation Review

Date: 2026-10-30. Scope: review of the H5 implementation against
[the H5 sub-plan](plans/2026-10-30-h5-phase4-secrets.md) (C1–C8,
Slices A–F) and the parent decisions in
[the FR-8 sub-plan](plans/2026-10-27-fr8-secrets-loop.md) (D1–D8),
plus optimization, memory/leak, concurrency, security, and
best-practice review of the code H5 touched and the shared code it
runs on. No product code was changed by this review.

Method: full read of the H5 modules and their callers, execution of
the focused and full test suites and the lint/type gates, and
throwaway probes (kept outside the repo) that reproduced every
confirmed gap below against the real code before it was recorded.

## Verdict

**H5 is functionally implemented as planned, with 2 high-severity
gaps (plus 1 high deployment gap), 4 medium gaps, and several low
confirmed gaps. No H5 slice is missing.**

The detect → baseline → removal-PR → awaiting-rotation → closure
loop works end-to-end and satisfies the H5 validation sentence:
live secret alerts with a removal PR; a merged PR alone never
closes; closure needs HEAD-clean plus rotation confirmed. The
no-store discipline holds for the database, run notes, and audit
log. The gaps are correctness, persistence, and hardening defects
inside otherwise-present features — most importantly a leaked
secret that can reappear at HEAD without ever re-alerting (G1),
secret bytes persisted to disk by delivery (G2), and a removal PR
closed unmerged stranding its finding forever (G3).

Do not read this as "release-ready": the Docker sandbox
(follow-up #1) is still a stub, neither scanner binary is in the
image, and production stays fail-closed (see Security S1–S2).

## Gate results (parent-run, this review)

| Gate | Command | Result |
|---|---|---|
| H5 focused tests | `pytest tests/unit/test_secrets_{engine,scan,lifecycle,removal}.py tests/integration/test_secrets_dashboard.py tests/e2e/test_h5_validation.py -q` | 39 passed, 1 skipped |
| Full suite | `pytest -q` | 351 passed, 4 skipped |
| Skips | — | `test_h2_validation.py:253` and `test_h4_validation.py:288` osv-scanner not on PATH; `test_h5_validation.py:251` betterleaks not on PATH; `test_deliver.py:538` ssh signing unavailable. All environmental. |
| Lint | `ruff check src tests` | All checks passed |
| Types | `mypy src` | Success, no issues in 41 files |
| Format | `ruff format --check src tests` | **FAIL** — 10 files would be reformatted (see B1) |

Test PASS claims were corroborated by execution. Gap claims G1–G8
were each reproduced with a throwaway probe against the real code
(probe outcomes are quoted inline). Code citations use `file:line`.

## Plan-compliance matrix

| Clause | Verdict | Evidence |
|---|---|---|
| C1 `fs`/`git` invocation with `--validate`, `--analyze` off, `revoke` never invoked | PASS | [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:73) `scan_worktree`; [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:78) `scan_history`; [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:46) `_run_betterleaks` appends only `--output -` plus optional `--config` |
| C1 manifest prefix corrected to `["betterleaks"]` | PASS | [tools.py](/Users/f3lx/Documents/projects/meta/src/security_agent/sandbox/tools.py:25); asserted by `test_secrets_scan.py:121` |
| C1 secret values never persisted (DB / notes / audit) | PASS for DB/notes/audit; **GAP G2** on disk | [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:132) `normalize_report` stores rule/path/line/fingerprint/liveness only; e2e `test_h5_validation.py:163` asserts absence. Delivery patch files break the same discipline — see G2 |
| C2 first-run / config-change history baseline; later runs HEAD-only | PASS with **GAP G4** | [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:372) `_needs_baseline`; [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:384) `_record_baseline`; unshallow only on baseline at [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:249) |
| C2 new-only by (rule, path, fingerprint) dedup | PASS | Unique constraint in [models.py](/Users/f3lx/Documents/projects/meta/src/security_agent/db/models.py:396); insert-first race handling in [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:296) |
| C3 liveness mapping; unknown fails open; dead is sticky | PASS with **GAP G6** | [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:117) `liveness_of`; sticky OR at [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:334). History-side refresh missing — see G6 |
| C4 finding model and lifecycle `open → proposed → awaiting_rotation → closed` + `informational` | PASS | [models.py](/Users/f3lx/Documents/projects/meta/src/security_agent/db/models.py:387) `SecretFinding`; [lifecycle.py](/Users/f3lx/Documents/projects/meta/src/security_agent/control/lifecycle.py:137) `SECRET_TRANSITIONS`; migration 0008 round-trips (`test_migrations.py:70`) |
| C4 history-only live → `awaiting_rotation`, no PR; dead baseline → `informational`, no alert; HEAD → `open` + PR | PASS (one ambiguity, R2) | [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:342) history loop; [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:322) HEAD loop |
| C5 alert = audit + run note + OPEN finding; H6 fan-out behind a seam | PASS with **GAP G8** | [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:214) `notify_secret_alert` (audit seam only); stage notes appended in [scan.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:797) |
| C5 redact `KEY=value` → `KEY=${KEY}`, else `***REMOVED***`; diff-scope + rescan-verify gate the Proposal | PASS | [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:472) `redact_line`; [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:593) `validate_removal` |
| C5 no diff stored on the Proposal; delivery re-derives from HEAD | PASS for the DB; **GAP G2** on disk | [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:674) `patch=None`; [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:696) `apply_secret_removal` |
| C5 removal PRs request MERGE gates; merge sync moves no secret state | PASS | [deliver.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/deliver.py:537) `request_gate` after PR; [deliver.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/deliver.py:754) `_apply_provider_state` touches findings only via `finding_ids` (empty for secret proposals) — proven by `test_h5_validation.py:201` |
| C6 closure = HEAD-clean AND (mark-rotated OR sticky dead); mark-rotated only in `awaiting_rotation`, Owner/Maintainer, audited | PASS with **GAP G5, G6** | [lifecycle.py](/Users/f3lx/Documents/projects/meta/src/security_agent/control/lifecycle.py:169) `mark_secret_rotated`; same-run dead closure in [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:364) |
| C7 secrets stage never fails the vuln run; failure = loud note + audit warning | PARTIAL — **GAP G7, G8** | Isolation holds at [scan.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:796); the audit half is missing and history failures poison the stage — see G7/G8 |
| C8 diff secret check: Betterleaks `stdin` engine first, 8 markers as fallback (follow-up #17) | PASS | [secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:83) `scan_diff_blob` (no `--validate`, redacted, rule IDs only); [patch.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:78) `diff_secret_violations` degrades to markers on engine error |
| Slice A data + lifecycle (migration 0008) | PASS | `test_secrets_lifecycle.py` (5 tests); `test_migrations.py:70` 0008 round-trip |
| Slice B scanner adapter (parse, caps, no-store) | PASS | `test_secrets_scan.py` (12 tests) incl. recorded fixtures and fake-binary `stdin` end-to-end |
| Slice C baseline + new-only + closure engine | PASS with G1/G4/G6/G7 | `test_secrets_engine.py` (7 tests) |
| Slice D removal PR + delivery | PASS with G2/G3 | `test_secrets_removal.py` (8 tests) |
| Slice E dashboard + #17 | PASS with G5 | `test_secrets_dashboard.py` (4 tests); findings template shows guidance + Confirm-rotated only for approvers in `awaiting_rotation` |
| Slice F validation (fixture + recorded JSON, offline, skip-if-missing live probe) | PASS | `test_h5_validation.py` (4 tests, live probe skipped here — binary absent) |

## Confirmed gaps (each reproduced by probe)

### G1 — High — A closed or informational secret that reappears at HEAD never re-alerts

In [reconcile](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:322),
an existing row found in the HEAD (`fs`) scan has its liveness and
line refreshed, but only an `AWAITING_ROTATION` row is reopened.
`CLOSED` and `INFORMATIONAL` are terminal in
[SECRET_TRANSITIONS](/Users/f3lx/Documents/projects/meta/src/security_agent/control/lifecycle.py:137),
so the same fingerprint recommitted after rotation — or a baseline
dead hit later committed live to HEAD — updates `liveness` to
`live` and then is ignored forever: no alert, no removal PR, and
the unique key prevents a new row.
Probe (real code, test DB): close a finding via the dead path,
reconcile the same fingerprint at HEAD — stats all zero, status
stays `closed` with `liveness=live`. Same result starting from
`informational`.
Fix: treat HEAD presence of a `closed`/`informational` fingerprint
as a new incident — reopen (new lifecycle edge or a superseding
row) and alert. Add reconcile tests for both reappearances.
→ Follow-up #20.

### G2 — High (security) — Secret delivery persists the secret bytes to disk, and delivery artifacts are never pruned

Plan C5 stores no diff on the Proposal because a unified diff
"would rest the secret bytes in the DB via its `-` lines". The
delivery path then writes exactly that diff to disk:
[_deliver_secret_group](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/deliver.py:528)
runs `git format-patch -1 HEAD` into `deliveries/run-<id>/` for
every secret removal (and [_deliver_group](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/deliver.py:605)
does the same for vuln PRs). Probe: a one-line removal commit's
`.patch` file contains the original secret value verbatim
(`SECRET IN PATCH FILE: True`).
The `deliveries/` tree is also never cleaned — every delivery adds
patch/issue files with no retention, an unbounded disk leak.
Note the provider PR diff inherently shows the removed line until
rotation; the local patch file is a second, quieter copy that
outlives the wiped workdir.
Fix: skip `format-patch` for secret proposals (branch + PR are the
artifact), or write a redacted patch; add a retention sweep for
`deliveries/`. Extend the e2e no-store assertion to the delivery
directory — today `test_h5_validation.py:163` covers findings,
proposals, notes, and audit, but not the patch files.
→ Follow-up #21.

### G3 — Medium — A removal PR closed unmerged strands its finding in `proposed` forever

`SECRET_TRANSITIONS` allows `proposed → open` ("the removal PR died
unmerged"), but no code drives it. Provider sync
([_apply_provider_state](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/deliver.py:754))
flips vuln findings via `finding_ids`; secret proposals carry
`finding_ids=[]`, so a closed-unmerged PR updates only the
Proposal row. Probe: `_apply_provider_state(pid, "closed", False)`
leaves the secret `proposed`. From there,
[run_secrets_removal](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:633)
only picks up `open` rows, and reconcile only moves `proposed`
when HEAD rescans clean — with the secret still at HEAD, nothing
ever re-proposes a removal.
Fix: in the provider-state sync (and the ancestry path), flip a
secret finding `proposed → open` when its PR closes unmerged.
→ Follow-up #22.

### G4 — Medium — Baseline config-hash source mismatch can re-baseline on every run

[_needs_baseline](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:372)
compares the stored hash against the **fs** report's
`config_hash`, but [_record_baseline](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:384)
stores `hist_hash or config_hash` — the **history** report's hash
wins. Probe: with fs hash `fs-hash` and history hash `hist-hash`,
two consecutive stages invoke the history scan twice
(`hist calls: 1 → 2`) instead of once. Each spurious re-baseline
pays a `git fetch --unshallow` plus a full-history Betterleaks run
(600 s timeout each) and re-walks every commit.
Fix: record and compare one canonical hash (the fs hash the check
uses). The existing baseline test mocks both hashes equal, so it
cannot see this.
→ Follow-up #23.

### G5 — Medium — Rotation confirmation does not check the secret belongs to the URL's repo

[confirm_rotated](/Users/f3lx/Documents/projects/meta/src/security_agent/app/routers/repos.py:149)
verifies the repo exists, then calls
[mark_secret_rotated](/Users/f3lx/Documents/projects/meta/src/security_agent/control/lifecycle.py:169)
with only the secret id — `SecretFinding.repo_id` is never compared
to the path `repo_id`. Probe: a secret owned by repo A closes
through a call carrying repo B's id (the lifecycle layer has no
repo parameter to check). Roles are global (Owner/Maintainer), so
this is an integrity/IDOR defect rather than a privilege
escalation, but any approver can close any repo's awaiting secret
through any repo URL, with the audit line naming only the secret.
Fix: load the finding in the route (or pass `repo_id` into
`mark_secret_rotated`) and 404/400 on mismatch.
→ Follow-up #24.

### G6 — Low/Medium — Dead re-validation is never refreshed from history, so history-only secrets can only close by hand

The history loop in
[reconcile](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:342)
skips any key already in `existing` (`HEAD-present handled above;
known hits never re-alert`), so a history-only `awaiting_rotation`
row never receives a later dead verdict: `liveness` and
`dead_verdict` are only refreshed for HEAD-present rows
([secrets.py:332](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:332)).
Probe: baseline a live history hit, reconcile again with the same
fingerprint now `dead` — status stays `awaiting_rotation`,
`dead_verdict` stays false. The dead-closure leg of C6 therefore
only fires when dead was observed while the secret was still at
HEAD and HEAD then cleaned in a later run (the tested path,
`test_secrets_engine.py:86`). That is a defensible reading of D7,
but the history re-validation leg is effectively dead code.
Fix: refresh `liveness`/`dead_verdict` from history drafts for
existing rows without re-alerting, then let the existing
awaiting+dead closure fire.
→ Follow-up #25.

### G7 — Medium — A history-scan failure discards the whole stage, including good HEAD results

In [run_secrets_stage](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:432),
only `_ensure_full_history` failure is isolated (deferred with a
note). A `scan_history` failure after a successful fs scan raises
out of the stage, so `reconcile` never runs: new HEAD secrets are
not stored, not alerted, and get no removal proposal that run.
Probe: fs report with one live finding + history raising
`SecretError` — stage raises, zero findings persisted. The vuln
run still finishes (C7 isolation at
[scan.py:796](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:796)
holds), but a broken history path silently suppresses HEAD
detection on every baseline/re-baseline run.
Fix: reconcile the fs drafts first (or on history failure), and
treat history failure like the deferred-baseline path: note +
audit + retry next run.
→ Follow-up #26.

### G8 — Low — C7's audit warning is missing, and alerts are written before the transaction commits

C7 promises "a loud run note + audit warning" for a missing binary
or scanner error. The run-note half exists; the audit half does not
outside the deferred-baseline branch. Probe: with the binary
absent, `run_secrets_stage` returns the skip note and appends zero
`secret` audit entries; scanner errors surface only as a Python
`log.warning` in [scan.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:800).
Separately, `notify_secret_alert` is called from inside
[reconcile](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:330)'s
open transaction (before `session_scope` commits at scope exit), so
a late flush/commit failure rolls back the finding while the alert
stays in the shared audit log — a phantom alert with no finding.
Fix: append a `secret`/`warning` audit entry on the skip and stage-
failed paths (the caller in `scan.py` is the natural place), and
move `notify_secret_alert` after commit (collect created ids in
`reconcile`, notify in `run_secrets_stage`).
→ Follow-up #27.

## Security

Overall: the secrets logic is sound in isolation — argv-only
execution, no-store normalization, symlink containment, sticky-dead
liveness, audited rotation. The dominant risks are inherited from
the shared execution plane plus G2 above.

### S1 — Critical (pre-prod blocker, follow-up #1, not an H5 slice failure)

[assert_host_execution_allowed](/Users/f3lx/Documents/projects/meta/src/security_agent/sandbox/__init__.py:30)
blocks only `is_prod`. The Docker runner is still a sleep-stub
([runner.py](/Users/f3lx/Documents/projects/meta/src/security_agent/sandbox/runner.py:6)),
so in any non-prod deployment hostile repo code executes on the
host, and in prod the pipeline fails closed and does not run at
all. H5 inherits this unchanged: Betterleaks `--validate` callbacks,
`git fetch --unshallow`, and the removal rescan all run as host
subprocesses via [tools.py](/Users/f3lx/Documents/projects/meta/src/security_agent/sandbox/tools.py:125).
**Release gate: do not scan untrusted repos outside a throwaway
environment until #1 lands.**

### S2 — High — Neither scanner binary ships in the image

The [Dockerfile](/Users/f3lx/Documents/projects/meta/Dockerfile)
installs only Python dependencies. There is no `betterleaks` (H5)
or `osv-scanner` (H2) binary in the app/worker image, so a Compose
deployment silently skips the secrets stage on every run
("betterleaks not on PATH") and cannot complete vuln scans. Tests
cannot see this — every test fakes the scanner and the one live
probe skips. This is the deployment half of follow-up #1: the
sandbox image must pin and install both binaries.
→ Follow-up #28.

### S3 — Medium — Private-repo baselines cannot fetch full history

[_ensure_full_history](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:249)
runs `git fetch --unshallow` against the credential-stripped origin
([clone_repo](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:106)
removes the token after cloning; only
[_push_branch](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/deliver.py:403)
re-attaches it). Private repos will fail the unshallow on every
baseline attempt, defer forever, and never record history — with
only a run note to show for it. Fix alongside G4/G7: re-attach the
repo token for the fetch with the same redaction discipline as
push, or record the deferral durably so it stops retrying blindly.
→ Folded into follow-up #26.

### Confirmed security positives

- `shell=False` with manifest-prefix argv only; the v2 prefix fix
  is asserted by test ([tools.py:25](/Users/f3lx/Documents/projects/meta/src/security_agent/sandbox/tools.py:25)).
- Secret values are memory-only: the scanner's temp output spools
  to unlinked files and only a capped head is read back
  ([tools.py:168](/Users/f3lx/Documents/projects/meta/src/security_agent/sandbox/tools.py:168));
  drafts carry no bytes and the e2e asserts findings/proposals/
  notes/audit are clean.
- Diff checking never validates: `scan_diff_blob` omits
  `--validate` so candidate secrets are never sent to providers,
  and only rule IDs leave the function
  ([secrets.py:83](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:83)).
- Removal refuses untracked files, oversize files, stale
  locations, and symlink escapes
  ([secrets.py:531](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:531));
  tracked-file gating plus diff-scope and rescan verification mean
  a proposal cannot touch a non-secret line.
- Alert lines are sanitized before hitting the audit log
  ([secrets.py:224](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:224)),
  rotation is Owner/Maintainer-only and audited after commit
  ([lifecycle.py:169](/Users/f3lx/Documents/projects/meta/src/security_agent/control/lifecycle.py:169)),
  and child processes get an allowlisted environment with
  secret-pattern keys refused
  ([tools.py:96](/Users/f3lx/Documents/projects/meta/src/security_agent/sandbox/tools.py:96)).
- Plain-SHA256 fingerprints remain guessable for low-entropy
  values — already tracked as follow-up #19, not re-filed.

## Memory, leaks, and performance

No unbounded process-memory leak was found in the H5 code itself:
tool output spools to temp files with a capped head read, the audit
store is a bounded deque under a lock, sessions close on all paths,
and every pipeline temp dir is reaped in a `finally`. Two genuine
leaks and several transient/quadratic costs sit around it:

| ID | Sev | Finding |
|---|---|---|
| M1 | Med (leak) | The rate limiter grows without bound and contradicts its own docstring. [_buckets](/Users/f3lx/Documents/projects/meta/src/security_agent/app/ratelimit.py:10) is a `defaultdict` keyed by `(ip, path)`; stale entries are swept only when the *same* key is seen again. Probe: 5,000 distinct IPs leave 5,000 buckets resident forever. Rotating source IPs — exactly the login-attack shape the limiter exists for — grow the dict for the life of the process. Fix: periodic/global sweep or a capped LRU of buckets. → Follow-up #29. |
| M2 | Med (disk leak) | `deliveries/` is never pruned (see G2). Every `run_deliver` writes `format-patch`/issue files under `deliveries/run-<id>/` with no retention anywhere in the codebase. → Follow-up #21. |
| M3 | Med | [reconcile](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:290) loads **every** `SecretFinding` row for the repo as ORM objects on every scan, and [list_repo_secrets](/Users/f3lx/Documents/projects/meta/src/security_agent/control/lifecycle.py:202) does the same then sorts in Python. `secret_findings` has no retention and no `(repo_id, status)` index, so a long-lived repo's per-scan and per-page-view cost grows with its entire secret history. Fix: column-only selects (the news `_Candidate` pattern), SQL-side ordering, and a status index. → Follow-up #30. |
| M4 | Med | Repeated full `--validate` scans. One scan run pays fs (600 s cap) + history on baseline + a validation rescan in [validate_removal](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:616); each delivered secret pays two more (scan + rescan-verify in [apply_secret_removal](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:713)), each in a fresh clone, sequentially per secret. `--validate` also makes provider calls per secret. Fix: reuse the run's fs report where HEAD is unchanged, batch delivery verification, key a scan cache on HEAD sha. → Follow-up #30. |
| M5 | Low | A 25M-char report is fully buffered twice — the capped string plus `json.loads`' parsed tree, which retains every secret `value`/`full` until `run_secrets_removal` finishes. A report past the cap truncates into invalid JSON and fails the stage (compounding G7). Fix: extract the removal plan, then drop value fields before reconciling; consider a streaming parse for history reports. → Follow-up #30. |
| M6 | Low | Small shared caches are unsynchronized or share mutable values: [_lock_packages_cache](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:241) mutates a plain dict with a check-clear-set sequence and hands out the cached dict; [kev_exploited_ids](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:54) returns the cached `set` itself; the HIBP caches in [accounts.py](/Users/f3lx/Documents/projects/meta/src/security_agent/app/accounts.py:32) (512-entry cache plus a fail-map whose entries are only removed on a later success for the same prefix) have no lock. All are safe under today's single-threaded worker / GIL, fragile under any future threading. Fix: lock or copy-on-return while touching M1. → Follow-up #29. |
| M7 | Low | [apply_removal](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:544) materializes the full `git ls-files` list and a `(content, ending)` tuple per line for every touched file (1 MB per-file cap bounds the damage), and [run_secrets_removal](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:650) maps skipped files to rows with a nested loop. Minor at realistic secret counts. |

Bounded-and-clean, verified: the 1 MB removal file cap, the
50k-file reachability graph cap with fail-open truncation, the
news throttle's bounded evicting map, per-file manifest caps, and
subprocess temp-file spooling. Temp dirs, file handles, DB
sessions, and HTTP streams all close on exception paths — no
handle or session leak was found.

## Concurrency

The design center is a single worker draining runs sequentially,
with per-repo single-flight enforced by a partial unique index.
Inside that envelope the code is careful (insert-first with
savepoints everywhere two writers could meet). The issues are at
the edges of the envelope:

| ID | Sev | Finding |
|---|---|---|
| K1 | Med | [claim_pending_runs](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scheduler.py:84) is a read, not a claim: it selects `RUNNING` rows and returns them, with no lease, owner, or status transition. Two worker processes (or a worker plus a manual `run_once`) both execute the same run. Secrets survive this by unique key (the losing insert is discarded), but `Proposal` has no unique guard on `secret_finding_id`, so duplicate removal proposals, branches, and PR attempts are possible. Either enforce one worker, or make claiming atomic (status/lease update with rowcount check). → Follow-up #31. |
| K2 | Med | Baseline check-then-record is a TOCTOU pair: [_needs_baseline](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:372) and [_record_baseline](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:384) run in separate sessions minutes apart (a full-history scan sits between them). Concurrent runs for one repo both pay the history scan; the later record can overwrite the baseline sha with an older HEAD. The per-repo single-flight index makes this unreachable today; it becomes live the moment K1 does. Fix together: serialize baseline recording per repo (the insert-first upsert already half-does this — compare-and-set the sha). → Follow-up #31. |
| K3 | Low | In [reconcile](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:290), two concurrent reconciles for one repo each snapshot `existing`, then update `liveness`/`status` last-writer-wins. A `closed` written by one can be overwritten by the other's stale `awaiting_rotation` snapshot (SQLAlchemy updates all loaded columns on flush). Same single-flight caveat as K2. |
| K4 | Low | The app tier is threaded (sync FastAPI routes run in a threadpool) but [ratelimit.allow](/Users/f3lx/Documents/projects/meta/src/security_agent/app/ratelimit.py:13) mutates a shared `defaultdict`/`deque` with a delete-then-recreate sequence and no lock; concurrent requests from one IP can lose counts (fail open) or, worst case, observe a bucket mid-replacement. See also M6 for the accounts/scan caches. Fix with M1: one lock around the bucket map. → Follow-up #29. |
| K5 | Low | [run_allowlisted](/Users/f3lx/Documents/projects/meta/src/security_agent/sandbox/tools.py:165) acquires the 4-slot tool semaphore with `timeout=timeout` — the *tool* timeout doubles as the *queue* timeout, so a queued `betterleaks` call can burn its whole 600 s waiting and then run another 600 s, and a queued 120 s scanner can time out without ever running. Wake order is also not FIFO. Harmless while callers are sequential; document or split the two budgets before parallelizing patch/deliver groups. |

Confirmed concurrency positives: the `RUNNING` partial unique
index plus `IntegrityError` handling makes concurrent enqueues
coalesce ([scheduler.py:53](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scheduler.py:53));
secret, finding, boost, gate, and token writes are all
insert-first inside savepoints ([secrets.py:314](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:314),
[scan.py:719](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:719),
[gates.py:73](/Users/f3lx/Documents/projects/meta/src/security_agent/control/gates.py:73));
the audit store's purge-under-append race is fixed with an `RLock`
([audit/__init__.py:37](/Users/f3lx/Documents/projects/meta/src/security_agent/audit/__init__.py:37)) and the KEV cache uses
double-checked locking ([scan.py:54](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:54)).

## Optimization notes (beyond M3–M5)

- News work runs twice per worker iteration: `tick()` polls and
  matches, then the graph's `fetch_signals` node polls and matches
  again ([scheduler.py:124](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scheduler.py:124),
  [graph.py:44](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/graph.py:44)).
  `poll_due` makes the second poll cheap, but `run_matcher` rewalks
  every item × finding pair (follow-up #5) on both passes.
- [group_by_package](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/deliver.py:335)
  issues one `db.get(Finding)` per proposal, and
  [_apply_provider_state](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/deliver.py:754)
  opens a session per finding plus one per transition. Batch both
  when touching follow-up #30.
- Scheduler `due_repos` N+1, Python-side retention purges, and the
  news matcher index are already tracked (#5, #14) and not
  re-filed here.
- `run_secrets_stage` re-reads settings (`_config_args`) and
  re-resolves `shutil.which("betterleaks")` on every call and every
  `diff_secret_violations` — negligible cost, noted only because
  the diff check runs per patch attempt (up to 3 rounds per group).

## Best practice

- **B1 — Format gate is red.** `ruff format --check` fails on 10
  files, including the core H5 files
  ([secrets.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py),
  [deliver.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/deliver.py),
  [lifecycle.py](/Users/f3lx/Documents/projects/meta/src/security_agent/control/lifecycle.py),
  [repos.py](/Users/f3lx/Documents/projects/meta/src/security_agent/app/routers/repos.py))
  and H5 tests. `ruff check` and `mypy` are clean, so this is
  mechanical — run `ruff format` — but a red gate trains operators
  to ignore gates. → Follow-up #32.
- **B2 — String-matched error dispatch.** Delivery decides
  "supersede" by substring-matching
  `"no longer present at HEAD" in str(exc)`
  ([deliver.py:501](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/deliver.py:501)).
  Any rewording of the `SecretError` message silently turns
  supersede into infinite retry. Give `SecretError` a reason code.
- **B3 — Direct status writes bypass the transition table.**
  `reconcile` assigns `row.status` directly in four places; the
  writes happen to be legal edges today, but
  [SECRET_TRANSITIONS](/Users/f3lx/Documents/projects/meta/src/security_agent/control/lifecycle.py:137)
  cannot guard them, which is how G1/G3-class edges stay missing
  unnoticed. Route reconcile flips through a checked helper (or
  assert the edge inline).
- **B4 — Duplicated constants.** The 600 s scanner timeout exists
  as `SECRETS_SCAN_TIMEOUT_SECONDS` and again as a bare `600`
  literal in the unshallow call
  ([secrets.py:264](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:264)).
  Minor; fix while touching G4.
- Positive: error handling is disciplined throughout H5 — no bare
  `except:`, scanner failures fail loud as `SecretError`, expected
  races are caught at the savepoint, and every skip carries a
  reason that reaches the run notes.

## Risks (real, lower confidence or lower impact)

| ID | Sev | Risk |
|---|---|---|
| R1 | Low | Scan-time removal mutates the scan workdir ([apply_removal](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/secrets.py:588) writes in place). In the graph flow that workdir is a temp clone and is wiped, so this is safe today — but `run_scan(..., source_dir=...)` callers hand over a real checkout and get their files redacted on disk with no PR. Validate on a copy, or document `source_dir` as sacrificial. |
| R2 | Low | A dead secret still present at HEAD is inserted `open` and alerted (with a removal PR), where C4's literal text sends dead *baseline* hits to `informational`. Hygiene removal of a revoked-but-present credential is defensible; the alert is arguably noise. The behavior is test-encoded (`test_secrets_engine.py:86`), so treat as a plan-reading decision to confirm, not a bug. |
| R3 | Low | `git ls-files` output quoting: paths with spaces or non-ASCII names come back quoted, miss the `tracked` set, and are skipped as "file not tracked in git" — a removal silently never happens for such paths (the finding stays `open` with a skip note, so it is visible, not silent). |
| R4 | Low | Audit durability: secret alerts live only in the worker process's bounded in-memory log (10k entries, lost on restart, invisible to the app process). The finding row is the durable record, so nothing is *lost*, but the C5 "audit entry" half of an alert does not survive the worker. Owned by follow-up #2 (durable LogStore backend). |

## Unproven (claimed by plan, not demonstrated)

- **U1 — Real Betterleaks v2 behavior.** Every test fakes the
  scanner; the live probe (`test_h5_validation.py:246`) skipped
  here because the binary is absent, exactly as it would in the
  shipped image (S2). The pinned argv and report shape are verified
  against fixtures and upstream docs only. First deployment with
  the real binary is the actual contract test.
- **U2 — Postgres concurrency.** All race handling (partial unique
  indexes, savepoint inserts) is exercised on SQLite in tests;
  Postgres lock/serialization behavior under concurrent workers was
  inferred, not run.
- **U3 — Scale.** No load test: a monorepo history past the 25M
  report cap, thousands of baseline findings (M3), and dozens of
  simultaneous secrets (M4) are reasoned from code bounds, not
  measured.

## Deferred by plan (not gaps)

From the H5 sub-plan's Non-goals and
[cross-phase-followups.md](/Users/f3lx/Documents/projects/meta/docs/cross-phase-followups.md):
channel delivery fan-out (H6, behind the `notify_secret_alert`
seam), automatic rotation execution, history rewrite/purge,
commit-range incremental scans (#18), HMAC-keyed fingerprints
(#19). Follow-up #17 is correctly marked Done. The Docker sandbox
(#1) is deferred but gates production (S1).

## Recommended fix order

1. **G1** — reopen-and-alert on HEAD reappearance. A known live
   secret sitting unalerted is the worst failure mode this phase
   exists to prevent.
2. **G2** — stop writing secret-bearing patch files; prune
   `deliveries/`. Pair with **S2** (ship the binaries) so the fix
   is exercised against real delivery.
3. **G3 + G5** — small, surgical: PR-closed re-proposal and the
   rotation repo check.
4. **G4 + G7 + S3** — one baseline-pass change: canonical hash,
   isolated history failure, authenticated unshallow.
5. **G6 + G8** — history dead-refresh; audit warnings; notify
   after commit.
6. **M1/M2 + K1** — rate-limiter bound, deliveries retention
   (with G2), and an explicit single-worker guard or atomic claim
   before any scale-out.
7. **B1–B4, M3–M5** — format gate, error codes, transition
   helper, and the secrets perf pass.

## Follow-ups filed from this review

Added to [cross-phase-followups.md](/Users/f3lx/Documents/projects/meta/docs/cross-phase-followups.md)
as items **#20–#32** (all `Open`): #20 HEAD reappearance (G1),
#21 secret patch files + deliveries retention (G2/M2),
#22 PR-closed re-proposal (G3), #23 baseline hash (G4),
#24 rotation repo check (G5), #25 history dead-refresh (G6),
#26 history-failure isolation + private unshallow (G7/S3),
#27 alert audit + notify-after-commit (G8), #28 scanner binaries
in the image (S2), #29 limiter/cache thread-safety and bounds
(M1/M6/K4), #30 secrets perf: full-table loads + repeated
validation scans (M3–M5), #31 atomic run claim / baseline
serialization (K1–K3), #32 format gate (B1). B2–B4 and R1–R4 are
recorded above as in-phase hardening notes for whoever picks up
#20–#27, not separate tracker items.

## Addendum — fixes applied (2026-10-30)

All items above are fixed except the two partials noted below;
follow-ups #20–#29 and #32 are marked Done, #30/#31 stay Open with
progress notes.

- G1 (#20): `closed`/`informational` fingerprints at HEAD reopen as
  new incidents with a fresh alert; new `SECRET_TRANSITIONS` edges
  plus reconcile tests for both reappearances. The old test
  asserting `informational → open` is illegal now asserts the
  reopen — the test encoded the bug.
- G2/M2 (#21): secret delivery writes no `format-patch` file (the
  branch + PR are the artifact); new `purge_old_deliveries`
  retention sweep wired into the scheduler tick; unit + e2e
  no-store assertions extended to sweep the delivery directory.
  The old test asserting a patch file exists now asserts its
  absence — it encoded the leak.
- G3 (#22): provider sync flips a secret `proposed → open` when
  its PR closes unmerged; merged PRs still move no secret state.
- G4 (#23): the fs report hash is canonical for both compare and
  record; the baseline test now pins `cfg-2` (it encoded
  history-wins) and a differing-hash stickiness test guards the
  regression.
- G5 (#24): the rotation route 404s when the secret's repo differs
  from the URL repo; cross-repo integration test added.
- G6 (#25): history drafts refresh `liveness`/`dead_verdict` on
  known rows without re-alerting, so history-only secrets close on
  dead re-validation.
- G7/S3 (#26): history-scan failure defers the baseline while HEAD
  results still reconcile; `fetch --unshallow` re-attaches the
  repo token with push-style redaction and strips it after.
- G8 (#27): skip and stage-failed paths emit `secret`/`warning`
  audit entries (exception text stays out of the log);
  `reconcile` collects alerts for the caller to emit after commit.
- S2 (#28): both scanners pinned in the shared Dockerfile interim
  (betterleaks v2.0.0-rc.1, osv-scanner v2.7.0) with per-arch
  SHA-256 verification; all four digests were verified
  byte-for-byte against upstream release artifacts. Upstream
  verification also confirmed the adapter must stay on the v2
  line: v1.9.0 stable uses `dir` + `--report-path`, which would
  break the `fs`/`git`/`stdin --output -` contract — this is now a
  Dockerfile comment and a pin test. Relocation to the sandbox
  image rides follow-up #1. `docker build` could not run here
  (no daemon in this environment); the static pin test plus
  checksum verification is the proof.
- M1/M6/K4 (#29): the limiter holds a lock and evicts
  oldest-resident past 4096 buckets; HIBP and lockfile caches are
  locked (fail-map bounded); KEV returns copies. Bound +
  exact-count concurrency tests added.
- M3–M5 (#30, partial): migration 0009 adds the
  `(repo_id, status)` index; `list_repo_secrets` orders SQL-side.
  Scan reuse by HEAD sha and a secrets retention policy remain.
- K1–K3 (#31, partial): unique `secret_finding_id` guard
  (migration 0009) with a lost-race skip in removal, plus
  single-worker guards in the worker docstring and Compose file.
  The atomic claim/lease remains.
- B1 (#32): `ruff format` applied; all four gates green.
- B2–B4, R1, R3 folded in: `SecretError` reason codes (delivery
  supersede checks `gone`, not message text); reconcile flips go
  through a checked `_flip` helper; the unshallow timeout uses the
  shared constant; removal proof redaction is snapshotted and
  restored so `source_dir` callers never see a redacted checkout;
  `ls-files -z` keeps space-bearing paths matchable. R2 (dead-HEAD
  alert) is left as a plan-reading decision to confirm.

Gates after fixes: 369 passed, 4 skipped (the same 4 environmental
skips); `ruff check`, `ruff format --check`, and `mypy` clean.
Behavior-encoded tests were updated only where the old expectation
was the reported bug (noted per item above); every fix carries a
regression test. The 0008 migration test needed a sequencing fix
(downgrade 0009 before 0008) once 0009 depended on its column —
test-only, the chain itself was already ordered.

