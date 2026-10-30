# H2 — Phase 1: Node.js Vuln Loop (detailed sub-plan)

Status: done (2026-10-30). Parent: [implementation plan](2026-10-29-implementation-plan.md)
plus FR-2/3/4/5/9/12 sub-plans and [architecture.md](../architecture.md).

## Goal

End-to-end loop for Node.js repos: connect → scheduled scan → osv-scanner +
KEV findings → reachability verdicts → bump-first patches → PR/MR/branch
delivery → approval queue. Per H2 validation: importing fixture gets a patch,
non-importing stays silent-with-reason, failed verification yields
report-only, withhold-approval runs show zero merges with a full audit trail.

## FR-1 intake closure (just-in-time, decided here)

- Accept any git URL (https/ssh, any host) or an absolute local path.
- Clone/fetch runs inside the disposable sandbox only. Local-path repos are
  cloned via `file://` into the sandbox for scan/reachability/patch, and
  delivery pushes the new branch back to the local path remote — zero host
  execution is preserved.
- Provider tokens stored encrypted (`encrypted_tokens`, owner
  `repo-token:{id}`), injected as env in-sandbox, never logged or re-viewed.
- Local-path repos are poll-only (no webhooks). GitHub + GitLab webhook
  receivers verify per-repo signatures (FR-2 D3).

## Slices (build order; each lands tested)

- **A. Data foundation.** Tables: repos, scan_runs, findings, verdicts,
  proposals, approvals, delegations + migration + lifecycle transition
  service (open → proposed → resolved → closed, unpatchable/silent
  terminals, rescan reopen). Done when: migration applies clean, lifecycle
  unit tests green.
- **B. Intake + scheduler.** Repo connect (URL/local validation, token
  store), 6h-per-repo poll loop + scan-on-connect + manual trigger,
  GitHub/GitLab webhook receivers with signature verify. Done when:
  connect triggers a run record; scheduled/manual/webhook triggers enqueue.
- **C. Scan node.** Sandbox clone, lockfile (generate in-sandbox with
  scripts disabled when absent, noted in run), osv-scanner invocation,
  KEV join by CVE, D6 normalization + (package, advisory) dedup.
  Done when: fixture lockfile yields canonical finding records.
- **D. Reachability node.** In-sandbox import/require graph (ripgrep + JS
  parser), verdicts with chain evidence / reason codes / fail-open
  markers, lifecycle flips incl. reopen. Done when: importing fixture
  reachable, non-importing silent-with-reason, import-added reopens.
- **E. Patch node.** Bump-first + model adaptation, repo-tests-or-static
  verify, related-failures-only + scoped test edits, 3 repair rounds,
  report-only + filed issue on exhaustion/unpatchable. Done when:
  reachable fixture yields a verified proposal; failing verify yields
  report-only with reason. Landed with a null adaptation hook (bump-only;
  repair-by-alternate-version is live): the model-backed adapter plugs
  into `adapt` once live-model validation is available, and issue filing
  rides Slice F delivery.
- **F. Deliver node.** Ready PR/MR per package (grouped when related,
  reason disclosed), bot identity + SSH-signed commits, default-branch
  targeting, minimal template, local branch + format-patch files,
  provider state sync (webhook + per-scan resync). Done when: proposal
  delivers without touching the working branch; merge state observed.
  Landed grouping same-package-only (overlap/edge judgment is a
  follow-up); signing key comes from `BOT_SIGNING_KEY`, unsigned commits
  recorded in run notes, key ceremony deferred to H6; GHES state queries
  degrade to skip.
- **G. Dashboard + gates.** Findings / patches / approval-queue views
  (grouped by repo, needs-action first, KEV/severity/recency), Approve/
  Deny + delegation + 72h timeout + history, graph `interrupt_before`
  checkpoints, privileged backend merge executor. Done when:
  withhold-approval run shows zero merges with full audit trail.
  Landed with just-in-time closures: separate `repo-merge-token`
  credential for backend merges (FR-9 D3 least-privilege); timeout
  re-queue capped at 3; local repos merge manually in their checkout
  (ancestry observes); branches deleted post-merge escape ancestry
  observation (API path covers provider PRs).
- **H. H2 validation suite.** Fixture repos + end-to-end checks per the H2
  validation plan. Done when: all four H2 validation checks green.
  Default live target: `https://github.com/devcbuea/dt-collect-web-client`
  (see `DEFAULT_TEST_REPO_URL` in `tests/e2e/test_h2_validation.py`).
  Live runs are read-only (scan + reachability; delivery never runs
  against it) and skip without an `osv-scanner` binary on PATH or
  network. Offline checks replay `tests/e2e/fixtures/osv-recorded.json`
  through the full graph with real git workdirs. The default repo is a
  validation constant only — never auto-connected on fresh installs.
  Landed 2026-10-29: offline checks green (importing fixture patched,
  non-importing stays silent, withhold-approval merges nothing); live
  pass green (239 findings, 0 reachable / 239 `no-import-chain` —
  verified correct: axios/lodash unused, rest transitive toolchain).
  Live-found fixes: scanner output cap 25MB, npm lockfile timeout 600s,
  KEV enrichment moved to the CSV feed (CISA JSON 404s), `analyze`
  resolves tmpdir symlinks. Follow-ups: yarn.lock repos need npm
  regeneration (slow); KEV 15s fetch can time out behind proxies
  (fail-open holds, enrichment skips that run).

Dependencies: A gates everything; B/C gate D; D gates E; E gates F; F gates
G; H last. Dashboard views (G) can parallelize against E/F once A's
service APIs are stable.

## Risks

- osv-scanner availability/version drift in the sandbox image.
- Model adaptation quality for breaking bumps (mitigated: verify gate,
  3 repair rounds, report-only fallback).
- Provider merge-state observation races (mitigated: webhook + resync).
