# FR-2 Vuln Detection (Node.js) — Sub-Plan

Status: **Final** (accepted 2026-10-27).

Parent: [2026-10-27-ai-security-agent.md](/Users/f3lx/Documents/projects/meta/docs/plans/2026-10-27-ai-security-agent.md) (v7) — FR-2, FR-3 (consumer), FR-6 (boost only), FR-14/NFR-1/NFR-2 (sandboxed tool execution).

## Parent constraints (carried in, not re-decided here)

- OSV, GitHub Advisory, CISA KEV, and NVD signals trigger sandbox clone plus scan (FR-2).
- HN plus RSS match the stack and raise priority; boost never triggers action alone (FR-6).
- Every scan runs in a fresh disposable sandbox; host execution banned in prod (NFR-1, NFR-2).
- Scanners run as narrow `@tool` wrappers with allowlisted argv; ad-hoc shell via `ShellToolMiddleware` + `DockerExecutionPolicy` (FR-14).
- `osv-scanner scan -r` is currently named only as the validation oracle for reachability, not as the scanner.
- Phase 1 scope is Node.js; Python reuses the loop via FR-7.

## Settled decisions

- **D1. Scanner(s) for v1:** _settled_ — osv-scanner is the primary v1 scanner (promoted from oracle-only); KEV joined by CVE ID as exploitation enrichment. npm audit deferred as redundant (same GHSA upstream); Socket/malware heuristics out of FR-2 scope.
- **D2. Tier 1 watcher definition:** _settled_ — per-repo scan scheduler. One scheduler process fans out; each tracked repo has its own schedule and state (last scan + last findings for diff), and each run gets its own disposable sandbox with its own osv-scanner invocation. "Tier 1" names the trigger-signal set (OSV/GHSA/KEV/NVD via osv-scanner + KEV join); Tier 2 is news boosters in FR-6. Multiple repos supported. Global-feed watching out of v1.
- **D3. Poll cadence / trigger model:** _settled_ — poll plus optional webhooks. Scheduled rescan every 6h by default (configurable per repo), plus immediate scan on repo connect, plus manual scan-now. Optional provider webhooks (push/PR events) when the install is publicly reachable; repo admin registers our per-repo URL + secret provider-side, backend verifies signature and enqueues a scan. Local-path repos are poll-only. GitHub + GitLab receivers in v1; other hosts later (AWS CodeCommit explicitly deferred).
- **D4. Signal correlation / dedup:** _settled_ — one finding per (package, canonical advisory ID); canonical prefers CVE, else GHSA, else OSV ID, aliases collapse. Same CVE across packages = separate findings linked by advisory ID. Severity = max CVSS across merged records (fail loud on conflict); KEV sets exploited=true and raises priority, not the score. Transitive deps in scope; each finding carries its dependency path to the direct parent for FR-4.
- **D5. Scan scope:** _settled_ — transitive deps in scope (see D4); lockfile is the scan input, generated in-sandbox (`npm install --package-lock-only`, scripts disabled) when absent, generation noted in the run record; devDependencies scanned, findings scope-labeled (prod/dev), dev-only defaults to lower priority, never silent.
- **D6. Handoff to FR-3:** _settled_ — full typed finding record: repo, package + installed version, canonical advisory + aliases, severity (score + winning source), KEV exploited flag, dependency path, prod/dev scope, fixed versions, source citation URLs, scan run id. Single normalization point; FR-3/FR-4 never re-fetch OSV.

## Pending parent amendments

- **FR-2** names osv-scanner as the v1 scanner with KEV enrichment (D1).
- **Validation plan** reachability oracle shifts from `osv-scanner scan -r` to direct OSV API / npm audit cross-check, since the scanner is now osv-scanner itself (D1).
- **Phase 1** "Tier 1 watcher" defined as the per-repo scan scheduler; Tier 1 = trigger-signal set, Tier 2 = news boosters in FR-6 (D2).
- **FR-2 / Phase 1** trigger model is poll (6h default, per-repo configurable) + scan-on-connect + manual + optional GitHub/GitLab webhooks; local repos poll-only (D3).
- **FR-5 dependency:** the D3 webhook receiver is available for reuse in PR-state sync (poll vs webhook) when FR-5 is grilled.
- **FR-2 / FR-4** findings are per (package, advisory) with dependency paths; transitive CVEs in scope (D4).
- **FR-2** scan input is the lockfile, generated in-sandbox when absent (D5).
- **FR-3** input is the D6 typed finding record (D6).

## Scope contract (proposed — not yet accepted)

- **Artifact boundary:** this sub-plan file plus the listed parent-plan amendments (applied to the parent upon acceptance). Out of scope: runtime code, tests, other FR sub-plans, follow-on specs.
- **Done means:** every D-item above is settled or explicitly marked unresolved, and the user accepts this contract in writing. No D-item remains unresolved. Accepted (chat, 2026-10-27).
