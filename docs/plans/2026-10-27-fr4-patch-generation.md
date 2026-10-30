# FR-4 Patch Generation — Sub-Plan

Status: **Final** (accepted 2026-10-27).

Parent: [2026-10-27-ai-security-agent.md](/Users/f3lx/Documents/projects/meta/docs/plans/2026-10-27-ai-security-agent.md) (v7) — FR-4, FR-3 (input), FR-5 (output), FR-9/NFR-5 (gates).

## Parent constraints (carried in, not re-decided here)

- The patch node produces fixes for reachable vulns only (FR-3 decides reachability).
- Generation runs in-sandbox (autonomous, approval-free); proposals go out as unmerged PRs/MRs; merge is gated (FR-9).
- Model output is validated before it becomes a patch; findings cite sources (NFR-5).
- Node.js first; Python reuses the same loop (FR-7) — decisions generalize unless noted.
- Batching/delivery shape belongs to FR-5; this plan covers generation only.

## Settled decisions

All settled — recorded below as agreed.

- **D1. Patch strategies in v1:** _settled_ — bump-first + model adaptation, bundled: take the advisory-recommended fixed version (else the next fixed version), implement in sandbox, check docs/changelog for breaking changes, apply code adaptation in the same patch. Propose only what verifies.
- **D2. Test gates before proposing:** _settled_ — repo tests, if present, must pass; otherwise static impact analysis must be clean. Propose only on pass.
- **D3. Patch validation rules:** _settled_ — full rule set: diff limited to dependency + necessary adaptation; lockfile updated and consistent; rescan introduces no new CVE; no secrets in diff. Test rules: only failures in tests related to the changed code count (unrelated failures ignored; agent judges relatedness and discloses ignored tests in the proposal). Agent may edit/delete/add/refactor existing tests, but only for sections affected by the change and only to match new behavior — never to force a pass.
- **D4. Unpatchable-case behavior:** _settled_ — report-only finding with upgrade/replace guidance, plus a filed provider issue so the vuln is tracked where the team works.
- **D5. Deterministic vs model split:** _settled_ — version selection is data-driven (advisory data); implementation, doc reading, and code adaptation are model-driven; verification is mechanical (tests or static analysis).
- **D6. Iterative repair on failure:** _settled_ — up to 3 repair rounds (adapt code, try alternate version); on exhaustion, no PR — report-only finding with the failure reason.

## Pending parent amendments

- **FR-4** expanded to the settled flow: advisory version → sandbox implement + adapt with docs → verify (tests or static analysis) → propose (D1, D2, D5).
- **FR-4** validation: related-tests-only failure, scoped test edits, 3 repair rounds then report-only (D3, D6).
- **FR-4** unpatchable: report-only + guidance + filed issue (D4).

## Scope contract (accepted 2026-10-27)

- **Artifact boundary:** this sub-plan file plus the listed parent-plan amendments (applied to the parent upon acceptance). Out of scope: runtime code, tests, other FR sub-plans, follow-on specs.
- **Done means:** every D-item above is settled or explicitly marked unresolved, and the user accepts this contract in writing. No D-item remains unresolved. Accepted (chat, 2026-10-27).
