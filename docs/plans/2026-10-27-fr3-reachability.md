# FR-3 Reachability Analysis — Sub-Plan

Status: **Final** (accepted 2026-10-27).

Parent: [2026-10-27-ai-security-agent.md](/Users/f3lx/Documents/projects/meta/docs/plans/2026-10-27-ai-security-agent.md) (v12) — FR-3, FR-2 (finding records), FR-4 (patch consumer), FR-12 (silent-with-reason state).

## Parent constraints (carried in, not re-decided here)

- Reachability decides patch versus silent-with-reason and consumes the FR-2 typed finding record (FR-3).
- Findings are per (package, advisory) with dependency paths; lockfile is the scan input; prod/dev scope-labeled, dev-only never silent (FR-2 D4/D5/D6).
- The patch node handles reachable vulns only (FR-4).
- The dashboard lifecycle has a terminal silent-with-reason state; FR-3 decides when a finding lands there and how visible it is (FR-12 D1).
- Validation: importing fixture gets a patch; non-importing fixture stays silent with reason; oracle cross-check agrees.
- Node.js first; Python reuses the loop via FR-7.

## Settled decisions

None yet — each answer below is recorded here as it settles.

- **D1. Analysis depth:** _settled_ — import-based static import/require graph from first-party code, transitive; unresolvable dynamic imports count as reachable. Runs in-sandbox per FR-14 (narrow tool wrapper and/or sandboxed shell search such as ripgrep plus a JS parser).
- **D2. Silenced-findings visibility:** _settled_ — shown in silent-with-reason state, excluded from default active filters, counted separately in reports.
- **D3. Verdict record:** _settled_ — typed verdict: reachable flag + import-chain evidence (file:line hops from first-party code) or dynamic fail-open marker; unreachable carries a reason code (no-import-chain, entry-point-excluded); test-only imports count as reachable.
- **D4. Re-evaluation rules:** _settled_ — recompute every scan; verdict flips drive lifecycle transitions including reopen (silent → reachable reopens; reachable → silent parks with new reason).

## Pending parent amendments

- **FR-3** analysis is an import-based static import/require graph from first-party code, transitive; unresolvable dynamic imports count as reachable; runs in-sandbox per FR-14 (D1).
- **FR-3** silenced findings show in silent-with-reason, out of default active filters, counted separately in reports (D2).
- **FR-3** verdict record: reachable flag + import-chain evidence or fail-open marker; unreachable reason codes; test-only imports count as reachable (D3).
- **FR-3** verdicts recompute every scan; flips drive lifecycle transitions including reopen (D4).
- **Validation Reachability** gains checks: unused-package fixture silenced with reason code; import-added fixture reopens with chain evidence.

## Scope contract (accepted 2026-10-27)

- **Artifact boundary:** this sub-plan file plus the listed parent-plan amendments (applied to the parent upon acceptance). Out of scope: runtime code, tests, other FR sub-plans, follow-on specs.
- **Done means:** every D-item above is settled or explicitly marked unresolved, and the user accepts this contract in writing. Accepted with "Accept. Accept" (chat, 2026-10-27).
