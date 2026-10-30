# FR-5 Patch Delivery — Sub-Plan

Status: **Final** (accepted 2026-10-27).

Parent: [2026-10-27-ai-security-agent.md](/Users/f3lx/Documents/projects/meta/docs/plans/2026-10-27-ai-security-agent.md) (v8) — FR-5, FR-4 (producer), FR-9 (merge gating, D2c sync deferred here), FR-2 D3 (webhook receiver reuse).

## Parent constraints (carried in, not re-decided here)

- Delivery targets: GitHub PR, GitLab MR, local branch plus patch files (FR-5).
- Opening proposals needs no approval; the agent cannot merge; merge is the gated action, provider-side approval/merging counts (FR-9, FR-9 D2c).
- Sandbox token is least-privilege: read + open PRs/issues; no merge/rotate/publish (FR-9 D3).
- FR-4 hands over verified patches only; proposals disclose ignored tests; unpatchable → report-only + guidance + filed issue (FR-4 D3, D4).
- The FR-2 webhook receiver is available for reuse in PR-state sync (FR-2 D3).

## Settled decisions

None yet — each answer below is recorded here as it settles.

- **D1. Draft vs ready PRs/MRs:** _settled_ — every proposal opened ready-for-review, no drafts in v1.
- **D2. Batching:** _settled_ — one PR per patched package, grouped when related: patches touching overlapping code or linked by a dependency edge ride in one PR. Agent judges relatedness and discloses the grouping reason in the proposal. Never batched across unrelated packages or per repo/run.
- **D3. Commit authorship + signing:** _settled_ — dedicated bot identity (per-install configurable name/email, sane default) with SSH-signed commits from a per-install key; public key published in dashboard/docs for verification.
- **D4. Target branch rules:** _settled_ — repo default branch by default (provider API / remote HEAD; local repos fall back to checked-out branch), user-configurable per repo in the dashboard.
- **D5. Provider state sync:** _settled_ — webhook-instant reconcile where configured (FR-2 receiver reused, subscribed to merge/close events) plus state resync piggybacked on every scheduled scan. No dedicated poller. Closes the FR-9 D2c deferral.
- **D6. Local delivery shape:** _settled_ — new branch `security/<package>-<advisory>` with the signed fix commit (checked-out branch never touched) plus `git format-patch` files in the run's delivery directory.
- **D7. Proposal content:** _settled_ — fixed minimal template: title + summary line (package x→y, advisory IDs), KEV-exploited flag when set, one-line verification result, one-line grouping/ignored-tests pointers, dashboard finding link. Full evidence and disclosures live in the dashboard. Unpatchable/report-only: provider issue with guidance summary + dashboard link, never a PR.

## Pending parent amendments

- **FR-5** proposals open ready-for-review, no drafts in v1 (D1).
- **FR-5** batching is one PR per patched package, grouped when related (overlap or dependency edge), grouping disclosed (D2).
- **FR-5** commits carry a bot identity and SSH signatures from a per-install key (D3).
- **FR-5** PRs target the default branch unless the user picks another per repo in the dashboard (D4).
- **FR-5** provider merge state syncs via webhooks where configured plus resync on every scan; closes the FR-9 D2c deferral (D5).
- **FR-5** local delivery is a new `security/<package>-<advisory>` branch plus format-patch files; working branch untouched (D6).
- **FR-5** proposals use a fixed minimal template with a dashboard link for full detail; unpatchable cases file issues, never PRs (D7).

## Scope contract (proposed — not yet accepted)

- **Artifact boundary:** this sub-plan file plus the listed parent-plan amendments (applied to the parent upon acceptance). Out of scope: runtime code, tests, other FR sub-plans, follow-on specs.
- **Done means:** every D-item above is settled or explicitly marked unresolved, and the user accepts this contract in writing. No D-item remains unresolved. Accepted (chat, 2026-10-27).
