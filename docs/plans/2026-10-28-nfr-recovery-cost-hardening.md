# NFR Recovery, Cost & Hardening — Sub-Plan

Status: **Final** (accepted 2026-10-28).

Parent: [2026-10-27-ai-security-agent.md](/Users/f3lx/Documents/projects/meta/docs/plans/2026-10-27-ai-security-agent.md) (v14) — NFR-5 (prompt-injection resistance), NFR-8 (cost control), NFR-9 (recoverability); decision 7 (encryption), decision 8 (hardening), Phase 5, FR-13 (notification channels), FR-15 D4 (bounded retry/park).

## Parent constraints (carried in, not re-decided here)

- Stored tokens encrypted AES-256-GCM under a per-install master key; audit on decrypt; never re-viewed (NFR-4, decision 7).
- Repo code, feeds, news, and tool output are data; model output validated before commands, patches, or rotations; findings cite sources (NFR-5, decision 8).
- Per-run token caps, spend alerts, queue backpressure (NFR-8); bounded retry within caps, park + alert on exhaustion (FR-15 D4).
- Backup ceremony documented including master key; restore tested (NFR-9); Phase 5 owns the backup/restore runbook and injection suite.
- Email, Slack, and webhook channels with per-severity routing; test-send per channel (FR-13).
- Self-hosted Compose on the operator network: app, worker, db, sandbox runner (NFR-10).

## Settled decisions

None yet — each answer below is recorded here as it settles.

- **D1. Backup scope & store (NFR-9):** _settled_ — Postgres dumps (+ config + encrypted fields as-stored) written to an operator-provided path shared between container and host via a Compose bind mount (default `./backups`); master-key material backed up separately under D2, never in the same backup.
- **D2. Master-key ceremony (NFR-9):** _settled_ — app-generated, shown once: the app creates the per-install key on first boot and displays it a single time for the operator to store outside the install; loss means encrypted fields are unrecoverable and tokens must be re-entered.
- **D3. Restore proof (NFR-9):** _settled_ — gate on change: the runbook restore is proven pre-launch and re-proven on every release touching storage, encryption, or backup code; pass means a scratch-stack restore boots, Owner login works, sample findings and approvals read correctly, and a secret decrypt fires its audit entry.
- **D4. Cap & alert numbers (NFR-8):** _settled_ — per-run cap 1M tokens with an 80% warning; daily spend alerts at warn $25 / critical $100; all defaults, Owner-configurable per install.
- **D5. Cap enforcement (NFR-8):** _settled_ — hard stop: hitting the cap halts the run (parked, alert fires, resumes only under a raised cap); Owner or Maintainer may raise caps and resume over-cap runs.
- **D6. Output validation rules (NFR-5):** _settled_ — validate at the boundary: structured schema checks on all tool args, tool-manifest membership with fail-closed, sandbox containment for execution, diff-scoped patches; human approval stays exactly where FR-9 already puts it (merge, rotation, publish).
- **D7. Injection suite scope (NFR-5):** _settled_ — fixture suite + release gate: hostile fixtures (injected repo content, malicious tool output, poisoned feeds/news, exfil attempts, approval-bypass lures) run in CI; a failing suite blocks the release.

## Pending parent amendments

- **NFR-9** backup: Postgres dumps + config + encrypted fields as-stored to a shared container↔host bind mount (default `./backups`); key material separate (D1).
- **NFR-9** key ceremony: app-generated, shown once, operator stores outside the install; loss means re-entering tokens (D2).
- **NFR-9** restore: proven pre-launch and on every storage/encryption/backup release; scratch-stack pass criteria (D3).
- **NFR-8** numbers: 1M-token runs, 80% warning, $25/$100 daily spend alerts, Owner-configurable; hard stop at cap, Owner/Maintainer raise and resume (D4/D5).
- **NFR-5** validation: boundary checks (schema, manifest fail-closed, sandbox, diff-scoped patches); approval points unchanged (D6).
- **Validation + Phase 5:** injection fixture suite runs in CI and gates releases; backup/restore runbook carries the D1–D3 ceremony (D7/D3).
- **Risks:** master-key loss consequence stated — no recovery, tokens re-entered (D2).

## Scope contract (accepted 2026-10-28)

- **Artifact boundary:** this sub-plan file plus the listed parent-plan amendments (applied to the parent upon acceptance). Out of scope: runtime code, tests, other FR/NFR sub-plans, follow-on specs.
- **Done means:** every D-item above is settled or explicitly marked unresolved, and the user accepts this contract in writing. Accepted with "Accept" (chat, 2026-10-28).
