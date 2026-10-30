# FR-9 Approval Gates + Containment — Sub-Plan

Status: **Final** (accepted 2026-10-27).

Parent: [2026-10-27-ai-security-agent.md](/Users/f3lx/Documents/projects/meta/docs/plans/2026-10-27-ai-security-agent.md) (v5) — FR-9, NFR-1, NFR-2, NFR-6, NFR-7.

## Parent constraints (carried in, not re-decided here)

- Approvals are pre-execution checkpoints between graph nodes; no mid-shell-session interrupts.
- Containment is the approval boundary: fully in-sandbox commands run autonomously.
- Approval triggers: sensitive information, out-of-scope external contact, externally-visible/irreversible effects (merge, rotation, publish).
- Opening a diff/PR/MR needs no approval; the agent cannot merge.
- Audit log shows request→approve→execute; zero merges/rotations without approval.

## Settled decisions

None yet — each answer below is recorded here as it settles.

- **D1. Approver model:** _partially settled_ — multi-role ladder with differentiated approval rights (chosen over admin-only). Exact roles: D1a. Rights mapping: D1b.
- **D1a. Role set:** _settled_ — Owner, Maintainer, Developer, Reporter (hosting-conventional ladder).
- **D1b. Approval rights per role:** _settled_ — Owner and Maintainer approve all classes (merge, rotation, publish, gated runtime steps); single approver suffices, no quorum in v1. Owner additionally manages accounts/roles. Developer triggers scans and views findings, approves nothing. Reporter is view-only.
- **D2. Task-declared scope definition:** _settled_ — no approval for in-sandbox external API calls or any in-sandbox work. Network scope is not an approval boundary.
- **D2b. Final approval trigger list:** _settled_ — merge, rotation, and publish gated (publish is merge-class: agent can only open PRs). PR/MR/issue creation free. Secret values consumed by reference via env and never read, so secret-viewing needs no gate.
- **D2c. Approval sources:** _settled_ — dashboard queue plus provider-side (approving/merging the PR on GitHub/GitLab counts). Agent must observe provider merge state; sync mechanics deferred to FR-5 sub-plan.
- **D3. Unknown/arbitrary calls:** _settled_ — credential separation: sandbox token is least-privilege (read + open PRs/issues; no merge/rotate/publish). Gated actions run only from the privileged backend post-approval. In-sandbox shell fully free; every line audit-logged. Parent "unknown calls stop the run" retired for in-sandbox; calls outside the tool manifest still fail closed.
- **D4. Pending-approval timeout:** _settled_ — deny after configurable window (default 72h); agent auto re-queues with a note.
- **D5. Approval channel:** _settled_ — approval requests fan out to all configured notification channels (FR-13 set: email, Slack, webhook/pager). Granting stays dashboard + provider-side only in v1; channel messages link to the dashboard, no in-chat/in-email approve action.
- **D6. Audit event contents:** _settled_ — full decision context (timestamp, run id, actor + role, action + target, decision + decider + source, reason). Retention per install policy, default 1 year.
- **D8. Log storage backend:** _settled_ — Loki ships as v1 default behind the pluggable `LogStore` interface (append/query/retention-purge); Elasticsearch/OpenSearch/ClickHouse plug in later. Labels stay low-cardinality (tenant, action class, decision); run id in line content.
- **D7. Break-glass bypass:** _settled_ — no standing bypass. Instead: an Owner may delegate approval privileges to a Developer (Maintainer needs none, already approves per D1b; Reporter excluded). Delegation is time-boxed (default 24h, configurable), non-transferable, revocable, optionally narrowed by class, and fully audited. Bounds are recorded defaults, amendable at acceptance.

## Pending parent amendments

- **FR-10 roles** admin/member → Owner, Maintainer, Developer, Reporter (D1a).
- **FR-9 triggers** final: merge, rotation, publish gated; PR/MR/issue creation free; secrets by reference, never read (D2b).
- **FR-9 approval sources:** dashboard plus provider-side merge counts (D2c).
- **NFR-2 egress** wording to reconcile: firewall control stays as a technical guardrail, but carries no approval (D2).
- **FR-5 dependency:** provider PR-state sync mechanics (poll vs webhook) decided in FR-5 sub-plan (D2c).
- **FR-8/NFR-4 dependency:** secrets-by-reference mechanism details (env injection point, rotation flow) decided there.
- **Parent decision 2** "unknown calls stop the run" retired for in-sandbox; sandbox token is least-privilege and gated actions run only from the privileged backend (D3).
- **New:** audit logs live in a separate pluggable log store behind a `LogStore` interface (append/query/retention-purge); v1 default Loki (D8).

## Scope contract (accepted 2026-10-27)

- **Artifact boundary:** this sub-plan file plus the listed parent-plan amendments (applied to the parent upon acceptance). Out of scope: runtime code, tests, other FR sub-plans, follow-on specs.
- **Done means:** every D-item above is settled or explicitly marked unresolved, and the user accepts this contract in writing. No D-item remains unresolved. Accepted with "Accept it." (chat, 2026-10-27).

## Sources (inspected during interview)

- https://github.com/grafana/loki (README: single-binary ops, labels-only indexing, Grafana-native)
- https://signoz.io/blog/loki-vs-elasticsearch/ (2026 comparison: resource/ops contrast)
