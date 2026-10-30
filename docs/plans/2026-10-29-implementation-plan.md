# Implementation Plan — Headlines

Status: H1–H6 done (2026-10-30). Headline-level; each H-item expands into a detailed sub-plan on request.

Parent: [2026-10-27-ai-security-agent.md](/Users/f3lx/Documents/projects/meta/docs/plans/2026-10-27-ai-security-agent.md) plus [architecture.md](/Users/f3lx/Documents/projects/meta/docs/architecture.md) and sub-plans FR-2/3/4/5/8/9/10/12/15 and NFR recovery/cost/hardening.

## Goal

Turn the accepted solution plan and architecture into a working self-hosted AI security agent, built in headline phases we will expand one by one.

## Success Criteria

- `compose up` gives dashboard + worker + db + sandbox runner on the operator network.
- Any repo URL or local path can be connected, scanned, patched, and approved from the dashboard.
- Zero host-executed agent commands; zero merges/rotations/publishes without approval.
- News boosts priority but never triggers action alone.

## Approach

Follow the architecture's Phase 0–5 build order, mapping the six planes (orchestration, execution, control, presentation+identity, data/audit/recovery, integrations) onto `app`, `worker`, `db`, `sandbox runner`. Each headline below becomes a detailed sub-plan on request. Open seams from `architecture.md` (FR-1, FR-6, FR-7, FR-11, FR-13, FR-14 details) are closed just-in-time before the phase that needs them.

## Steps

- **H1 — Phase 0: Scaffold, probe, auth skeleton.** ✅ Done (2026-10-29). FastAPI app + LangGraph worker + Compose + Postgres with encrypted fields; Muse Spark native `tool_calls` probe gate; sandbox execution policy; dashboard skeleton with Owner-first signup, accounts, Google/Microsoft SSO, roles, TLS.
- **H2 — Phase 1: Node.js vuln loop end-to-end.** ✅ Done (2026-10-30). Scheduler (6h poll + connect + manual + webhooks), sandbox osv-scanner + KEV join, import-graph reachability, bump-first patch node, PR/MR/branch delivery, findings lifecycle + patches view + approval queue. Detail: [H2 sub-plan](2026-10-29-h2-phase1-vuln-loop.md).
- **H3 — Phase 2: News boosters.** ✅ Done (2026-10-30). HN + RSS pollers, stack matcher, priority boost only, polite scrape fallback. Detail: [H3 sub-plan](2026-10-30-h3-phase2-news-boosters.md).
- **H4 — Phase 3: Python reachability.** ✅ Done (2026-10-30). Same graph, Python scan/reachability/patch nodes: manifest discovery + ecosystem routing, AST import graph, requirements bumps with pytest-or-static verify. Detail: [H4 sub-plan](2026-10-30-h4-phase3-python.md).
- **H5 — Phase 4: Secrets loop.** ✅ Done (2026-10-30). Betterleaks in-run scan, history baseline + new-only, notify + removal-PR + rotation guidance, awaiting-rotation closure. Detail: [H5 sub-plan](2026-10-30-h5-phase4-secrets.md).
- **H6 — Phase 5: Notifications, hardening, recovery.** ✅ Done (2026-10-30). Email/Slack/webhook delivery + routing + digests; boundary validation + injection fixture suite as release gate; cost caps/park/resume; backup/key-ceremony/restore runbook. Detail: [H6 sub-plan](2026-10-30-h6-phase5-notifications-hardening.md).
- **H7 — Release readiness.** OSS docs, operator runbooks (SSO registration, backup/restore, cap tuning), scratch-stack restore proof.

Dependencies: H1 gates everything (probe pass required); H2 gates H3–H5; H6 hardening gates release; H7 last.

## Validation Plan

- H1: probe round-trips native `tool_calls`; auth checks (Owner-first, invite expiry, SSO, last-Owner guard); hostile fixture proves no host execution.
- H2: importing fixture patches, non-importing stays silent-with-reason; failing verification yields report-only; withhold-approval run shows zero merges with full audit trail (highest risk).
- H3: known-discussed CVE rises with link; rumor-only input yields no patch.
- H4: Python fixtures mirror Node.js reachability/patch checks.
- H5: live secret alerts + removal-PR; merged PR alone never closes; closure needs HEAD-clean + rotation confirmed.
- H6: test-send per channel; injection suite red blocks release; scratch-stack restore boots with login + findings + decrypt audit.
- H7: fresh-install runbook followed verbatim succeeds.

## Risks / Open Questions

- SSO app registration needs operator-created Google/Microsoft OAuth clients.
- Open seams with no sub-plan yet: FR-1 intake details, FR-6 stack matcher, FR-7 Python parsers, FR-11 OIDC setup, FR-13 channel mechanics, FR-14 tool argv allowlists — each closed before its phase.
- None beyond the above; endpoint-shape risk already retired per FR-15.
