# Dependency Update Tracker — Decision Record

Status: Final — accepted by the user on 2026-11-01.

Parent context: the agent today tracks vulnerabilities only. `Finding`
is one row per (repo, package, canonical advisory) from osv-scanner on
the lockfile (`worker/scan.py:normalize/persist_findings`), with
reachability (`worker/reachability.py`), bump-first patch + model
adaptation (`worker/patch.py:patch_group/patch_python_group`), and
PR/branch delivery gated by FR-9 approvals (`db/models.py:Proposal,
Approval`). Scheduler polls per repo every 6h by default
(`Repo.schedule_hours`, `worker/scheduler.py:tick`). Dashboard has
per-repo findings/patches views (`app/routers/repos.py:findings_view,
patches_view`). No non-security version-freshness tracking exists yet.

## Goal (as stated by the user)

Per repository, a table tracking the non-dev (production) dependencies
the app actually uses, for Python and Node to start. The tracker
regularly checks whether newer versions exist (from `package.json` /
lockfile, `requirements` / `pyproject` / Pipfile equivalents). When an
update exists it proposes the update to the user. Before the user
approves, the agent/model gathers impact information: scan the new
package version (changelog / breaking changes) and scan the repo's
usage of that package, so the report shows how the update would affect
this repo. Only after that report and user approval does any patch get
created.

## Decisions

### D1. Update scope — package tracking, not a security feature
- Status: SETTLED in interview (record Final).
- Decision: Option A. Every newer production version appears in the
  per-repo dependency table, classified `major / minor / patch` and
  tagged `security / non-security` (security when the target version
  also fixes a known advisory, cross-linked to the existing `Finding`).
  The agent proactively proposes majors and security fixes; minor/patch
  updates sit in the table until the user picks them.
- Emphasis recorded: this feature is package/dependency tracking in
  its own right, not a security feature. Security is only one tag on
  an update, not the reason the table exists.

### D2. Data model — new `Dependency` table
- Status: SETTLED in interview (record Final).
- Decision: Option A. New `Dependency` table, one row per
  (repo, ecosystem, package): installed version, latest version,
  update class, security tag, manifest file, and status
  (`up_to_date / update_available / proposed / ignored`, etc.).
  On approval it hands off to the existing patch flow and links to
  the resulting `Proposal`. `Finding` stays purely vulnerability
  rows; a dependency row cross-links to a `Finding` when its
  security tag applies.

### D3. Tracked set and installed-version source
- Status: SETTLED in interview (record Final), as clarified by the user.
- Decision: Option A with a narrowing clarification. The tracked set
  is only the direct production packages declared in the manifest
  (`package.json` dependencies, `pyproject.toml` dependencies,
  `requirements` entries). This feature does not track or propose
  updates for a dependency of a dependency (transitive packages are
  out of scope here; they remain covered by the existing
  vulnerability `Finding` pipeline when they carry an advisory).
- Installed version: when a lockfile exists, the resolved version
  from the lockfile is the installed version. The manifest spec
  (what is written in `package.json` / `pyproject.toml` /
  `requirements`) is also stored and shown alongside it. When there
  is no lockfile, the manifest spec is the fallback source of truth
  for the tracked package.

### D4. Freshness source and execution home — native tooling, own sandbox
- Status: SETTLED in interview (record Final).
- Decision: Option B, as clarified by the user. Freshness is checked
  with the native ecosystem tooling (for example `npm outdated`
  style output for Node and the pip/uv equivalent for Python),
  not by calling registry HTTP APIs from the host/worker.
- Execution home: each check creates its own fresh disposable
  sandbox, initializes it, runs the tools to extract every piece of
  information needed, and is destroyed afterwards — the same
  disposable-sandbox principle as the existing scan pipeline
  (NFR-1: zero host-executed agent commands). Restarting/creating
  a sandbox per interval check or per manual check is accepted
  cost; there is no long-lived checker process.

### D5. Cadence and run separation
- Status: SETTLED in interview (record Final); cadence revised by D14.
- Decision: Option A. A new `DependencyCheck` run type with its own
  sandbox, status, and failure domain, enqueued on the repo's
  dependency-check cadence (D14; originally settled as the scan
  `schedule_hours` cadence, superseded), plus on repo connect, plus
  a manual per-repo "Check updates" action. It is not a stage
  inside the vulnerability `ScanRun`: a failed freshness check
  never fails or delays a security scan, and vice versa.

### D6. Pre-approval impact report — model-written, read-only
- Status: SETTLED in interview (record Final).
- Decision: Option A, as clarified by the user. Before any approval
  and before any code is touched, the model produces a summary
  impact report for the proposed update, and that report is what
  guides the user's decision. The report is read-only work:
  (1) upstream evidence (changelog/release-notes diff between
  installed and latest, breaking-change flags), (2) repo usage
  (import/require/call sites in first-party code, file:line,
  highlighting sites touching changed APIs), and (3) a model-written
  summary assessment (likely affected / likely safe, and why) citing
  (1) and (2) and explicitly marking what could not be determined.
  No bump, adaptation, or test-run happens before approval; that
  work starts only after approval, through the existing patch flow.

### D7. Approval — formal audited gate on the report
- Status: SETTLED in interview (record Final).
- Decision: Option A. When an impact report is ready, the dependency
  row enters `awaiting_decision`. Owner/Maintainer (existing approver
  roles) approve or deny on the report in the dashboard; Developers
  can trigger checks and request reports but not approve. Approve
  authorizes exactly one thing: the worker runs the existing patch
  flow (bump manifest + lockfile, model adaptation if needed, run
  repo tests) and delivers the usual PR/branch `Proposal`. Merge
  still needs the existing FR-9 gate, unchanged. Deny marks that
  specific version `declined`: the row stays quiet until a newer
  version appears, then it re-proposes with a fresh report. Every
  decision is audit-logged with report id, decider, and reason.

### D8. Post-approval patch shape and grouping
- Status: SETTLED in interview (record Final), with the user's grouping
  clarification.
- Decision: Option A on the bump itself: approving a version rewrites
  the manifest spec to the approved target (preserving existing spec
  style where one exists, e.g. `^1.2.3` -> `^1.9.0`, exact pin ->
  exact pin) and refreshes the lockfile to resolve it.
- Grouping is user-initiated, agent-decided: the approver may approve
  a single update exclusively, or choose "update all" to approve
  every `awaiting_decision` row at once (a repo can carry many
  packages; one-after-the-other is not the expected workflow). Once
  approved — singly or in bulk — the agent/model responsible for
  patching decides whether the approved updates land as one PR or
  multiple PRs (relatedness: overlapping code touched, dependency
  edge, shared adaptation), and discloses the grouping reason in
  each PR, as the existing delivery flow already does. A single
  exclusive update still requires the user's approval (D7) before
  patching, and the agent reports back its result; merge still
  needs the existing FR-9 gate, unchanged.

### D9. "Auto" means batch processing with a single report
- Status: SETTLED in interview (record Final) — user clarification that
  corrects a per-package reading of D6/D7/D8.
- Decision: "Auto" here names how the agent works, not a way to skip
  approval. On a check, the agent goes through all tracked packages
  at the same time, runs the impact analysis (D6) across them, and
  comes out with a single combined summary report for that check
  (per-package findings as sections inside it). The user is not
  asked to approve a stack of separate per-package reports. The
  single report guides one decision point before patching; after
  it, D8 grouping (agent decides one PR vs multiple, discloses why)
  applies. Per-package reports remain possible in the sense that a
  single exclusive update produces a report covering just that one
  package.

### D10. Decision granularity on the combined report
- Status: SETTLED in interview (record Final).
- Decision: Option A. The combined report lists each update with its
  impact section and a checkbox, all ticked by default. The approver
  may untick individual packages, then approves once. Ticked packages
  go to patching (agent groups into PRs per D8/D9). Unticked packages
  are marked `declined` for that specific version only: they stay
  quiet until a newer version appears, then rejoin the next combined
  report with a fresh impact section.

### D11. Dashboard — Dependencies tab on the repo page
- Status: SETTLED in interview (record Final).
- Decision: Option A. A Dependencies tab on the repo detail page:
  one table per repo with columns Package, Ecosystem, Manifest spec,
  Installed (lockfile-resolved per D3), Latest, Update
  (major/minor/patch badge or "up to date"), Security (tag linking
  to the `Finding` when present), Status (`up_to_date /
  update_available / awaiting_decision / proposed / declined /
  ignored`), Last checked. Row action "View impact" jumps to that
  package's section in the latest combined report. Page actions:
  "Check updates now" and "View latest report". No cross-repo
  rollup page in v1.

### D12. Manifest coverage — broad v1
- Status: SETTLED in interview (record Final).
- Decision: Option B. v1 covers, per ecosystem: Node — `package.json`
  with npm (`package-lock.json`), yarn (`yarn.lock`), and pnpm
  (`pnpm-lock.yaml`); Python — `pyproject.toml` (PEP 621
  `project.dependencies` and Poetry-style dependencies),
  `requirements*.txt` (including `-r` includes), `Pipfile` /
  `Pipfile.lock`, and pdm/uv projects (`pdm.lock`, `uv.lock` as the
  resolved-version source). This deliberately exceeds what the
  current sandbox allowlist and patch rewriters support (today:
  npm only, Python `.txt` bumps only), so new sandbox tool entries,
  parsers, and manifest rewriters for the added formats are part of
  this feature's implementation scope, not follow-ups.

### D13. "Latest" definition
- Status: SETTLED in interview (record Final).
- Decision: Option A. Latest (the table column and the proposed
  target) is the absolute latest stable release that exists, even
  when the current manifest range forbids it. Pre-releases are
  ignored unless the installed version is itself a pre-release.
  Yanked/withdrawn releases never count as latest. When an in-range
  update also exists (installed `1.2.3`, wanted `1.9.0`, latest
  `2.0.0`), the report names both but proposes the absolute latest,
  noting the in-range step as the lower-risk alternative.

### D14. Report trigger, proactivity, and check cadence
- Status: SETTLED in interview (record Final).
- Decision: Option A with part of C. Each DependencyCheck updates
  the table. A new combined impact report is generated automatically
  (rows move to `awaiting_decision`) only when the update set changed
  since the last report: a package gained an update, a newer version
  superseded a reported one, or an approved/declined state changed.
  Unchanged sets reuse the previous report with no model call. A
  manual "Generate report" can still force one. From C: proactive
  proposal/notification is reserved for majors and security-tagged
  updates (consistent with D1); minor/patch-only changes are tracked
  and reported but quiet — no push notification.
- Cadence (revises D5): dependency checks do not ride the 6h scan
  cadence. Default interval is 24 hours, configurable by the user
  via dashboard Settings.

### D15. Cadence scope — global default, per-repo override
- Status: SETTLED in interview (record Final).
- Decision: Option A. Dashboard Settings holds the install-wide
  dependency-check interval (default 24h) inherited by every repo.
  An individual repo may override it on its own page, including
  "never check automatically" (manual and on-connect checks still
  work).

### D16. Notifications — dashboard notification centre first
- Status: SETTLED in interview (record Final).
- Decision: Option A, as clarified and expanded by the user.
  Dependency-update notifications stay in the dashboard for v1 of
  this feature: they surface through a notification icon in the
  dashboard header, which is the start of an in-dashboard
  notification centre/pool. That pool is intended to also collect
  other notification events, including events that are additionally
  sent through Slack, email, and webhook — the dashboard pool is
  the common record, outbound channels are delivery options on top
  of it. For dependency updates specifically, dashboard notification
  is the default and only delivery until the user opts in: whether
  dependency notifications also go out by email (or Slack/webhook)
  is configurable by the user on the Settings page.

### D17. Notification centre scope in this feature
- Status: SETTLED in interview (record Final).
- Decision: Option A. This feature ships a stored dashboard
  notification record (unread/read, per user, linked to repo and
  report) and the header notification icon (unread count, listing),
  fed only by dependency events: new combined report, patch result
  after an approved update, and check failure. It is built for
  extension — existing email/Slack/webhook notifications are not
  retrofitted into the pool here; that migration is a follow-up
  reusing the same record.

### D18. Multiple manifests / monorepos
- Status: SETTLED in interview (record Final).
- Decision: Option A. The check walks the repo (excluding
  `node_modules`, `.venv`, and VCS directories) for all D12 manifest
  types. The Dependencies tab groups rows by manifest path, each
  manifest resolving installed versions from its own lockfile. A
  safety cap (precedent: `MAX_PYTHON_MANIFESTS = 20`) bounds the
  walk; hitting the cap is noted on the tab, never silent. The
  `Dependency` row key therefore includes `manifest_path`. One
  combined report still covers the whole repo (D9), with
  per-manifest sections.

### D19. Partial failure behaviour
- Status: SETTLED in interview (record Final).
- Decision: Option A. Partial results ship; every gap is a named
  state. A failed tool for one manifest leaves that manifest's
  section `check_failed` with the tool error and its rows at
  last-known values marked stale; other manifests update normally.
  A package with no usable changelog gets a report section stating
  exactly that, with impact assessed from the usage scan only; the
  model cites evidence or marks points undetermined (D6). A check
  where everything fails marks the run failed and fires the D17
  dashboard notification. Private-registry/auth failures are the
  same `check_failed` state with the registry host named; this
  feature adds no registry credential storage.

### D20. Collision with vulnerability Findings
- Status: SETTLED in interview (record Final).
- Decision: Option A. A dependency update defers to an active
  Finding patch for the same package in the same manifest: the row
  shows `covered_by_finding` (security tag, link to the
  Finding/Proposal) and is excluded from the combined report's
  patchable set while that Proposal is live. If the Finding's fixed
  version is below the latest, the report may propose latest but
  must state the security fix lands either way; delivering a
  dependency patch to a version >= the fix supersedes the Finding's
  Proposal, and the rescan resolves the Finding. Two live PRs
  bumping the same package in the same manifest never coexist: the
  dependency patch queues behind the Finding Proposal, then
  re-evaluates against the new installed version.

### D21. Silencing — decline-version and ignore-package
- Status: SETTLED in interview (record Final).
- Decision: Option A. Two reversible, audited silences, both
  Owner/Maintainer-only (as approval, D7): (1) decline-this-version
  (D10; quiet until a newer version appears) and (2) ignore-package
  per manifest+package — the row stays in the table, still
  freshness-checked so Latest stays honest, but it never enters a
  combined report, never triggers a proactive notification, and
  shows `ignored` with who/when. Un-ignoring rejoins the next
  report if an update is available.

### D23. Cost budget — separate from the security pipeline
- Status: SETTLED in interview (record Final), revised by the user after
  the initial Option A answer.
- Decision: The dependency feature has its own budget, independent
  of the vulnerability/security pipeline budget (NFR-8 per-run caps
  and daily alert thresholds do not govern dependency work, and
  dependency spending never parks or starves a security scan — and
  vice versa). The dependency budget is configured in dashboard
  Settings (alongside the D14/D15 cadence controls). Within this
  feature, DependencyCheck (tooling) and report generation (model)
  are still accounted as separate steps: if the dependency budget
  parks report generation, the table still updates, the tab shows
  `report_pending_cap` with a raise-budget/resume path for the
  dependency budget, and a D17 notification fires. A model outage
  fails only the report step (error recorded); the table still
  updates and the next check retries because the update set remains
  unreported.

### D22. Production-section boundary per format
- Status: SETTLED in interview (record Final).
- Decision: Option A. Node: `dependencies` + `optionalDependencies`
  tracked (optional labelled on the row); `devDependencies`
  excluded; `peerDependencies` not tracked as rows, but a peer range
  excluding the latest of a tracked package is noted in that
  package's report section. Python: `project.dependencies` + every
  `project.optional-dependencies` extra tracked (labelled by extra);
  `dependency-groups`, Poetry dev groups, Pipfile `develop`, and
  dev-named requirements files (existing `python_dev_packages`
  heuristics) excluded.

## Unresolved questions

_None. Q1–Q23 are settled as D1–D23 above (Final, accepted by the user on 2026-11-01). Registry egress allowlisting for the native tools
(npm/yarn/pnpm/PyPI hosts) inside the sandbox is an implementation
detail of D4, bounded by D19's named-failure contract._

## Scope contract

### Artifact-level boundary
In scope, when implementation is separately requested:
- Data: `Dependency` table (+ `manifest_path` in its key), a combined
  impact-report record per DependencyCheck, a DependencyCheck run
  type, and a stored dashboard-notification record (D2, D9, D17).
- Worker: manifest discovery across D12 formats and D18 monorepo
  walk, native-tool freshness checks in a fresh sandbox per check
  (D4), model-written combined impact reports (D6, D14), and
  post-approval patching reusing the existing patch/delivery flow
  with new manifest rewriters for yarn/pnpm/Pipfile/Poetry/PDM
  formats (D8, D12), honouring D20 Finding precedence.
- Dashboard: per-repo Dependencies tab (D11), combined-report view
  with per-package exclusion and approve/deny (D7, D10), Settings
  cadence and separate dependency-budget controls (D14, D15, D23),
  and the header notification icon fed by dependency events
  (D16, D17).
Out of scope: transitive dependency updating (D3); dev dependency
tracking (D22); auto-skipping report approval (D9 clarification);
registry credential storage (D19); a cross-repo dependencies page
(D11); retrofitting existing email/Slack/webhook notifications into
the dashboard pool (D17). Any of these requires its own interview.

### Done means
- A Python repo and a Node repo each show a correct Dependencies tab
  (manifest spec, lockfile-installed, latest, class, status) after a
  scheduled (default 24h) and a manual check, in npm/yarn/pnpm and
  pyproject/requirements/Pipfile variants from D12 fixtures.
- A changed update set produces one combined model report with
  changelog evidence, usage sites, and named unknowns; an unchanged
  set produces no new model call (D14).
- Approve (with exclusions) creates patch PR(s) with agent-decided
  grouping disclosed; deny/ignore silence exactly as D10/D21 specify;
  merges still pass the existing FR-9 gate.
- Existing test suite still passes; new behaviour covered by tests
  in the repo's existing unit/integration style; a colliding Finding
  patch demonstrably blocks a duplicate dependency PR (D20).

### Staged designs
This record is stage 1 (design only). Implementation is stage 2 and
starts only on a separate explicit request; accepting this record
does not authorize stage 2. The full dashboard notification centre
(all event types in the pool) is a deferred proposal for its own
interview (D17).
