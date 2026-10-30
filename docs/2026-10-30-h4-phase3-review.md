# H4 — Phase 3 (Python Reachability) Implementation Review

Date: 2026-10-30. Scope: validation-only review of H4 against
[the H4 sub-plan](plans/2026-10-30-h4-phase3-python.md) (D1–D5, Slices A–E),
plus security, memory/leak, performance, and best-practice review.
No product code was changed by this review.

Method: six independent read-only reviewers (plan compliance, scan,
reachability, patch, security, memory/perf/quality) plus one adversarial
critic that re-inspected the strongest PASS claims, followed by parent-run
gates and direct spot-checks of every falsified claim.

## Verdict

**H4 is functionally implemented as planned, with 5 confirmed medium gaps,
1 unproven enforcement claim, and 1 pre-prod blocker owned outside H4.**
The detect → reach → patch loop for Python works end-to-end and mirrors the
Node loop. No H4 slice is missing. The gaps below are correctness/hardening
defects inside otherwise-present features, not absent features.

Do not read this as "release-ready": the Docker sandbox (follow-up #1) is
still a stub, so production stays fail-closed and non-production runs
execute hostile repo code on the host (see Security S1).

## Gate results (parent-run, this review)

| Gate | Command | Result |
|---|---|---|
| H4 focused tests | `pytest tests/unit/test_python_{scan,reachability,patch}.py tests/e2e/test_h4_validation.py -q` | 57 passed |
| Full suite | `pytest tests/ -q` | 280 passed, 2 skipped |
| Skips | — | `test_h2_validation.py:253` osv-scanner not on PATH; `test_deliver.py:528` ssh signing unavailable. Both environmental. |
| Lint | `ruff check src tests` | All checks passed |
| Types | `mypy` | **4 errors** — see Best Practice B1. None in H4 modules. |

Test PASS claims in this report were corroborated by execution.
Code-inspection claims cite `file:line` and were spot-checked by the parent
for every falsified item (G1–G5, U1).

## Plan-compliance matrix

| Clause | Verdict | Evidence |
|---|---|---|
| D1 manifest discovery, cap 20, one osv-scanner call per file | PASS | [scan.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:210) `PYTHON_LOCK_NAMES`/`MAX_PYTHON_MANIFESTS=20`; [scan.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:232) `discover_python_manifests`; tests `test_python_scan.py:94-131` |
| D1 setup.py never executed; unpinned-only skipped with note | PASS | [scan.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:257) `python_unpinned_note` (existence probe only) |
| D1 no-manifest repos finish DONE-empty (not npm failure) | PASS | [scan.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:542); `test_python_scan.py:275-284` |
| D1 merged drafts, severity fail-loud | PASS | [scan.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:358) `merge_drafts` raises `ScanError` on conflict |
| D2 migration 0007, `Finding.ecosystem` nullable | PASS (test gap G6) | [0007_ecosystem.py](/Users/f3lx/Documents/projects/meta/migrations/versions/0007_ecosystem.py:12); [models.py](/Users/f3lx/Documents/projects/meta/src/security_agent/db/models.py:220) |
| D2 routing PyPI→Python, npm/NULL→Node, unknown→union fail-open | PASS | [reachability.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/reachability.py:652); [patch.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:956) groups keyed `(ecosystem, package)` |
| D3 AST graph, never imports repo code | PASS | [reachability.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/reachability.py:436) `parse_python_imports` (`ast.parse` only) |
| D3 import/from absolute+relative; literal dynamics static | PASS with gap G4 | [reachability.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/reachability.py:456) |
| D3 non-literal dynamics fail open | **GAP G4** (aliased forms) | See Confirmed gaps |
| D3 stdlib + first-party shadowing, PEP 503 + alias table | PASS with gap G5 | [reachability.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/reachability.py:529) `package_of_python` |
| D3 roots = all first-party files; test-only imports reachable | PASS in code, untested for Python (R3) | [reachability.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/reachability.py:544) `analyze_python` |
| D3 oversize/unparseable fail open with note; symlink/venv skip | PASS | [reachability.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/reachability.py:558); 1 MB cap at `:43` |
| D4 `==`-only surgical rewrite preserving extras/markers/comments | PASS with gap G2 | [patch.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:292) `_rewrite_pin_line` |
| D4 transitive appended pin; lock/non-`==` report-only | PASS in code, enforcement **UNPROVEN U1** | [patch.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:566) `validate_python_patch` |
| D4 sanitized pins-only install, `--only-binary :all:`/`--no-input`/`--target` | **GAP G1** (not pins-only) | [patch.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:406) `sanitized_requirements` |
| D4 install failure → identical-output comparison with disclosure | **AT RISK R1** (near-unreachable) | [patch.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:162) `compare_test_runs` |
| D4 verify = repo tests else static; 3 rounds then report-only | PASS | [patch.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:541), `MAX_ROUNDS=3` at `:760` |
| D5 shared planes unchanged (KEV, lifecycle, delivery, gates, news, scheduler, graph) | PASS behaviorally; not diff-provable (U2) | [graph.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/graph.py:25) 7 linear nodes; zero ecosystem branching in shared modules |
| Slice A KEV-cache lock, audit-store lock, audited `env`, `pip-install`+`pytest` manifest | PASS with risk S3 | [scan.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:45); [audit/__init__.py](/Users/f3lx/Documents/projects/meta/src/security_agent/audit/__init__.py:37); [tools.py](/Users/f3lx/Documents/projects/meta/src/security_agent/sandbox/tools.py:27) |
| Slice E e2e mirrors H2 (patch / silent / report-only / withhold-approval), offline only | PASS with gap R4 | [test_h4_validation.py](/Users/f3lx/Documents/projects/meta/tests/e2e/test_h4_validation.py:119) |
| No new config, no new dependency | PASS | [config.py](/Users/f3lx/Documents/projects/meta/src/security_agent/config.py:10) (no H4 field); [pyproject.toml](/Users/f3lx/Documents/projects/meta/pyproject.toml:11) |

## Confirmed gaps (parent spot-checked in source)

### G1 — Medium — Test-dep install is not pins-only (D4 violated)

[sanitized_requirements](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:406)
keeps any line with a parseable name verbatim (`out.append(line)`), so
`gunicorn>=1` and bare unpinned names are installed at floating versions.
The test suite asserts this behavior
(`test_python_patch.py:204-220`), so the test encodes the violation of the
plan's "sanitized pins-only requirements" (H4 plan D4).
Fix: re-serialize kept lines to canonical `name==version`; drop or pin
range/bare lines and record them in `skipped`.

### G2 — Medium — Bump silently drops compound specifiers and hashes

[_rewrite_pin_line](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:292):
for `pkg==1.0,!=1.5; marker` or `pkg==1.0 --hash=sha256:…`, the remainder
after the version token is dropped unless it starts with `;`. Compound
constraints and hashes are lost silently on bump, weakening the pin the
operator approved.
Fix: preserve a `,!=…` tail and `--hash` options, or refuse (report-only)
instead of dropping them.

### G3 — Medium — `-c` constraints and non-glob `-r` targets escape bump + rescan

[discover_requirement_files](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:286)
only returns `requirements*.txt` / `requirements/*.txt`. A
`constraints.txt` (via `-c`) or `-r deps/base.txt` target is neither bumped
nor rescanned, so an appended root pin can pass
[validate_python_patch](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:582)
while a constraint still pins the vulnerable version.
Fix: follow the same in-repo include graph used by `sanitized_requirements`
for bump/rescan discovery, including `-c` files.

### G4 — Medium — Aliased dynamic imports falsely silence findings (D3 violated)

[_is_dynamic_import_call](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/reachability.py:424)
recognizes only the exact names `__import__`/`import_module` and
`importlib.import_module`. Aliased forms
(`import importlib as il; il.import_module("x")`,
`from importlib import import_module as im; im("x")`) and
`getattr`/`eval` indirection emit neither a static nor an unresolved site,
so the verdict is `no-import-chain` SILENT. This contradicts D3's
"non-literal dynamics fail open."
Fix: track import aliases per file; treat any unresolvable dynamic-import
call shape as an unresolved (fail-open) site.

### G5 — Medium — Dotted namespace distros falsely silence findings

[package_of_python](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/reachability.py:529)
maps only the top segment through the alias table, so
`import google.cloud.storage` resolves to distro `google`, not
`google-cloud-storage`. Findings for namespace distros
(`google-cloud-*`, `azure-*`, `zope.*`) can be silenced incorrectly.
No test covers dotted namespace distros.
Fix: try progressively longer dotted prefixes against known finding
packages before falling back to the top segment.

### G6 — Low — Migration 0007 has no test

No test executes any Alembic migration:
[conftest.py](/Users/f3lx/Documents/projects/meta/tests/conftest.py:13)
builds schema via `Base.metadata.create_all`. Upgrade/downgrade of
[migration 0007](/Users/f3lx/Documents/projects/meta/migrations/versions/0007_ecosystem.py:12)
is unverified on both SQLite and Postgres. Repo-wide pattern, flagged here
because H4 introduced the migration.
Fix: one upgrade/downgrade smoke test per migration chain head.

## Unproven (claimed by plan, not demonstrated)

### U1 — Medium — Stale-lock rescan enforcement never exercised on a real lockfile

[validate_python_patch](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:555)
rescans all discovered manifests in code, but the test fake
(`test_python_patch.py:78-102`) regex-reads only `==` pins, so a
`poetry.lock` input yields no pins and "remediation" passes vacuously.
There is no `poetry.lock`/`Pipfile.lock`/`pdm.lock`/`uv.lock`-named test.
D4's "enforced mechanically by the stale-lock rescan, never silently
inconsistent" is therefore unproven, not disproven.
Fix: add one named stale-lock test per lock format with a fake scanner
that still reports the finding post-bump, asserting report-only.

### U2 — Low — D5 "untouched" cannot be diff-proven

The workspace has no `.git` directory. D5 was verified behaviorally
(zero ecosystem branching in `control/`, `news`, `scheduler`, `deliver`,
`graph`, `config`; unchanged 7-node topology), not against pre-H4 code.
Treat historical "untouched" as unverified; current behavior is verified.

## Risks (real, lower confidence or lower impact)

| ID | Sev | Risk |
|---|---|---|
| R1 | Low–Med | [compare_test_runs](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:162) requires byte-identical pytest output across two distinct `mkdtemp` workdirs ([patch.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:771)). Real pytest output embeds absolute paths and durations, so the D4 install-failure degradation path is near-unreachable in production and degrades to report-only instead. Mocked tests use static strings. Fix: normalize paths/durations before comparing. |
| R2 | Low | Re-lock guidance on exhaustion ([patch.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:681)) says "upgrade manually or replace" with no explicit re-lock instruction for lock-only findings (D4 wording). |
| R3 | Low | D3 "test-only imports count as reachable" holds in code (roots = all files) but has no Python test where the only import is in a test file. Node side is tested. |
| R4 | Low | E2E report-only case ([test_h4_validation.py](/Users/f3lx/Documents/projects/meta/tests/e2e/test_h4_validation.py:157)) uses `fixed_versions=[]` (no-fix), not a failing verify; failing-verify report-only is covered only in unit tests. The e2e fixture also has no `tests/`, so pytest-verify never runs through the graph. Same shape as H2 e2e. |
| R5 | Low | BOM / encoding-cookie Python files fail open for the whole graph ([reachability.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/reachability.py:560) uses `read_text()` without `tokenize` decoding). Safe direction (false-reachable noise), confirmed by probe, not by project tests. Fix: `tokenize.open`. |
| R6 | Low | CRLF bare-name lines lose their `\r` on rewrite ([patch.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:343)); mixed endings result. No CRLF test. |
| R7 | Low | `pdm.lock`/`uv.lock` dev-dependency heuristic falls through to prod ([scan.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:306)). Priority-only impact; dev findings are never silenced. |

## Security

Overall: the H4 Python logic is sound in isolation (argv-only execution,
AST-never-imports, symlink containment, `--only-binary` install, rescan
validation). The dominant risk is the shared execution plane, which H4
inherits rather than introduces.

### S1 — Critical (pre-prod blocker, deferred follow-up #1, not an H4 slice failure)

[assert_host_execution_allowed](/Users/f3lx/Documents/projects/meta/src/security_agent/sandbox/__init__.py:30)
blocks only `is_prod`. The Docker runner is still a sleep-stub
([runner.py](/Users/f3lx/Documents/projects/meta/src/security_agent/sandbox/runner.py:6));
the Docker policy in [shell.py](/Users/f3lx/Documents/projects/meta/src/security_agent/sandbox/shell.py:15)
is never wired into the graph — nodes call `run_scan`/`run_patch` directly.
Consequence: in any non-prod deployment, hostile repo code (pytest suites,
conftest, plugins, npm scripts posture) executes on the host; in prod the
pipeline fails closed and does not run at all. This contradicts the H4
plan's "disposable sandbox" wording for test-dep installs (D4) until
follow-up #1 lands. Tracked as Open in
[cross-phase-followups.md](/Users/f3lx/Documents/projects/meta/docs/cross-phase-followups.md).
**Release gate: do not run untrusted repos outside prod until #1 lands,
and prod cannot scan until it does.**

### S2 — High — Host environment leaks to hostile code

[run_allowlisted](/Users/f3lx/Documents/projects/meta/src/security_agent/sandbox/tools.py:84)
passes `{**os.environ, **env}` to every tool, including pytest/pip/npm.
Hostile test code can read `MASTER_KEY`, `DATABASE_URL`, and provider keys
from its own environment. The audit log records only env key names
([tools.py](/Users/f3lx/Documents/projects/meta/src/security_agent/sandbox/tools.py:79)),
which protects the log, not the child process. The same mechanism lets any
future caller override `PATH`/`LD_PRELOAD`/`PYTHONPATH` with values that
are never audited — the H4 plan's "audited env" (Slice A) overstates this.
Fix: allowlist child env (PATH, HOME, lang vars + explicit caller keys);
audit values for non-secret keys or hash them.

### S3 — Medium — OSV fixed-version strings trusted verbatim

[_fixed_versions](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:167)
and [apply_python_bump](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:381)
insert the scanner/OSV `fixed` string into `package=={target}` with no
PEP 440 or newline validation. A malformed value such as
`1.0\n evil==9` injects extra requirement lines that are later installed
and executed. Same trust issue for package names from scanner output
before DB storage.
Fix: validate with `packaging.Version` / a strict name regex; reject
anything containing whitespace or newlines.

### S4 — Medium — Wheel code executes at verify time (accepted posture, restated)

`--only-binary :all:` prevents sdist `setup.py` execution at install time,
but installed wheels run at verify time via
`PYTHONPATH=.pip-deps` and pytest plugin entry points
([patch.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:546)).
This matches the plan's stated `npm ci` posture, but combined with S1/S2
it means "install is safe" must not be read as "verify is safe."

### Confirmed security positives

- `shell=False` everywhere; manifest-prefix argv only
  ([tools.py](/Users/f3lx/Documents/projects/meta/src/security_agent/sandbox/tools.py:86)).
  Filenames, package names, and versions are argv/file data, never shell.
- `git clone` uses `--` before the URL, redacts the token, and strips the
  credentialed origin ([scan.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:96)).
- Symlink escapes excluded for both scan manifests and first-party Python
  files ([scan.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:224),
  [reachability.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/reachability.py:401)); tested.
- Reachability never executes repo code: `ast.parse` only, `setup.py`
  never run ([reachability.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/reachability.py:442)).
- Sanitized `-r` includes are resolve-inside, depth-capped (5),
  cycle-guarded, and 1 MB-budgeted
  ([patch.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:418)).
- Field encryption is AES-256-GCM with HKDF-separated subkeys
  ([crypto.py](/Users/f3lx/Documents/projects/meta/src/security_agent/crypto.py:32));
  repo tokens are audited by ID only.
- Low: diff secret scan covers only 8 marker prefixes
  ([patch.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:59));
  non-marker secrets in untracked files can enter `Proposal.patch`.
  Low: `keys.py:31` logs a generated `MASTER_KEY` once at WARNING —
  log capture at key ceremony would disclose it.

## Memory, leaks, and performance

No unbounded leak was found in long-lived structures: the audit store is a
`deque(maxlen=10000)` under an `RLock` with retention purge
([audit/__init__.py](/Users/f3lx/Documents/projects/meta/src/security_agent/audit/__init__.py:24)),
DB sessions commit/rollback/close on all paths
([session.py](/Users/f3lx/Documents/projects/meta/src/security_agent/db/session.py:29)),
KEV cache is TTL-bounded, the news throttle state is capped, and every
pipeline temp dir is reaped in a `finally`
(`scan.py:588`, `reachability.py:683`, `patch.py:782`).
No file handle, subprocess, or session leak was found on exception paths.

The defects are transient-memory and quadratic-CPU issues bounded by
hostile input size — a hostile repo can spike the worker, not grow it
forever:

| ID | Sev | Finding |
|---|---|---|
| P1 | High | [load_lockfile_packages](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:181) does `json.loads(lockfile.read_text())` with **no size cap**, re-parsed on every `normalize()` call. A 500 MB lockfile is fully buffered per manifest. The Python path caps reads at 10 MB ([scan.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:285)); the Node lock path does not. Fix: stat gate at `MAX_LOCK_PARSE_BYTES` + parse once per run. |
| P2 | Med | [run_allowlisted](/Users/f3lx/Documents/projects/meta/src/security_agent/sandbox/tools.py:86) uses `capture_output=True` and truncates **after** capture (`[:max_output]` at `:103`). A tool emitting ≫25 MB spikes memory before the slice. Fix: stream-truncate or spool to a temp file. |
| P3 | Med | [lockfile_context](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scan.py:187) linearly scans all lock entries per (package, advisory): O(vulns × entries). Fix: pre-index packages by name once per run. |
| P4 | Med | Reachability keeps all import sites/edges in memory with **no file-count cap** (per-file 1 MB cap exists at [reachability.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/reachability.py:43)), and [_verdict_for](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/reachability.py:296) runs a BFS per finding: O(findings × files). A 100k-file repo spikes both. Fix: file-count cap + inverted package→hits index with shared BFS. |
| P5 | Med | Patch reads requirements files unbounded and repeatedly: [apply_python_bump](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:338), `python_pin_resolves:393`, `_requirements_own:715`, `has_python_tests:506` (`pyproject.toml`). A multi-GB `requirements.txt` OOMs the patch worker before the sanitized 1 MB budget applies. Fix: reuse the 10 MB capped-read helper everywhere. |
| P6 | Med | Scheduler N+1, pre-existing and shared with H2/H3: [scheduler.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/scheduler.py:37) loads all repos then queries per repo; stale-run reaping filters in Python. Already tracked by follow-up #5's scale note. Fix: SQL-side filtering + join. |
| P7 | Low | [diff_text](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:210) concatenates strings in a loop (bounded by the 200k cap, so minor). Fix: list + `join`. |

Bounded-and-clean areas, verified: KEV fetch (30 s timeout, 6 h TTL,
fail-open), manifest count cap (20), Python lock read cap (10 MB),
sanitized-requirements budget (1 MB, depth 5), AST parsing (iterative
`ast.walk`, no own recursion; `RecursionError` caught fail-open), and the
JS/Python regexes (no catastrophic backtracking found).

## Best practice

- **B1 — `mypy` gate is red (4 errors), none in H4 modules:**
  [lifecycle.py](/Users/f3lx/Documents/projects/meta/src/security_agent/control/lifecycle.py:221),
  [news.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/news.py:57),
  [gates.py](/Users/f3lx/Documents/projects/meta/src/security_agent/control/gates.py:78),
  [brain/__init__.py](/Users/f3lx/Documents/projects/meta/src/security_agent/brain/__init__.py:15).
  Without git history this review cannot prove they pre-date H4; their
  locations (news/lifecycle/gates/brain) are outside every H4-touched
  module, and H4 modules type-check clean. Fix or explicitly waive before
  release — a red type gate trains operators to ignore it.
- **B2 — Duplicated repair loops:** `patch_python_group`
  ([patch.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/patch.py:598))
  and `patch_group` (`:821`) are near-identical ~90-line loops, and size-cap
  discipline is inconsistent across `patch.py:91/:175/:698` vs the capped
  readers in scan/reachability. Extract a shared capped-read helper and a
  templated repair loop; this is also the cheapest way to close P5.
- **B3 — Error handling is disciplined:** no bare `except:`, no swallowed
  errors without a disclosed note; fail-open paths log at `warning`
  (KEV `scan.py:73`, test-dep install `patch.py:488` degrades with a
  disclosure note per D4). Graph `fetch_signals` isolates news failures so
  they never block scans ([graph.py](/Users/f3lx/Documents/projects/meta/src/security_agent/worker/graph.py:44)).
- **B4 — Tests encode one violation:** the pins-only test asserts the
  G1 behavior (`gunicorn>=1` kept). When G1 is fixed, that test must change
  with it — flagging so the fix is not mistaken for a regression.

## Deferred by plan (not gaps)

From [cross-phase-followups.md](/Users/f3lx/Documents/projects/meta/docs/cross-phase-followups.md),
correctly excluded from H4 scope: #1 Docker sandbox runner (but see S1 —
it gates production), #11 managed-lockfile re-lock patching, #12 Python
entry-point narrowing, #13 `pyproject.toml`/`Pipfile`/PEP-621 scanning.
Report-only behavior for `poetry.lock`/`Pipfile.lock`/`pdm.lock`/`uv.lock`
findings is intended under #11/#13 — subject to U1's missing proof.

## Unresolved / not verified by this review

- Real `osv-scanner` binary behavior: every test fakes `scan_lockfile`.
  Whether the binary emits ecosystem exactly as `PyPI`/`npm` for all seven
  lock formats, and its internal lockfile parsing, were not executed
  (binary not on PATH; one H2 live test skipped for this reason).
  The plan's own Risks section already notes scanner parser drift.
- No load test was run (large monorepo / large lockfile): P1–P5 impacts
  are derived from code bounds, not measured.
- Postgres behavior of migration 0007 and lock contention under
  concurrent workers were inferred from code, not exercised.
- `deliver.py` / `gates.py` / `news.py` received only H4-adjacent review,
  not a deep audit.

## Recommended fix order

1. **S1/S2** — land follow-up #1 (Docker runner) and an env allowlist
   before scanning any untrusted repo outside a throwaway environment.
2. **G1 + G2 + S3** — one patch-module change: canonical pins-only
   serialization, preserve-or-refuse compound/hash tails, validate
   OSV fixed versions. Update the G1-encoding test.
3. **G4 + G5** — alias-aware dynamic imports (fail open) and dotted-prefix
   distro matching, with the missing namespace/alias tests.
4. **G3 + U1** — include-graph discovery for bump/rescan plus named
   stale-lock tests per lock format.
5. **P1 + P5 + B2** — shared capped-read helper; parse lockfiles once.
6. **G6 + B1** — migration smoke test; clear or waive the 4 mypy errors.
7. R1–R7 as hardening follow-ups in
   [cross-phase-followups.md](/Users/f3lx/Documents/projects/meta/docs/cross-phase-followups.md).

## Addendum — fixes applied (2026-10-30)

All fixable items above are implemented; non-phase items moved to
[cross-phase-followups.md](/Users/f3lx/Documents/projects/meta/docs/cross-phase-followups.md)
(#14 scheduler N+1, #15 repair-loop unification, #16 key-ceremony log,
#17 secret-marker coverage). S1 stays as follow-up #1 (Docker runner).

- G1: `sanitized_requirements` re-serializes to canonical
  `name[extras]==version[ --hash][; marker]`; ranges/bare/compounds dropped
  with notes. The G1-encoding test now asserts the drop.
- G2: `_preservable_spec_tail` keeps `,!=…` tails (refuses when the target
  is excluded) and refuses `--hash`/compound tails instead of mangling them.
- G3: `-r`/`-c` includes expand in `discover_python_manifests`
  (in-repo, depth-5, cycle-guarded), so included pins are bumped and
  rescanned; the sanitizer distinguishes true cycles from diamonds.
- G4/G5: dynamic-import aliases tracked per file (fail open);
  `package_of_python` tries dotted prefixes against the verdict target.
- G6: `tests/unit/test_migrations.py` runs the full Alembic chain plus a
  0007 downgrade/upgrade round-trip on throwaway SQLite.
- U1: the patch-scan fake is lock-aware; one stale-lock report-only test
  per managed format (`poetry`/`Pipfile`/`pdm`/`uv`) plus a group-level
  exhaustion test with re-lock guidance (R2).
- S2: child env is allowlisted (secrets never inherited); secret-pattern
  caller keys refused loudly. S3: OSV names/versions validated at ingest
  (`packaging.Version`, strict name regex) and targets re-validated at bump.
- P1–P5/P7: size-gated + mtime-cached lockfile parses, spooled tool output,
  prebuilt lockfile index, capped patch reads via the shared
  `read_text_capped`/`read_json_capped` helpers, 50k-file graph cap with
  truncation fail-open, cached BFS parents, spec-match memo, `join`ed diffs.
- R1/R5/R6/R7/R3/R4: volatile-output normalization, `tokenize.open` reads,
  CRLF-preserving bumps, pdm/uv dev heuristics, test-only and failing-verify
  e2e coverage. B1: mypy clean (4 pre-existing errors fixed).
- Report correction applied during implementation: the `deliver.py`
  suggestion to add `--` to `git checkout <branch>` would have changed
  branch-switch into path-restore; the stored branch name is validated
  instead. The new `run_allowlisted` sanitizer runs before semaphore
  acquisition so a refusal can never leak a worker slot.
- Live validation mirrors H2: `feelcoder/mcq` scans DONE-empty as designed
  (it ships no manifests); a pinned fixture copy yielded 16 real findings →
  16 reachable → honest report-only, and recent pins yielded 5 findings →
  2 verified proposals. Permanent live test:
  `tests/e2e/test_h4_validation.py::test_live_python_repo_scan_and_reachability`.

Gates after fixes: 311 passed, 3 skipped (all environmental); `ruff` and
`mypy` clean.


