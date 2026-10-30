# H4 — Phase 3: Python Reachability (detailed sub-plan)

Status: done (2026-10-30). Parent: [implementation plan](2026-10-29-implementation-plan.md)
plus FR-2/3/4 sub-plans and [architecture.md](../architecture.md) (Phase 3).

## Goal

Same detect→reach→patch loop for Python targets. A Python repo with a
pinned vulnerable dependency gets scanned, verdicts, and a bump PR through
the unchanged graph; an unused dependency stays silent-with-reason; failed
verification yields report-only. Per H4 validation: Python fixtures mirror
the Node.js reachability/patch checks.

## FR-7 closure (just-in-time, decided here)

- **D1. Python scan inputs.** Per-run manifest discovery, polyglot-safe (no
  repo schema change): Node scans `package-lock.json` as before; Python
  scans `requirements.txt`, `requirements-*.txt`, `requirements/*.txt`,
  `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `uv.lock` — one capped
  osv-scanner invocation per file (max 20), merged with Node severity
  fail-loud semantics. `setup.py`/`setup.cfg`/unpinned-`pyproject.toml`-only
  repos are skipped with a run note: versions are never fabricated, and
  `setup.py` is never executed. Repos with no supported manifest finish
  DONE-empty with a note (previously such runs failed in `npm`).
- **D2. Ecosystem routing.** `Finding.ecosystem` (migration 0007, nullable;
  `npm`/`PyPI` from scanner output). Reachability routes `PyPI`→Python
  graph, `npm`/NULL→Node graph (NULL preserves pre-H4 behavior exactly),
  unknown→union of available graphs (fail open). Patch groups key on
  (ecosystem, package); unknown ecosystems sniff the template manifests,
  defaulting to the Node path.
- **D3. Reachability.** `ast`-based import graph, never importing repo code:
  `import`/`from` (absolute + relative), literal `__import__`/
  `importlib.import_module` as static sites, non-literal dynamics fail open.
  Stdlib (`sys.stdlib_module_names`, first-party shadowing wins) is neither
  package nor edge. Matching is PEP 503 normalized plus a curated
  import→distro alias table. Roots = all first-party files v1 (fail open;
  entry narrowing deferred). Oversize/undecodable/unparseable files fail
  open with a run note; symlink escapes and venv/build/cache dirs skipped.
  Test-only imports count as reachable (FR-3 D3).
- **D4. Patch.** `requirements.txt`-family `==` pins only: surgical
  line rewrite preserving extras/markers/comments; transitive deps get an
  appended pin. `poetry.lock`/`Pipfile.lock`/`pdm.lock`/`uv.lock` findings
  and non-`==` specs go report-only with re-lock guidance — enforced
  mechanically by the stale-lock rescan, never silently inconsistent.
  Verify = repo tests when present else static (FR-4 D2). Test deps install
  best-effort via sanitized pins-only requirements (`--only-binary :all:`,
  `--no-input`, `--target` workdir dir, never the ambient env); install
  failure degrades to identical-output comparison with disclosure, never to
  unpatchable. 3 repair rounds, then report-only (FR-4 D6).
- **D5. Shared, unchanged.** KEV join, lifecycle, delivery, gates, news
  matching, scheduler, and graph topology are language-agnostic and
  untouched. No new config, no new dependency.

## Slices (build order; each lands tested)

- **A. Data + tooling.** Migration 0007 (`ecosystem`), `normalize`
  records ecosystem, KEV-cache lock, audit-store lock (fixes concurrent
  append/purge entry loss), `run_allowlisted` gains audited `env`,
  manifest adds `pip-install` (baked safety flags) + `pytest`.
- **B. Scan.** Manifest discovery, per-file capped scans, merged drafts,
  per-ecosystem run notes. Done when: Python fixture lockfile yields
  canonical `PyPI` findings; mixed repo yields both; manifest-less repo
  finishes DONE-empty.
- **C. Reachability.** AST parser, first-party resolution (incl.
  `src/` layout), alias table, routing. Done when: importing fixture
  reachable with chain evidence, non-importing silent with
  `no-import-chain`, import-added reopens.
- **D. Patch.** Requirements bump, venv-free `--target` test install,
  pytest-or-static verify, rescan + secrets + diff-scope validate.
  Done when: reachable fixture yields a verified proposal; failing
  verify yields report-only with reason.
- **E. Validation.** `vuln-py-app` fixture + recorded OSV JSON; e2e
  mirrors the H2 checks (patch / silent / report-only / withhold-approval
  merges nothing). No live-repo test (offline only).

Dependencies: A gates everything; B gates C; C gates D; E last.

## Non-goals (deferred, see cross-phase follow-ups)

Managed-lockfile re-lock patching (poetry/pdm/uv/pipenv), unpinned-manifest
version resolution, Python entry-point narrowing, `pyproject.toml`/
`Pipfile`/PEP-621 spec scanning+patching, dashboard ecosystem display.

## Risks

- osv-scanner Python parser drift (mitigated: pinned inputs only, rescan
  enforces remediation mechanically).
- `pip install` supply chain during test-dep install (mitigated:
  sanitized pins-only file, `--only-binary :all:`, disposable workdir
  target, best-effort with disclosure; setup.py of repo deps can still
  run only inside the disposable sandbox, same posture as `npm ci`).
- Alias-table gaps (mitigated: normalized-equality fallback; misses fail
  toward silent only for exotic renames — table covers the common ones).
