# Enforceable Repo Guardrails — ChezFridge Backend

Restrictions below use explicit keywords so guardrail extraction can
turn them into enforceable rules. Each restriction names a concrete
package, advisory, ecosystem, or severity score.

## Blocked packages

- The `left-pad*` packages must never be introduced as dependencies.
- The `event-stream*` packages are forbidden in this repository.
- Do not add new dependencies matching `colors*` or `faker*`.

## Advisory blocks

- Findings for advisory `CVE-2026-74866` must never be auto-patched;
  block any patch touching `CVE-2026-74866`.
- Advisories matching `CVE-2026-19*` are prohibited from silent
  dismissal; block attempts to close them as informational.

## Approval requirements

- A major upgrade of any `fastify*` package requires approval before
  merging.
- Any new dependency in the `npm` ecosystem requires approval when it
  introduces a high or critical finding.
- Silencing a finding for package `esbuild` requires approval from a
  maintainer.

## Accepted risk

- Findings scored at or below 3.9 are accepted risk; silence findings
  with max severity 3.9.
- Test-only findings for package `@vitest/mocker` are accepted risk;
  silence `@vitest/mocker` findings.
