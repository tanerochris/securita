# Sample Repo Security Policy — ChezFridge Backend

Test policy for exercising the repo policy upload. Delete or replace
before using in production.

## Patching and dependencies

- Patch reachable vulnerabilities before silent ones. Reachable findings
  are the default priority queue for every scan.
- Prefer minor and patch version bumps over major upgrades. A major
  upgrade needs a note in the pull request explaining what was checked.
- Lockfiles are the source of truth. Never hand-edit
  `package-lock.json`; regenerate it with the package manager.
- A dependency with no fixed version available stays open and tracked;
  it must not be closed as informational without a written reason.

## Severity thresholds

- Critical and high severity advisories should be patched within
  7 days of first being seen.
- Medium severity advisories should be patched within 30 days.
- Low severity advisories may wait for the next scheduled maintenance
  window, unless the advisory is listed in the CISA KEV catalog.
- KEV-listed advisories are treated as critical regardless of their
  CVSS score.

## Approvals

- Automated dependency patches may merge once CI passes.
- Major version upgrades require one human approval.
- Changes that touch authentication, session handling, or payment code
  require two human approvals, even when proposed by automation.
- Silencing or dismissing a finding always requires a reason and one
  human approval.

## Secrets and credentials

- No credentials, tokens, or private keys may be committed to the repo
  in any file, including tests, fixtures, and documentation.
- If a credential is ever committed by accident, rotate it immediately
  and treat the old value as compromised.
- Sample configuration files must use obvious placeholders such as
  `CHANGEME` rather than realistic-looking values.
- Report suspected leaked secrets to the security channel the same day
  they are found.

## Unpatchable advisories

- When no fixed version exists, document the exposure: which routes or
  jobs load the vulnerable package, and what input reaches it.
- Prefer a mitigation in this order: remove the dependency, replace it
  with a maintained alternative, constrain the reachable input, and
  only then accept the risk with an expiry date.
- Risk acceptances expire after 90 days and must be re-reviewed; they
  never apply to KEV-listed advisories.

## Contact

- Security owner: the repo maintainer team.
- Urgent issues: page the on-call engineer; do not wait for the next
  scan cycle.
