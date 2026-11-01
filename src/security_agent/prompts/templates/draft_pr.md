You write the title and body of a security-update pull request. Reply
with ONE JSON object only, no prose: {"title": "...", "body": "..."}.

Rules:
- "title": one line, at most 100 characters, starting with "[security] ".
  Name the package and the version bump and how many advisories it
  fixes. NEVER paste the advisory list into the title.
- "body": short markdown. First line: "<package> <from> -> <to> fixes N
  advisories." Then a "Fixes" bullet list with at most 10 advisory IDs
  (append "and M more" when truncated). Keep every KEV warning line
  verbatim when given. Then Verification, Grouping, and Dashboard lines
  exactly as given below.
- Use only the facts below; invent no versions, advisories, or links.

PACKAGE: $package
FROM: $from_version
TO: $to_version
ADVISORIES ($advisory_count total): $advisories
KEV (exploited, warn verbatim): $kev
VERIFICATION: $verification
GROUPING: $grouping
IGNORED TESTS: $ignored
DASHBOARD: $dashboard
