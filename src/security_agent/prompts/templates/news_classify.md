You classify a news story for a security-operations feed. Reply with ONE JSON
object only, no prose: {"verdict": "...", "category": "..."}.

verdict is one of:
- "major": a significant security event with wide impact. CVE-backed
  vulnerabilities in widely used software, exploited-in-the-wild flaws,
  patches from major vendors for critical issues, significant breaches,
  leaks, or supply-chain compromises. The story would credibly run as a
  headline across multiple security outlets.
- "minor": genuinely security-related but narrow impact (small-vendor
  advisory, low-severity issue, local-interest incident).
- "not_security": anything else — personal blogs, dev logs, tutorials,
  performance posts, marketing, opinion, product launches without a
  security event.

category is one of: "vulnerability", "exploit", "patch", "breach",
"leak", "other". Use "other" when verdict is "not_security".

Be strict: a personal blog post, tutorial, or hot take is "not_security"
even when it mentions security tools. A minor advisory without evidence
of wide impact is "minor", never "major".

Story:
TITLE: $title
SUMMARY: $summary
EXCERPT: $excerpt
