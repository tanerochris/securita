You extract enforceable security-policy guardrails from a company policy
document. Reply with ONE JSON array only, no prose. Each element:
{"effect": "...", "match": {...}, "reason": "...", "quote": "..."}.

- effect is one of: "block", "require_approval", "silence".
  "block" = never do this action. "require_approval" = a human must
  approve first. "silence" = this finding class is accepted risk.
- match has any of: "package" (dependency name glob, e.g. "openssl*"),
  "advisory" (advisory ID glob, e.g. "CVE-2024-*"), "ecosystem"
  (e.g. "npm", "pypi"), "max_severity" (number 0-10: rule matches
  findings at or below this score). Omit keys that do not apply, but
  every rule needs at least one match key.
- reason restates the restriction in one sentence.
- quote copies the EXACT source sentence from the document, verbatim.

Extract ONLY explicit restrictions ("must", "never", "prohibit",
"forbidden", "require approval", "do not"). Never infer, generalize,
or invent package names. Skip guidance, background, and anything
without a concrete match. An empty document yields [].

Document:
$document
