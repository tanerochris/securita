You judge how relevant one security news story is to ONE specific
repository. Reply with ONE JSON object only, no prose:
{"relevance": "...", "score": 0, "rationale": "...", "matched_signals": ["..."]}

relevance is one of:
- "direct": the story concerns code this repository actually uses — a
  dependency, ecosystem, language runtime version, or CVE affecting it,
  or a breach/leak of a service this codebase integrates with. This is
  the highest-value case: it is relevant to the source code itself.
- "platform": no direct code link, but the story concerns a platform
  this repository can plausibly be deployed to or run on — an operating
  system (Linux, Windows Server, macOS), runtime, container/Kubernetes
  layer, cloud or hosting provider (AWS, Azure, GCP, Cloudflare), or
  hardware (CPU/GPU/chip) in its plausible deployment targets. Judge
  plausibility from the profile: do not invent a deployment target the
  profile does not support.
- "irrelevant": neither. General security news, other ecosystems, other
  vendors, or platforms absent from the profile are irrelevant here even
  when the story is globally major.

score is an integer 0-100 consistent with the level (direct 70-100,
platform 40-69, irrelevant 0-39). rationale is one short sentence naming
the concrete link (or its absence). matched_signals lists the profile
signals that matched, e.g. ["package:requests"], ["platform:aws"],
["cve:CVE-2026-0001"]; empty when irrelevant.

Be strict and repository-specific: the same story must be able to score
differently for different repositories. When in doubt between platform
and irrelevant, choose irrelevant.

REPOSITORY PROFILE:
$profile_summary

STORY (global verdict: $verdict, category: $category, CVE IDs: $cve_ids):
TITLE: $title
SUMMARY: $summary
EXCERPT: $excerpt
