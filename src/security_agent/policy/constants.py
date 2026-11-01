"""Policy RAG vocabulary: scopes, sources, effects, tasks (D1c/D2/D5)."""

SCOPES = ("platform", "repo")

SOURCES = ("upload", "editor", "readme")

# block | require_approval | silence enforce; allow exists only as an
# override_of exception (D2) and is rejected anywhere else.
EFFECTS = ("block", "require_approval", "silence", "allow")
EFFECT_RANK = {"allow": 0, "silence": 1, "require_approval": 2, "block": 3}

DOC_STATUSES = ("ready", "disabled")
RULE_STATUSES = ("pending", "confirmed", "disabled")

# Worker tasks a doc/rule can narrow itself to (D2 task filter, D5).
GUIDANCE_TASKS = ("adapt", "news-relevance", "unpatchable-guidance", "policy-extract", "pr-text")
ENFORCEMENT_TASKS = ("patch", "deliver", "ingest")
POLICY_TASKS = GUIDANCE_TASKS + ENFORCEMENT_TASKS
