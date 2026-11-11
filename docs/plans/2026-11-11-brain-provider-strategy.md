# Brain provider strategy + LLM config in Settings

Status: **Final** (scope accepted 2026-11-11).

## Goal

Owners configure the brain provider from Settings — OpenRouter, Vercel AI
Gateway, Ollama-local, custom OpenAI-compatible URL, native Google, native
Anthropic — with org-level keys, replacing the single env-configured model.

## Success Criteria

- An Owner can select any launch strategy, paste its key, pick a model, save,
  and get a working brain without touching env or redeploying.
- Gateway strategies show live provider/model lists; native strategies show
  curated model lists; custom accepts any model id.
- Every model call ledgers spend at that model's price; caps and alerts keep
  working across providers.
- A missing or broken provider fails loudly at runtime (clear brain error,
  runs park) — never silently and never with keyless templates.
- No `MODEL_*` env vars remain; existing installs migrate their env config
  into Settings on upgrade.

## Settled decisions

| # | Decision | Status |
|---|----------|--------|
| D1 | Key ownership | ✅ Org-level keys, managed through Settings |
| D2 | Role of Vercel AI SDK | ✅ Gateway as a provider preset, no TS SDK |
| D3 | Launch provider set | ✅ A — gateways + local + custom + native Google + native Anthropic |
| D4 | Model picker UX | ✅ Strategy-first; live gateway lists; curated natives |
| D5 | Validation on save | ✅ No check on save; brain errors at runtime |
| D6 | Per-model price source | ✅ A — live gateway prices + static native table |
| D8 | Brain required; Settings-only | ✅ Provider mandatory, Settings-only, no env |
| D7 | Scope contract | ✅ Accepted 2026-11-11 (see below) |

- **D1 — Org-level keys through Settings.** One key per configured provider,
  Owner-managed; scans, workers, and chat all use it. No per-user brain keys.
  Keys stored via the existing `EncryptedToken` + AES-256-GCM pattern;
  provider selection via install-wide settings overrides with env fallback
  removed per D8.
- **D2 — Vercel AI Gateway as a provider preset.** No TypeScript SDK, no chat
  rewrite; the Gateway is one more OpenAI-compatible Strategy entry beside
  OpenRouter.
- **D3 — Launch set A.** OpenRouter + Vercel AI Gateway + Ollama-local +
  custom OpenAI-compatible URL + native Google (`ChatOpenAI` preset, no new
  dep) + native Anthropic (`ChatAnthropic`, new `langchain-anthropic` dep).
  Factory returns the chat-model interface, not `ChatOpenAI` specifically.
- **D4 — Strategy-first picker; live gateway lists; curated natives.** Owner
  picks the strategy first (openrouter, vercel, ollama, custom, native), then
  the model UI follows: gateways live-fetch provider/model lists, natives show
  curated model lists. Ollama live-lists local tags with free-text fallback;
  custom is free-text; any live-fetch failure falls back to free-text plus
  last cached list.
- **D5 — No check on save; the brain errors at runtime.** Settings stores
  whatever the Owner saves. A missing or broken provider surfaces as a loud
  brain error when AI work runs (fail-loud/park, never silent templates). The
  probe remains as a manual "Test" action plus the CLI.
- **D6 — Live gateway prices + static native table.** Gateway model prices
  come from the models API alongside the fetched list; natives from a small
  versioned price table; custom/Ollama default $0 with operator override.
- **D8 — Brain requires a Settings-configured provider; `MODEL_*` env vars
  removed.** No keyless brain. First boot shows an empty state with a
  configure-brain notice; one-time env-to-Settings migration on upgrade;
  README/judges flow and `security-agent-probe` updated; non-AI scanning
  unaffected.

## Accepted scope (D7)

User acceptance, quoted verbatim from chat on 2026-11-11: "accept".

1. **Artifact boundary.** In scope: this plan, then on `go`, the
   implementation — provider Strategy registry plus factory, Settings brain
   section (strategy picker, org key management, model picker, probe-gated
   save changed per D5 to save-as-is, price display), encrypted key storage,
   settings-backed selection, env removal with migration, per-model ledger
   pricing, tests, and doc updates. Out of scope: per-user brain keys,
   TypeScript chat rewrite, streaming chat UI, native vendors beyond
   Anthropic/Google, SSO or notification changes.
2. **Done means.** Plan marked Final and accepted; on implementation, Owner
   configures any launch provider from Settings, all strategies build working
   chat models, ledger prices per model, `pytest` plus `ruff` green, README
   and `.env.example` updated.
3. **Stages.** Later stages (more natives, streaming, per-user keys) each
   return for their own interview; accepting this record never approves them.
4. **Execution words.** `go` authorizes only the boundary above. Anything
   wider stops for explicit approval first.

## Provider compatibility note (all verified from primary sources, 2026-11-11)

| Vendor | Native path through `ChatOpenAI`? | Detail |
|---|---|---|
| OpenAI | ✅ Yes | Native; the default. |
| Google Gemini | ✅ Yes | OpenAI-compat endpoint `…/v1beta/openai/`, Bearer key. |
| DeepSeek | ✅ Yes | Docs: "compatible with OpenAI/Anthropic", base `https://api.deepseek.com`. |
| xAI | ✅ Yes | Docs: "compatible with the OpenAI REST API", chat completions live. |
| Mistral | ✅ Yes | API ref serves `POST https://api.mistral.ai/v1/chat/completions`. |
| Meta | ✅ Yes | Current repo default is already OpenAI-compatible. |
| OpenRouter / Vercel Gateway | ✅ Yes | Both verified OpenAI-compatible; route to Anthropic/Google/etc. by model id. |
| Ollama / vLLM (local) | ✅ Yes | OpenAI-compatible `/v1` servers; Ollama lists locals at `GET /api/tags`. |
| Anthropic | ❌ No | Native API is `POST /v1/messages` + version headers — needs `ChatAnthropic`. |

Rule of thumb: every major vendor except Anthropic speaks OpenAI. Vendors not
listed here (e.g. Cohere, Bedrock, Vertex wrappers) stay unverified until a
user requests them; the custom-URL preset covers any OpenAI-shaped server.

## Approach

Strategy plus Factory behind the existing seams. A small `Strategy` protocol
(`key`, `label`, `build()` returning a LangChain chat model, `list_models()`,
`price_for()`, `needs_key`) with one entry per launch provider in a registry
dict, mirroring the embeddings module's `local`/`ollama`/`hosted`/`off`
dispatch. `get_chat_model()` stays the factory facade but returns the
chat-model interface and reads Settings-backed selection instead of env.

- OpenAI-shaped vendors (OpenRouter, Vercel, Ollama, custom, native Google,
  direct OpenAI/Meta via custom) ride `ChatOpenAI` strategies. Provider
  `langchain-openrouter` was considered and rejected: nothing the code reads
  needs it (verified: only `content`, `tool_calls`, `usage_metadata`).
- Native Anthropic rides a `ChatAnthropic` strategy (`langchain-anthropic`
  v1.7.10, Stable, MIT; needs `langchain-core>=1.7.5`). It must omit sampling
  params (the integration rejects non-default temperature) and set
  `max_tokens` (required by the Messages API); the probe qualifies it like
  every other strategy.
- Selection persists in `NotifyState` (plaintext-safe fields only); keys
  persist in `EncryptedToken` under `brain:<strategy>` owners, pasted once and
  never re-viewed — the same pattern as git PATs and notify secrets.
- Pricing: gateway `/models` responses cached with the model list carry
  per-model prices; natives use a versioned table; custom/Ollama default $0
  with an operator override field. The ledger prices each call at its
  resolved model price, replacing the single-price helper.
- No save-time validation (D5): saves store as-is; the factory raises a clear
  brain error at runtime when unconfigured or unreachable, and runs park.

## Steps

1. **Registry + strategies** (`src/security_agent/brain/providers.py`, new).
   `Strategy` protocol, registry, six launch entries, per-strategy
   `list_models()` (OpenRouter `/models` keyless; Vercel list endpoint —
   verify, else free-text + cached; Ollama `/api/tags`; curated natives).
   Factory in `brain/__init__.py` returns the chat-model interface from
   Settings-backed selection. Add `langchain-anthropic` to dependencies.
2. **Settings persistence** (`control/brain_settings.py`, new, + router
   endpoints). `NotifyState` selection keys (`brain.strategy`,
   `brain.model`, `brain.base_url`, `brain.price_override_usd`);
   `EncryptedToken` key owners (`brain:<strategy>`); Owner-only writes with
   CSRF; audit lines on key store/rotate/delete.
3. **Settings UI** (settings template + router). Brain section: strategy
   select first, then dynamic model UI per D4 (live lists with cached +
   free-text fallback), key paste (never re-displayed), price display,
   manual "Test" button running the existing probe against the saved config.
   Dashboard brain-status indicator + first-boot empty state.
4. **Runtime behavior.** Factory raises `BrainNotConfigured`/`BrainError`
   (loud, actionable). Update chat agent (drop the keyless message for a
   configure-brain error), patch adaptation, PR text, dependency reports,
   and news intel to surface it; runs park, non-AI pipeline unaffected.
5. **Ledger pricing** (`control/cost.py`). Resolve price per call from
   cached gateway pricing → native table → operator override → $0;
   replace the single-price path; keep caps/alerts unchanged.
6. **Env removal + migration.** Delete `MODEL_BASE_URL`, `MODEL_API_KEY`,
   `MODEL_NAME`, `MODEL_CHAT_NAME`, `MODEL_PRICE_PER_MTOK_USD` from config
   and `.env.example`; one-time upgrade import of env values into Settings
   (then ignored). Touchpoints: `config.py`, `brain/__init__.py`,
   `chat/agent.py`, `brain/pr_text.py`, `worker/deps_report.py`,
   `brain/embeddings.py` (hosted fallback), `ops/doctor.py`, `ops/backup.py`
   allowlist. No Alembic migration expected (reuses existing tables).
7. **Tests.** Unit: registry entries, factory per strategy (fakes, no
   network), price resolution, settings round-trip, runtime errors.
   Integration: Settings save/load, probe-against-stub per strategy.
   Update `test_policy_embeddings.py`, `test_pr_text.py`, `test_backup.py`,
   `test_chat.py`, `test_injection_suite.py`, `test_chat_validation.py`
   for the env removal. E2E: configure brain → chat turn → scan.
8. **Docs.** README setup/judges flow (provider setup required),
   `architecture.md` brain section, `.env.example`, key-rotation runbook.

## Validation Plan

- `uv run pytest` (full suite, incl. new + updated tests above).
- `uv run ruff check src tests` and `uv run ruff format --check src tests`.
- `uv run mypy` per repo config (new modules typed).
- Manual per strategy: configure in Settings → Test → dashboard chat turn →
  scan; confirm ledger shows per-model price and caps trip correctly.
- Manual failure paths: save bad key (stores; runtime brain error is clear),
  kill network during list fetch (cached list + free-text appears),
  fresh install (empty state, no crash), upgrade with legacy env (imported
  once, then env ignored).
- Security: key never re-viewed in UI, API, logs, or backup; decrypts
  audit-logged (existing crypto guarantees).

Highest-risk validation: the Anthropic-native tool-call round-trip through
`ChatAnthropic` (sampling/max_tokens quirks) — prove with the probe before
any other native work lands.

## Risks / Open Questions

- Vercel's models/pricing list endpoint is unverified; Step 1 verifies it,
  else Vercel ships free-text + cached/static prices like custom.
- Gateway model ids and prices churn; cached lists must show staleness and
  never block saving an id the cache hasn't seen.
- `langchain-core>=1.7.5` floor rises via the Anthropic dep; `uv sync`
  resolves it, but watch for LangChain v1 breaking notes.
- Legacy installs upgrading with only env config get a brain gap until the
  one-time import runs — the migration must run before the worker serves AI
  work.
- None of the above needs the user; all resolve inside implementation.

## Sources

- https://openrouter.ai/pricing
- https://openrouter.ai/api/v1/models
- https://vercel.com/docs/ai-gateway
- https://vercel.com/docs/ai-gateway/sdks-and-apis/openai-chat-completions/embeddings
- https://aistudio.google.com/docs/openai
- https://platform.claude.com/docs/en/api/messages
- https://api-docs.deepseek.com/
- https://docs.x.ai/developers/rest-api-reference/inference
- https://docs.mistral.ai/api
- https://pypi.org/pypi/langchain-openrouter/json
- https://pypi.org/pypi/langchain-anthropic/json
- https://github.com/ollama/ollama/blob/main/docs/api.md
