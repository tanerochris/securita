# FR-15 Model Brain — Sub-Plan

Status: **Final** (accepted 2026-10-28).

Parent: [2026-10-27-ai-security-agent.md](/Users/f3lx/Documents/projects/meta/docs/plans/2026-10-27-ai-security-agent.md) (v13) — FR-15, decision 1 (LangGraph + ChatOpenAI), Validation Probe, NFR-8 (cost control).

## Parent constraints (carried in, not re-decided here)

- Muse Spark via hosted OpenAI-compatible API; probe (auth, chat, tool call) gates Phase 1 (FR-15).
- LangGraph harness with LangChain `ChatOpenAI` and `base_url` override; custom loop rejected (checkpoints), Hermes rejected (operator call) (decision 1).
- Probe must return chat plus a tool call; no probe pass, no Phase 1 (Validation).
- Current fallback note is a thin custom LangChain chat adapter (Risks).
- Tool router governs sandbox-external tools; calls outside the manifest fail closed (decision 2).
- Per-run token caps, spend alerts, queue backpressure apply (NFR-8).

## Settled decisions

None yet — each answer below is recorded here as it settles.

- **D1. Probe-failure ladder:** _settled_ — portable native-tool-call gate on OpenAI-compatible Chat Completions: probe must round-trip native `tool_calls` via ChatOpenAI at `https://api.meta.ai/v1`; on shape mismatch try a thin adapter preserving the OpenAI-compatible shape; otherwise stop, Phase 1 gated. Portability constraint: every rung keeps the standard OpenAI-compatible shape; Responses-API-specific harness code and prompt-emulated tools excluded in v1.
- **D2. Tool-calling-absent operation:** _settled_ — full stop in v1: the harness invokes no tools without native tool calling; no emulated or chat-only path; Phase 1 stays gated per D1.
- **D3. Model substitution policy:** _settled_ — flexible configurable policy: Muse Spark is the default brain; the user can configure models per task (task list defined later) plus a substitution model, via a dashboard setting. Any family allowed (Anthropic, OpenAI, Muse) provided it meets the D1 portable shape (OpenAI-compatible Chat Completions + native tool calls) and passes the full probe before serving work; training-on-data tiers (e.g. `-contributor`) need explicit Owner opt-in.
- **D4. Runtime degradation:** _settled_ — bounded retry with backoff within per-run caps, then park under queue backpressure + alert; recovery replays completed tool results from logs (no re-execution of side-effecting tools) and reconstructs context from persisted run logs / log summaries (internal run memory), resuming via LangGraph checkpoint where valid. Substitution model applies to new runs, not mid-run switching.

## Pending parent amendments

- **FR-15** portable model policy: Muse Spark default; dashboard-configurable per-task models + substitution model; any family allowed if OpenAI-compatible Chat Completions + native tool calls; full probe before serving work; training-on-data tiers need Owner opt-in; no prompt-emulated or chat-only path in v1 (D1/D2/D3).
- **Validation Probe** is a native `tool_calls` round-trip via ChatOpenAI at `https://api.meta.ai/v1`; primary docs now confirm the endpoint shape; every configured model re-probes before serving work (D1/D3).
- **Risks** updates: endpoint-shape risk retired; added harness gotchas — strict tool-history pairing (400s), function names ≤1 dot, unsupported params rejected (D1).
- **Decision 1** note: Responses API deferred; harness stays on ChatOpenAI/Chat Completions per portability (D1).
- **Runtime degradation:** bounded retry within caps, then park + alert; recovery replays completed tool results from logs and resumes via run-log summaries / internal run memory with checkpoint (D4).

## Deferred follow-ups (proposals — not approved by this record)

- **Cross-run learning ("dreaming"):** distill past execution logs into persistent memories/skills so the system improves over time. Builds on the D4 internal run memory; needs its own interview and scope. Staged for after v1.

## Scope contract (accepted 2026-10-28)

- **Artifact boundary:** this sub-plan file plus the listed parent-plan amendments (applied to the parent upon acceptance). Out of scope: runtime code, tests, other FR sub-plans, follow-on specs.
- **Done means:** every D-item above is settled or explicitly marked unresolved, and the user accepts this contract in writing. Accepted with "Accept" (chat, 2026-10-28).
