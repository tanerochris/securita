"""Model brain: portable ChatOpenAI client + native tool_calls probe gate (FR-15)."""

from security_agent.config import get_settings


def get_chat_model(task: str | None = None):
    """Return a ChatOpenAI brain. Chat Completions + native tool calls only (FR-15 D1)."""
    from langchain_openai import ChatOpenAI
    from pydantic import SecretStr

    s = get_settings()
    # Any OpenAI-compatible model allowed if the probe passes; tasks may override later.
    _ = task
    return ChatOpenAI(
        model=s.model_name,
        api_key=SecretStr(s.model_api_key or "unset"),
        base_url=s.model_base_url,
        temperature=0,
    )


def tracked_invoke(model, prompt: str, *, task: str):
    """Invoke + ledger token usage against the current run's cap (NFR-8).

    Prefers `usage_metadata`; each side the server omits falls back to
    a disclosed char-based estimate. Raises CostCapExceeded (after
    parking) when a run-bound call crosses the cap.
    """
    from security_agent.control.cost import current_run_id, record_usage

    result = model.invoke(prompt)
    usage = getattr(result, "usage_metadata", None) or {}
    prompt_tokens = usage.get("input_tokens") or 0
    completion_tokens = usage.get("output_tokens") or 0
    estimated = False
    if not prompt_tokens:
        estimated = True
        prompt_tokens = max(1, len(prompt) // 4)
    if not completion_tokens:
        estimated = True
        completion_tokens = max(1, len(str(getattr(result, "content", "") or "")) // 4)
    record_usage(
        current_run_id(), task, int(prompt_tokens), int(completion_tokens), estimated=estimated
    )
    return result
