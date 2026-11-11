"""Model brain: Settings-configured provider strategies + ledgered invoke.

`get_chat_model` is the factory facade: it reads the Owner's Settings
selection and builds the chat-model interface for that strategy
(OpenAI-shaped vendors via `ChatOpenAI`, native Anthropic via
`ChatAnthropic`). No Settings provider means BrainNotConfigured — loud,
actionable, never a silent template.
"""

from security_agent.brain.providers import BrainError, BrainNotConfigured

__all__ = ["BrainError", "BrainNotConfigured", "get_chat_model", "tracked_invoke"]


def get_chat_model():
    """Return the configured chat model (Settings → Brain).

    Raises BrainNotConfigured when no provider is selected or its key /
    base URL is missing; BrainError when the client cannot be built.
    """
    from security_agent.brain.providers import build_chat_model
    from security_agent.control.brain_settings import get_brain_config, get_brain_key

    cfg = get_brain_config()
    if not cfg["strategy"] or not cfg["model"]:
        raise BrainNotConfigured(
            "Brain is not configured. Ask an Owner to pick a provider and model "
            "in Settings → Brain."
        )
    return build_chat_model(
        cfg["strategy"],
        model=cfg["model"],
        api_key=get_brain_key(cfg["strategy"]) or "",
        base_url=cfg["base_url"],
    )


def _describe_brain() -> str:
    try:
        from security_agent.control.brain_settings import brain_status

        status = brain_status()
    except Exception:  # noqa: BLE001 - description is best-effort
        return "unconfigured brain"
    if status.get("strategy") and status.get("model"):
        return f"{status['strategy']}/{status['model']}"
    return "unconfigured brain"


def tracked_invoke(model, prompt: str, *, task: str):
    """Invoke + ledger token usage and spend against the run's spend cap (NFR-8).

    Prefers `usage_metadata`; each side the server omits falls back to
    a disclosed char-based estimate. Provider failures raise BrainError
    (loud: runs park, chat/news surface it). Raises CostCapExceeded
    (after parking) when a run-bound call crosses the cap.
    """
    from security_agent.control.cost import current_run_id, record_usage

    try:
        result = model.invoke(prompt)
    except Exception as exc:  # noqa: BLE001 - provider failures are BrainError
        raise BrainError(f"Brain call failed ({_describe_brain()}): {exc}") from exc
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
