"""Native tool_calls probe gate (FR-15 D1/D2). No probe pass, no Phase 1.

Probes the Settings-configured brain, whatever strategy it uses: the
Anthropic-native client qualifies through the same round-trip as every
OpenAI-shaped strategy.
"""

from langchain_core.tools import tool


@tool
def probe_echo(text: str) -> str:
    """Echo back the given text (probe round-trip tool)."""
    return text


def run_probe() -> bool:
    """Round-trip a native tool_calls call via the configured brain.

    True only on native success. Raises BrainError when no provider is
    configured or the provider call fails (loud, actionable).
    """
    from security_agent.brain import get_chat_model, tracked_invoke

    model = get_chat_model().bind_tools([probe_echo])
    result = tracked_invoke(
        model, "Call probe_echo with text='probe-ok' and reply done.", task="probe"
    )
    calls = getattr(result, "tool_calls", None) or []
    return any(c.get("name") == "probe_echo" for c in calls)


def main() -> None:
    from security_agent.brain import BrainError

    try:
        ok = run_probe()
    except BrainError as exc:
        print(f"PROBE_FAIL: {exc}")
        raise SystemExit(1) from exc
    print("PROBE_PASS" if ok else "PROBE_FAIL")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
