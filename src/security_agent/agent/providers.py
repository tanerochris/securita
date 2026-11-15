"""Agent provider strategies: seven launch entries behind one factory seam.

Every chat-model vendor the install supports is one `Strategy` entry here:
OpenRouter + Vercel AI Gateway (gateways), Ollama-local, custom
OpenAI-compatible URL, native Google (OpenAI-compatible preset, no new
dep), native DeepSeek (OpenAI-compatible preset, no new dep), native
Anthropic (`ChatAnthropic`). OpenAI-shaped vendors ride
`ChatOpenAI`; only Anthropic needs its own client (the Messages API is
not OpenAI-shaped).

This module is pure: no database, no settings reads. Selection, keys,
and price caches live in `control/agent_settings.py`; the factory in
`security_agent.agent` resolves config and calls `build_chat_model`.
"""

from dataclasses import dataclass


class AgentError(Exception):
    """Loud agent failure: misconfigured or unreachable provider.

    Plain Exception deliberately (like CostCapExceeded): the patch
    repair loop swallows (PatchError, ScanError, RuntimeError,
    TimeoutError), and a agent failure must abort/park, never retry.
    """


class AgentNotConfigured(AgentError):
    """No usable agent: nothing selected, or key/base URL missing."""


#: Ledger fallback ($/MTok) when no price resolves: legacy cap
#: conversions and embeddings when no agent is configured. A
#: *configured* custom/Ollama agent ledgers $0, never this.
DEFAULT_PRICE_PER_MTOK_USD = 2.0

#: Max output tokens for the native Anthropic client. The Messages API
#: requires max_tokens; sampling params stay unset (the integration
#: rejects non-default temperature, so they are omitted entirely).
ANTHROPIC_MAX_TOKENS = 4096

#: Anthropic Models API base + version header for the live model list.
ANTHROPIC_API_BASE = "https://api.anthropic.com"
ANTHROPIC_VERSION = "2023-06-01"

#: Version of the static native price table below. Bump when prices
#: are refreshed; the Settings UI shows the version next to natives.
NATIVE_PRICE_TABLE_VERSION = 2

#: Blended $/MTok ≈ (input + output) / 2 per native model. Approximate
#: list prices, versioned above; the operator override in Settings wins
#: for any model missing here. Single blended number by design: the
#: ledger prices each call at one per-model rate.
NATIVE_PRICES: dict[str, float] = {
    # Google Gemini (OpenAI-compatible preset).
    "gemini-2.5-pro": 5.63,
    "gemini-2.5-flash": 1.40,
    "gemini-2.0-flash": 0.25,
    # Anthropic (native Messages API).
    "claude-opus-4-5": 15.0,
    "claude-sonnet-4-5": 9.0,
    "claude-haiku-4-5": 3.0,
    # DeepSeek (native OpenAI-compatible API).
    "deepseek-chat": 0.69,
    "deepseek-reasoner": 1.37,
}

CURATED_GOOGLE_MODELS = ("gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash")
CURATED_DEEPSEEK_MODELS = ("deepseek-chat", "deepseek-reasoner")
CURATED_ANTHROPIC_MODELS = ("claude-opus-4-5", "claude-sonnet-4-5", "claude-haiku-4-5")

_FETCH_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class Strategy:
    """One launch provider: how to build it, list it, and price it."""

    key: str
    label: str
    kind: str  # "openai" (ChatOpenAI) or "anthropic" (ChatAnthropic)
    default_base_url: str = ""
    needs_key: bool = True
    gateway: bool = False  # live model list + per-model prices
    blurb: str = ""
    #: How the Base URL field behaves: fixed (single known endpoint, hidden),
    #: optional (default shown, overridable), required (custom URL), or
    #: unused (no base URL at all, hidden).
    base_url_mode: str = "fixed"


STRATEGIES: dict[str, Strategy] = {
    "openrouter": Strategy(
        key="openrouter",
        label="OpenRouter",
        kind="openai",
        default_base_url="https://openrouter.ai/api/v1",
        gateway=True,
        blurb="One key, every vendor. Live model list with prices.",
    ),
    "vercel": Strategy(
        key="vercel",
        label="Vercel AI Gateway",
        kind="openai",
        default_base_url="https://ai-gateway.vercel.sh/v1",
        gateway=True,
        blurb="Vercel gateway preset. Live list when reachable, else free text.",
    ),
    "ollama": Strategy(
        key="ollama",
        label="Ollama (local)",
        kind="openai",
        default_base_url="http://localhost:11434/v1",
        needs_key=False,
        blurb="Local Ollama server. Lists installed tags; free.",
        base_url_mode="optional",
    ),
    "custom": Strategy(
        key="custom",
        label="Custom OpenAI-compatible",
        kind="openai",
        needs_key=False,
        blurb="Any OpenAI-shaped server: host, port, path. Free text model id.",
        base_url_mode="required",
    ),
    "google": Strategy(
        key="google",
        label="Google Gemini (native)",
        kind="openai",
        default_base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        blurb="Native Gemini through Google's OpenAI-compatible endpoint.",
    ),
    "anthropic": Strategy(
        key="anthropic",
        label="Anthropic (native)",
        kind="anthropic",
        blurb="Native Anthropic Messages API. Curated model list.",
        base_url_mode="unused",
    ),
    "deepseek": Strategy(
        key="deepseek",
        label="DeepSeek (native)",
        kind="openai",
        default_base_url="https://api.deepseek.com/v1",
        blurb="Native DeepSeek API. Curated model list.",
    ),
}

#: UI order: gateways, local, custom, natives.
STRATEGY_ORDER = ("openrouter", "vercel", "ollama", "custom", "google", "anthropic", "deepseek")


def strategy_label(key: str) -> str:
    entry = STRATEGIES.get(key or "")
    return entry.label if entry else (key or "unconfigured")


def build_chat_model(strategy: str, *, model: str, api_key: str = "", base_url: str = ""):
    """Build a LangChain chat model for a strategy (no network, no DB).

    Raises AgentNotConfigured when the strategy needs a key or base URL
    it was not given; AgentError when the client cannot be constructed.
    """
    from pydantic import SecretStr

    entry = STRATEGIES.get(strategy or "")
    if entry is None:
        raise AgentError(f"Unknown agent strategy {strategy!r}. Pick one in Settings → Agent.")
    if not (model or "").strip():
        raise AgentNotConfigured("Agent model is empty. Pick a model in Settings → Agent.")
    key = (api_key or "").strip()
    if entry.needs_key and not key:
        raise AgentNotConfigured(
            f"Agent strategy {entry.label} needs an API key. Paste one in Settings → Agent."
        )
    if entry.kind == "anthropic":
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError as exc:
            raise AgentError(
                "Native Anthropic needs the langchain-anthropic package "
                "(run `uv sync` to install it)."
            ) from exc
        try:
            # Documented ctor names as a kwargs dict: the fields carry
            # legacy aliases (model_name/max_tokens_to_sample) that vary
            # across langchain-anthropic versions, so static calls pin to
            # one version's stub while this works on all of them.
            kwargs: dict = {
                "model": model.strip(),
                "api_key": SecretStr(key),
                "max_tokens": ANTHROPIC_MAX_TOKENS,
            }
            return ChatAnthropic(**kwargs)
        except Exception as exc:  # noqa: BLE001 - build failures are AgentError
            raise AgentError(f"Could not build the Anthropic agent: {exc}") from exc
    base = (base_url or "").strip() or entry.default_base_url
    if not base:
        raise AgentNotConfigured(
            f"Agent strategy {entry.label} needs a base URL. Set one in Settings → Agent."
        )
    from langchain_openai import ChatOpenAI

    try:
        return ChatOpenAI(
            model=model.strip(),
            api_key=SecretStr(key or "not-needed"),  # keyless local servers
            base_url=base,
            temperature=0,
        )
    except Exception as exc:  # noqa: BLE001 - build failures are AgentError
        raise AgentError(f"Could not build the {entry.label} agent: {exc}") from exc


def _openrouter_blended(pricing: dict) -> float | None:
    """Blended $/MTok from an OpenRouter pricing block, else None."""
    try:
        prompt = float(pricing.get("prompt") or 0)
        completion = float(pricing.get("completion") or 0)
    except (TypeError, ValueError):
        return None
    if prompt < 0 or completion < 0:
        return None
    return (prompt + completion) / 2 * 1_000_000


def fetch_openrouter_models() -> list[dict]:
    """Live OpenRouter model list with per-model prices (keyless)."""
    import httpx

    try:
        resp = httpx.get("https://openrouter.ai/api/v1/models", timeout=_FETCH_TIMEOUT_SECONDS)
        resp.raise_for_status()
        rows = resp.json().get("data", [])
    except Exception as exc:
        raise AgentError(f"OpenRouter model list unavailable: {exc}") from exc
    out = []
    for row in rows or []:
        mid = (row or {}).get("id")
        if not mid:
            continue
        out.append({"id": str(mid), "price": _openrouter_blended((row or {}).get("pricing") or {})})
    return out


def fetch_openai_list_models(base_url: str, api_key: str = "") -> list[dict]:
    """Live `GET {base}/models` ids (OpenAI list shape, no prices).

    Used for the Vercel preset, whose list endpoint is otherwise
    unverified: any failure means free-text + cached, never a block.
    """
    import httpx

    base = (base_url or "").rstrip("/")
    if not base:
        raise AgentError("No base URL for the model list.")
    headers = {"Accept": "application/json"}
    if (api_key or "").strip():
        headers["Authorization"] = f"Bearer {api_key.strip()}"
    try:
        resp = httpx.get(f"{base}/models", headers=headers, timeout=_FETCH_TIMEOUT_SECONDS)
        resp.raise_for_status()
        rows = resp.json().get("data", [])
    except Exception as exc:
        raise AgentError(f"Model list unavailable at {base}/models: {exc}") from exc
    return [{"id": str(row["id"]), "price": None} for row in rows or [] if (row or {}).get("id")]


def fetch_anthropic_models(api_key: str) -> list[dict]:
    """Live Anthropic model list (`GET /v1/models`, active only).

    Follows `has_more`/`last_id` pages (capped) and maps known ids to the
    static price table; unknown ids carry no price. Key-authenticated:
    raises AgentError without a key or on any HTTP failure.
    """
    import httpx

    key = (api_key or "").strip()
    if not key:
        raise AgentError("No API key for the Anthropic model list.")
    out: list[dict] = []
    after: str | None = None
    for _ in range(5):
        params: dict[str, str | int] = {"limit": 1000}
        if after:
            params["after_id"] = after
        try:
            resp = httpx.get(
                f"{ANTHROPIC_API_BASE}/v1/models",
                params=params,
                headers={
                    "Accept": "application/json",
                    "anthropic-version": ANTHROPIC_VERSION,
                    "Authorization": f"Bearer {key}",
                },
                timeout=_FETCH_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            payload = resp.json() or {}
        except Exception as exc:
            raise AgentError(f"Anthropic model list unavailable: {exc}") from exc
        for row in payload.get("data", []) or []:
            if (row or {}).get("lifecycle", "active") != "active":
                continue
            mid = (row or {}).get("id")
            if not mid:
                continue
            out.append({"id": str(mid), "price": NATIVE_PRICES.get(str(mid))})
        if not payload.get("has_more"):
            break
        after = payload.get("last_id") or None
        if not after:
            break
    return out


def fetch_ollama_models(base_url: str) -> list[dict]:
    """Live Ollama tag list via `GET {host}/api/tags` (locals are free)."""
    import httpx

    base = (base_url or "").strip().rstrip("/")
    if base.endswith("/v1"):
        base = base[: -len("/v1")]
    if not base:
        raise AgentError("No base URL for the Ollama tag list.")
    try:
        resp = httpx.get(f"{base}/api/tags", timeout=_FETCH_TIMEOUT_SECONDS)
        resp.raise_for_status()
        rows = resp.json().get("models", [])
    except Exception as exc:
        raise AgentError(f"Ollama tag list unavailable at {base}/api/tags: {exc}") from exc
    return [{"id": str(row["name"]), "price": 0.0} for row in rows or [] if (row or {}).get("name")]
