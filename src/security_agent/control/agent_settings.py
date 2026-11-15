"""Settings-backed agent provider selection + org keys (agent strategy plan).

Selection (strategy/model/base_url/price override) lives in NotifyState
(plaintext-safe fields only); keys live in EncryptedToken under
`agent:<strategy>`, pasted once and never re-viewed — the same pattern
as git PATs and notify secrets. One key per configured provider,
Owner-managed; scans, workers, and chat all use it.

Saves store as-is (D5): no probe on save. A missing or broken provider
surfaces as a loud AgentError when AI work runs, and runs park.
"""

import json
import logging
from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from security_agent.agent.providers import (
    CURATED_ANTHROPIC_MODELS,
    CURATED_DEEPSEEK_MODELS,
    CURATED_GOOGLE_MODELS,
    DEFAULT_PRICE_PER_MTOK_USD,
    NATIVE_PRICES,
    STRATEGIES,
    AgentError,
    fetch_anthropic_models,
    fetch_ollama_models,
    fetch_openai_list_models,
    fetch_openrouter_models,
    strategy_label,
)
from security_agent.audit import get_shared_log
from security_agent.crypto import decrypt_field, encrypt_field
from security_agent.db.keys import get_encryption_key
from security_agent.db.models import EncryptedToken, NotifyState, Role, User
from security_agent.db.session import session_scope

log = logging.getLogger(__name__)
audit = get_shared_log()

AGENT_STRATEGY_KEY = "agent.strategy"
AGENT_MODEL_KEY = "agent.model"
AGENT_BASE_URL_KEY = "agent.base_url"
AGENT_PRICE_OVERRIDE_KEY = "agent.price_override_usd"
AGENT_CACHE_PREFIX = "agent.cache."  # + strategy: live list + prices + fetched_at

#: Marker for the one-time brain.* → agent.* rename import.
AGENT_RENAMED_KEY = "agent.renamed_from_brain"

#: Per-strategy key fingerprint prefix (first chars + last 4, never the key).
AGENT_KEY_HINT_PREFIX = "agent.key_hint."

_KEY_OWNER = "agent:{}"  # noqa: S105 - owner label, not a credential

#: brain.* state keys carried into agent.* — stored model/base_url are
#: deliberately NOT carried (operator chose to clear them and re-enter).
_CARRIED_STATE_KEYS = (
    ("brain.strategy", AGENT_STRATEGY_KEY),
    ("brain.price_override_usd", AGENT_PRICE_OVERRIDE_KEY),
)
_LEGACY_CACHE_PREFIX = "brain.cache."
_LEGACY_OWNER_PREFIX = "brain:"


def _read_state(db, key: str) -> str:
    row = db.get(NotifyState, key)
    return row.value if row is not None else ""


def _write_state(db, key: str, value: str) -> None:
    row = db.get(NotifyState, key)
    if row is None:
        db.add(NotifyState(key=key, value=value))
    else:
        row.value = value


def _parse_override(raw: str) -> float | None:
    try:
        value = float((raw or "").strip())
    except ValueError:
        return None
    return value if value >= 0 else None


def key_hint(plaintext: str) -> str:
    """Display fingerprint for a key: first 12 chars + last 4 (OpenRouter style).

    Short keys collapse to plain bullets so the hint never carries the key.
    """
    key = (plaintext or "").strip()
    if len(key) <= 16:
        return "••••••••"
    return f"{key[:12]}••••••••{key[-4:]}"


def _store_secret(owner: str, plaintext: str) -> bool:
    """Store/rotate one agent key. True when a row already held a key."""
    ciphertext = encrypt_field(plaintext, get_encryption_key())
    with session_scope() as db:
        try:
            with db.begin_nested():
                db.add(EncryptedToken(owner=owner, ciphertext=ciphertext))
                db.flush()
        except IntegrityError:
            row = db.scalar(select(EncryptedToken).where(EncryptedToken.owner == owner))
            if row is None:
                raise
            row.ciphertext = ciphertext
            return True
    return False


def get_agent_key(strategy: str) -> str | None:
    """Decrypted org key for a strategy (decrypts audit-logged, never re-viewed)."""
    with session_scope() as db:
        row = db.scalar(
            select(EncryptedToken).where(EncryptedToken.owner == _KEY_OWNER.format(strategy))
        )
        if row is None:
            return None
        return decrypt_field(row.ciphertext, get_encryption_key(), purpose=f"agent:{strategy}")


def has_agent_key(strategy: str) -> bool:
    """Whether a key is stored (existence only — no decrypt, no secret touch)."""
    with session_scope() as db:
        return (
            db.scalar(
                select(EncryptedToken).where(EncryptedToken.owner == _KEY_OWNER.format(strategy))
            )
            is not None
        )


def _require_owner(user: User) -> None:
    if user.role != Role.OWNER:
        raise PermissionError("Only an Owner may change the agent provider.")


def maybe_migrate_legacy_brain_keys() -> dict:
    """One-time brain.* → agent.* rename import. Idempotent via the
    renamed marker: after the first run legacy keys are never re-read.

    Copies carried state keys, model-list caches, and provider key rows
    to their agent.* names; stored model/base_url are intentionally left
    behind so the form starts blank. Old brain.* rows are kept untouched
    (rollback-safe: a downgrade keeps working); nothing is deleted.
    Returns what it did, without key material.
    """
    with session_scope() as db:
        if _read_state(db, AGENT_RENAMED_KEY):
            return {"migrated": False}
        carried: list[str] = []
        for old_key, new_key in _CARRIED_STATE_KEYS:
            if _read_state(db, old_key) and not _read_state(db, new_key):
                _write_state(db, new_key, _read_state(db, old_key))
                carried.append(new_key)
        caches = db.scalars(
            select(NotifyState).where(NotifyState.key.like(_LEGACY_CACHE_PREFIX + "%"))
        ).all()
        for row in caches:
            new_key = AGENT_CACHE_PREFIX + row.key[len(_LEGACY_CACHE_PREFIX) :]
            if not _read_state(db, new_key):
                _write_state(db, new_key, row.value or "")
                carried.append(new_key)
        tokens = db.scalars(
            select(EncryptedToken).where(EncryptedToken.owner.like(_LEGACY_OWNER_PREFIX + "%"))
        ).all()
        for row in tokens:
            new_owner = _KEY_OWNER.format(row.owner.split(":", 1)[1])
            exists = db.scalar(select(EncryptedToken).where(EncryptedToken.owner == new_owner))
            if exists is None:
                db.add(EncryptedToken(owner=new_owner, ciphertext=row.ciphertext))
                carried.append(new_owner)
        _write_state(db, AGENT_RENAMED_KEY, datetime.now(UTC).isoformat())
    if carried:
        audit.append(
            action_class="agent",
            decision="migrate",
            line=f"carried {len(carried)} brain.* keys to agent.*",
        )
    return {"migrated": True, "carried": carried}


def get_agent_config() -> dict:
    """Current agent selection. Runs the one-time legacy rename import
    first, so the migration always lands before any worker serves AI work."""
    maybe_migrate_legacy_brain_keys()
    with session_scope() as db:
        strategy = _read_state(db, AGENT_STRATEGY_KEY).strip()
        model = _read_state(db, AGENT_MODEL_KEY).strip()
        base_url = _read_state(db, AGENT_BASE_URL_KEY).strip()
        override_raw = _read_state(db, AGENT_PRICE_OVERRIDE_KEY).strip()
        hint = _read_state(db, AGENT_KEY_HINT_PREFIX + strategy).strip() if strategy else ""
    return {
        "strategy": strategy,
        "model": model,
        "base_url": base_url,
        "price_override": _parse_override(override_raw),
        "price_override_raw": override_raw,
        "has_key": bool(strategy) and has_agent_key(strategy),
        "key_hint": hint,
        "configured": bool(strategy and model),
    }


def save_agent_config(
    *,
    strategy: str,
    model: str,
    base_url: str = "",
    price_override: str = "",
    api_key: str = "",
    user: User,
) -> dict:
    """Owner-only agent save. Stores as-is (D5): no probe, no validation
    beyond Owner — a bad save surfaces as a loud runtime agent error."""
    _require_owner(user)
    strategy = (strategy or "").strip()
    model = (model or "").strip()
    base_url = (base_url or "").strip()
    price_override = (price_override or "").strip()
    entry = STRATEGIES.get(strategy)
    if entry is not None and entry.base_url_mode in ("fixed", "unused"):
        # Fixed-endpoint strategies never store a URL: a stale custom URL
        # from a previous strategy must not override the known endpoint.
        base_url = ""
    with session_scope() as db:
        _write_state(db, AGENT_STRATEGY_KEY, strategy)
        _write_state(db, AGENT_MODEL_KEY, model)
        _write_state(db, AGENT_BASE_URL_KEY, base_url)
        _write_state(db, AGENT_PRICE_OVERRIDE_KEY, price_override)
    audit.append(
        action_class="agent",
        decision="save",
        line=f"strategy={strategy or '—'} model={model or '—'} by={user.id}",
    )
    if (api_key or "").strip():
        key_strategy = strategy or "custom"
        rotated = _store_secret(_KEY_OWNER.format(key_strategy), api_key.strip())
        with session_scope() as db:
            _write_state(db, AGENT_KEY_HINT_PREFIX + key_strategy, key_hint(api_key.strip()))
        audit.append(
            action_class="credential",
            decision="allow",
            line=f"agent:{strategy or 'custom'} key {'rotated' if rotated else 'stored'} "
            f"by={user.id}",
        )
    return get_agent_config()


def delete_agent_key(strategy: str, user: User) -> bool:
    """Owner-only key delete. Returns True when a key was removed."""
    _require_owner(user)
    from typing import Any, cast

    from sqlalchemy.engine import CursorResult

    strategy = (strategy or "").strip() or "custom"
    with session_scope() as db:
        res = db.execute(
            delete(EncryptedToken).where(EncryptedToken.owner == _KEY_OWNER.format(strategy))
        )
        removed = (cast("CursorResult[Any]", res).rowcount or 0) > 0
        db.execute(delete(NotifyState).where(NotifyState.key == AGENT_KEY_HINT_PREFIX + strategy))
    if removed:
        audit.append(
            action_class="credential",
            decision="allow",
            line=f"agent:{strategy} key deleted by={user.id}",
        )
    return removed


def _read_cache(strategy: str) -> dict:
    with session_scope() as db:
        raw = _read_state(db, AGENT_CACHE_PREFIX + strategy)
    try:
        data = json.loads(raw or "{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _write_cache(strategy: str, models: list[dict]) -> dict:
    blob = {
        "fetched_at": datetime.now(UTC).isoformat(),
        "models": [{"id": m["id"], "price": m.get("price")} for m in models],
    }
    with session_scope() as db:
        _write_state(db, AGENT_CACHE_PREFIX + strategy, json.dumps(blob))
    return blob


def _cached_models(blob: dict) -> list[dict]:
    models = blob.get("models") if isinstance(blob, dict) else None
    if not isinstance(models, list):
        return []
    return [m for m in models if isinstance(m, dict) and m.get("id")]


def _curated_models(strategy: str) -> list[dict] | None:
    """Curated native list, or None when the strategy is not a native."""
    if strategy == "google":
        ids: tuple[str, ...] = CURATED_GOOGLE_MODELS
    elif strategy == "anthropic":
        ids = CURATED_ANTHROPIC_MODELS
    elif strategy == "deepseek":
        ids = CURATED_DEEPSEEK_MODELS
    else:
        return None
    return [{"id": mid, "price": NATIVE_PRICES.get(mid)} for mid in ids]


def _cache_answer(cached: dict) -> dict:
    models = _cached_models(cached)
    return {
        "models": models,
        "source": "cache" if models else "none",
        "fetched_at": cached.get("fetched_at", ""),
    }


def list_models(strategy: str, *, base_url: str = "", refresh: bool = True) -> dict:
    """Model options for a strategy: live list, else cached, else curated.

    Returns {"models": [{id, price}], "source": live|cache|curated|none,
    "fetched_at": iso|""}. Live-fetch failures never raise here — the UI
    falls back to the last cached list, then curated, then free text, and
    saving an id the cache hasn't seen is always allowed. Pass
    refresh=False for a render-blocking read (the Settings page shells
    live refresh out to the /agent/models endpoint so a slow provider
    never stalls the page).
    """
    strategy = (strategy or "").strip()
    entry = STRATEGIES.get(strategy)
    cached = _read_cache(strategy)
    curated = _curated_models(strategy) if entry is not None else None
    if curated is not None and not (strategy == "anthropic" and refresh):
        return {"models": curated, "source": "curated", "fetched_at": ""}
    if entry is None or not refresh or strategy == "custom":
        return _cache_answer(cached)
    base = (base_url or "").strip() or entry.default_base_url
    try:
        if strategy == "openrouter":
            models = fetch_openrouter_models()
        elif strategy == "vercel":
            models = fetch_openai_list_models(base)
        elif strategy == "ollama":
            models = fetch_ollama_models(base)
        elif strategy == "anthropic":
            models = fetch_anthropic_models(get_agent_key("anthropic") or "")
        else:  # custom: free text, plus whatever a previous fetch cached
            return _cache_answer(cached)
    except AgentError as exc:
        log.warning("agent model list for %s fell back to cache: %s", strategy, exc)
        if curated is not None:
            cached_answer = _cache_answer(cached)
            if cached_answer["source"] == "cache":
                return cached_answer
            return {"models": curated, "source": "curated", "fetched_at": ""}
        return _cache_answer(cached)
    blob = _write_cache(strategy, models)
    return {"models": blob["models"], "source": "live", "fetched_at": blob["fetched_at"]}


def current_model_price() -> float | None:
    """Resolved $/MTok for the configured model, else None.

    Order: cached gateway pricing → native table → operator override →
    $0 for custom/Ollama → None (unconfigured/unknown). None means the
    ledger falls back to the default price, never $0 by accident.
    """
    cfg = get_agent_config()
    strategy, model = cfg["strategy"], cfg["model"]
    if not strategy or not model:
        return None
    for cached in _cached_models(_read_cache(strategy)):
        if cached.get("id") == model and cached.get("price") is not None:
            try:
                price = float(cached["price"])
            except (TypeError, ValueError):
                break
            if price >= 0:
                return price
            break
    if model in NATIVE_PRICES:
        return NATIVE_PRICES[model]
    if cfg["price_override"] is not None:
        return cfg["price_override"]
    if strategy in ("custom", "ollama"):
        return 0.0
    return None


def price_per_token_usd() -> float:
    """Ledger price per token: resolved model price, else the default."""
    resolved = current_model_price()
    if resolved is None:
        resolved = DEFAULT_PRICE_PER_MTOK_USD
    return max(0.0, resolved) / 1_000_000


def agent_status() -> dict:
    """Dashboard/Settings agent indicator. Never raises, never leaks keys."""
    try:
        cfg = get_agent_config()
    except Exception as exc:  # noqa: BLE001 - status must never break a page
        log.warning("agent status unavailable: %s", exc)
        return {"configured": False, "strategy": "", "model": "", "error": str(exc)}
    strategy = cfg["strategy"]
    entry = STRATEGIES.get(strategy)
    try:
        price = current_model_price()
    except Exception:  # noqa: BLE001 - price must never break a page
        price = None
    return {
        "configured": bool(cfg["configured"]),
        "strategy": strategy,
        "label": strategy_label(strategy),
        "model": cfg["model"],
        "base_url": cfg["base_url"],
        "needs_key": bool(entry and entry.needs_key),
        "has_key": bool(cfg["has_key"]),
        "key_hint": cfg["key_hint"],
        "price_per_mtok_usd": price,
        "price_override": cfg["price_override"],
    }
