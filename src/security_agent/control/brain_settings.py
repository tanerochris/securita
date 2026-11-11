"""Settings-backed brain provider selection + org keys (brain strategy plan).

Selection (strategy/model/base_url/price override) lives in NotifyState
(plaintext-safe fields only); keys live in EncryptedToken under
`brain:<strategy>`, pasted once and never re-viewed — the same pattern
as git PATs and notify secrets. One key per configured provider,
Owner-managed; scans, workers, and chat all use it.

Saves store as-is (D5): no probe on save. A missing or broken provider
surfaces as a loud BrainError when AI work runs, and runs park.
"""

import json
import logging
import os
from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from security_agent.audit import get_shared_log
from security_agent.brain.providers import (
    CURATED_ANTHROPIC_MODELS,
    CURATED_GOOGLE_MODELS,
    DEFAULT_PRICE_PER_MTOK_USD,
    NATIVE_PRICES,
    STRATEGIES,
    BrainError,
    fetch_ollama_models,
    fetch_openai_list_models,
    fetch_openrouter_models,
    strategy_label,
)
from security_agent.crypto import decrypt_field, encrypt_field
from security_agent.db.keys import get_encryption_key
from security_agent.db.models import EncryptedToken, NotifyState, Role, User
from security_agent.db.session import session_scope

log = logging.getLogger(__name__)
audit = get_shared_log()

BRAIN_STRATEGY_KEY = "brain.strategy"
BRAIN_MODEL_KEY = "brain.model"
BRAIN_BASE_URL_KEY = "brain.base_url"
BRAIN_PRICE_OVERRIDE_KEY = "brain.price_override_usd"
BRAIN_MIGRATED_KEY = "brain.migrated"
BRAIN_CACHE_PREFIX = "brain.cache."  # + strategy: live list + prices + fetched_at

_KEY_OWNER = "brain:{}"  # noqa: S105 - owner label, not a credential

#: Pre-Settings default base URL, used only by the one-time env import
#: when an old install set a key/model without an explicit base URL.
_LEGACY_DEFAULT_BASE_URL = "https://api.meta.ai/v1"


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


def _store_secret(owner: str, plaintext: str) -> bool:
    """Store/rotate one brain key. True when a row already held a key."""
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


def get_brain_key(strategy: str) -> str | None:
    """Decrypted org key for a strategy (decrypts audit-logged, never re-viewed)."""
    with session_scope() as db:
        row = db.scalar(
            select(EncryptedToken).where(EncryptedToken.owner == _KEY_OWNER.format(strategy))
        )
        if row is None:
            return None
        return decrypt_field(row.ciphertext, get_encryption_key(), purpose=f"brain:{strategy}")


def has_brain_key(strategy: str) -> bool:
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
        raise PermissionError("Only an Owner may change the brain provider.")


def get_brain_config(*, migrate: bool = True) -> dict:
    """Current brain selection. Runs the one-time env import first, so the
    migration always lands before any worker serves AI work. Pass
    migrate=False for side-effect-free reads (doctor preflight)."""
    if migrate:
        maybe_migrate_env()
    with session_scope() as db:
        strategy = _read_state(db, BRAIN_STRATEGY_KEY).strip()
        model = _read_state(db, BRAIN_MODEL_KEY).strip()
        base_url = _read_state(db, BRAIN_BASE_URL_KEY).strip()
        override_raw = _read_state(db, BRAIN_PRICE_OVERRIDE_KEY).strip()
    return {
        "strategy": strategy,
        "model": model,
        "base_url": base_url,
        "price_override": _parse_override(override_raw),
        "price_override_raw": override_raw,
        "has_key": bool(strategy) and has_brain_key(strategy),
        "configured": bool(strategy and model),
    }


def save_brain_config(
    *,
    strategy: str,
    model: str,
    base_url: str = "",
    price_override: str = "",
    api_key: str = "",
    user: User,
) -> dict:
    """Owner-only brain save. Stores as-is (D5): no probe, no validation
    beyond Owner — a bad save surfaces as a loud runtime brain error."""
    _require_owner(user)
    strategy = (strategy or "").strip()
    model = (model or "").strip()
    base_url = (base_url or "").strip()
    price_override = (price_override or "").strip()
    with session_scope() as db:
        _write_state(db, BRAIN_STRATEGY_KEY, strategy)
        _write_state(db, BRAIN_MODEL_KEY, model)
        _write_state(db, BRAIN_BASE_URL_KEY, base_url)
        _write_state(db, BRAIN_PRICE_OVERRIDE_KEY, price_override)
    audit.append(
        action_class="brain",
        decision="save",
        line=f"strategy={strategy or '—'} model={model or '—'} by={user.id}",
    )
    if (api_key or "").strip():
        rotated = _store_secret(_KEY_OWNER.format(strategy or "custom"), api_key.strip())
        audit.append(
            action_class="credential",
            decision="allow",
            line=f"brain:{strategy or 'custom'} key {'rotated' if rotated else 'stored'} "
            f"by={user.id}",
        )
    return get_brain_config()


def delete_brain_key(strategy: str, user: User) -> bool:
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
    if removed:
        audit.append(
            action_class="credential",
            decision="allow",
            line=f"brain:{strategy} key deleted by={user.id}",
        )
    return removed


def _read_cache(strategy: str) -> dict:
    with session_scope() as db:
        raw = _read_state(db, BRAIN_CACHE_PREFIX + strategy)
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
        _write_state(db, BRAIN_CACHE_PREFIX + strategy, json.dumps(blob))
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
    falls back to the last cached list plus free text, and saving an id
    the cache hasn't seen is always allowed. Pass refresh=False for a
    render-blocking read (the Settings page shells live refresh out to
    the /brain/models endpoint so a slow provider never stalls the page).
    """
    strategy = (strategy or "").strip()
    entry = STRATEGIES.get(strategy)
    cached = _read_cache(strategy)
    curated = _curated_models(strategy) if entry is not None else None
    if curated is not None:
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
        else:  # custom: free text, plus whatever a previous fetch cached
            return _cache_answer(cached)
    except BrainError as exc:
        log.warning("brain model list for %s fell back to cache: %s", strategy, exc)
        return _cache_answer(cached)
    blob = _write_cache(strategy, models)
    return {"models": blob["models"], "source": "live", "fetched_at": blob["fetched_at"]}


def current_model_price() -> float | None:
    """Resolved $/MTok for the configured model, else None.

    Order: cached gateway pricing → native table → operator override →
    $0 for custom/Ollama → None (unconfigured/unknown). None means the
    ledger falls back to the default price, never $0 by accident.
    """
    cfg = get_brain_config()
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


def brain_status(*, migrate: bool = True) -> dict:
    """Dashboard/Settings brain indicator. Never raises, never leaks keys."""
    try:
        cfg = get_brain_config(migrate=migrate)
    except Exception as exc:  # noqa: BLE001 - status must never break a page
        log.warning("brain status unavailable: %s", exc)
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
        "price_per_mtok_usd": price,
        "price_override": cfg["price_override"],
    }


def _guess_strategy(base_url: str) -> str:
    host = (base_url or "").lower()
    if "openrouter.ai" in host:
        return "openrouter"
    if "vercel.sh" in host or "ai-gateway" in host:
        return "vercel"
    if "localhost:11434" in host or "127.0.0.1:11434" in host:
        return "ollama"
    if "googleapis.com" in host:
        return "google"
    if "api.anthropic.com" in host:
        return "anthropic"
    return "custom"


def maybe_migrate_env() -> dict:
    """One-time upgrade import of legacy MODEL_* env into Settings.

    Idempotent via the brain.migrated marker: after the first run the
    env is ignored. Only explicitly-set env vars import (never config
    defaults). Returns what it did, without key material.
    """
    with session_scope() as db:
        if _read_state(db, BRAIN_MIGRATED_KEY):
            return {"migrated": False}
    env_base = os.environ.get("MODEL_BASE_URL", "").strip()
    env_key = os.environ.get("MODEL_API_KEY", "").strip()
    env_model = os.environ.get("MODEL_NAME", "").strip()
    env_chat = os.environ.get("MODEL_CHAT_NAME", "").strip()
    env_price = os.environ.get("MODEL_PRICE_PER_MTOK_USD", "").strip()
    notes = []
    if env_chat:
        notes.append("MODEL_CHAT_NAME has no Settings equivalent and was not imported.")
    with session_scope() as db:
        _write_state(db, BRAIN_MIGRATED_KEY, datetime.now(UTC).isoformat())
        if not (env_base or env_key or env_model or env_price):
            return {"migrated": False, "notes": notes}
        strategy = _guess_strategy(env_base)
        base = env_base or _LEGACY_DEFAULT_BASE_URL
        _write_state(db, BRAIN_STRATEGY_KEY, strategy)
        if env_model:
            _write_state(db, BRAIN_MODEL_KEY, env_model)
        if strategy in ("custom", "ollama"):
            _write_state(db, BRAIN_BASE_URL_KEY, base)
        if "MODEL_PRICE_PER_MTOK_USD" in os.environ and _parse_override(env_price) is not None:
            _write_state(db, BRAIN_PRICE_OVERRIDE_KEY, env_price)
    if env_key:
        _store_secret(_KEY_OWNER.format(strategy), env_key)
    audit.append(
        action_class="brain",
        decision="migrate",
        line=f"strategy={strategy} model={env_model or '—'} from legacy MODEL_* env",
    )
    return {"migrated": True, "strategy": strategy, "model": env_model, "notes": notes}
