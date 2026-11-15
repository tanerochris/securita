"""Embedding providers for policy RAG (D4): operator's choice via env.

- "local" (default): a small ONNX model in-process (fastembed). No
  extra service; the model downloads once into EMBEDDING_LOCAL_CACHE_DIR.
- "ollama": an Ollama server's OpenAI-compatible /v1/embeddings
  (compose profile "ollama", or EMBEDDING_BASE_URL at your own server).
- "hosted": any OpenAI-compatible embeddings API.
- "off": keyword retrieval only.

One seam, `embed_texts`. Vectors are optional everywhere: any failure
returns None and retrieval falls back to keyword matching, so policy
features never hard-fail for lack of embeddings. Providers narrower
than the pinned column width zero-pad — cosine similarity is invariant
when both sides pad identically, and every vector passes through here.
"""

import logging

from security_agent.config import get_settings

log = logging.getLogger(__name__)

_PROVIDER_MODEL_DEFAULTS = {
    "local": "BAAI/bge-small-en-v1.5",
    "ollama": "nomic-embed-text",
    "hosted": "text-embedding-3-small",
}
_OLLAMA_DEFAULT_BASE = "http://embed:11434/v1"

_local_model = None
_local_model_key: tuple[str, str] | None = None


def _provider() -> str:
    provider = (get_settings().embedding_provider or "local").strip().lower()
    return provider if provider in (*_PROVIDER_MODEL_DEFAULTS, "off") else "hosted"


def _model_name(provider: str) -> str:
    return get_settings().embedding_model or _PROVIDER_MODEL_DEFAULTS[provider]


def _validated(raw: list, count: int, *, model: str) -> list[list[float]] | None:
    """Width/type-check + zero-pad raw vectors; None when unusable."""
    from security_agent.db.models import POLICY_EMBEDDING_DIM

    if len(raw) != count:
        log.warning("embeddings count mismatch: %d for %d inputs", len(raw), count)
        return None
    vectors: list[list[float]] = []
    for vec in raw:
        if (
            not isinstance(vec, list)
            or not 1 <= len(vec) <= POLICY_EMBEDDING_DIM
            or not all(isinstance(x, (int, float)) for x in vec)
        ):
            log.warning("embeddings response failed validation (model=%s)", model)
            return None
        vectors.append([float(x) for x in vec] + [0.0] * (POLICY_EMBEDDING_DIM - len(vec)))
    return vectors


def _embed_local(texts: list[str]) -> list[list[float]] | None:
    """In-process ONNX embeddings; model loads lazily, once per process."""
    global _local_model, _local_model_key
    from security_agent.db.models import POLICY_EMBEDDING_DIM

    s = get_settings()
    model_name = _model_name("local")
    key = (model_name, s.embedding_local_cache_dir or "")
    try:
        if _local_model is None or _local_model_key != key:
            from fastembed import TextEmbedding

            kwargs: dict = {"model_name": model_name}
            if key[1]:
                kwargs["cache_dir"] = key[1]
            _local_model = TextEmbedding(**kwargs)
            _local_model_key = key
        raw = [[float(x) for x in vec] for vec in _local_model.embed(texts)]
    except Exception as exc:  # noqa: BLE001 - embeddings optional; keyword covers
        log.warning("local embeddings unavailable (%s); using keyword fallback", exc)
        return None
    if len(raw) != len(texts):
        log.warning("local embeddings count mismatch: %d for %d", len(raw), len(texts))
        return None
    out: list[list[float]] = []
    for vec in raw:
        if not 1 <= len(vec) <= POLICY_EMBEDDING_DIM:
            log.warning("local embedding width %d unsupported", len(vec))
            return None
        out.append(vec + [0.0] * (POLICY_EMBEDDING_DIM - len(vec)))
    return out


def _embed_http(texts: list[str], provider: str) -> list[list[float]] | None:
    """OpenAI-compatible /embeddings POST (hosted APIs and Ollama)."""
    s = get_settings()
    if provider == "ollama":
        base = (s.embedding_base_url or _OLLAMA_DEFAULT_BASE).rstrip("/")
        key = s.embedding_api_key or "ollama"
    else:
        base = (s.embedding_base_url or "").rstrip("/")
        key = s.embedding_api_key or ""
    if not base:
        return None
    model = _model_name(provider)
    import httpx

    resp = httpx.post(
        f"{base}/embeddings",
        headers={"Authorization": f"Bearer {key}"},
        json={"model": model, "input": texts},
        timeout=s.embedding_timeout_seconds,
    )
    resp.raise_for_status()
    data = resp.json().get("data", [])
    raw = [(row or {}).get("embedding") for row in data]
    return _validated(raw, len(texts), model=model)


def embed_texts(texts: list[str], *, task: str = "policy-embed") -> list[list[float]] | None:
    """Embed a batch of chunk texts; None when unavailable."""
    # Cost lookups stay call-time: tests stub record_usage at its source.
    from security_agent.control.cost import current_run_id, record_usage

    cleaned = [(t or "")[:8000] for t in texts]
    if not cleaned:
        return []
    provider = _provider()
    try:
        if provider == "off":
            return None
        vectors = _embed_local(cleaned) if provider == "local" else _embed_http(cleaned, provider)
    except Exception as exc:  # noqa: BLE001 - embeddings are optional; keyword covers
        log.warning("embeddings unavailable (%s); using keyword fallback", type(exc).__name__)
        return None
    if vectors is None:
        return None
    try:
        record_usage(
            current_run_id(),
            task,
            sum(max(1, len(t) // 4) for t in cleaned),
            0,
            estimated=True,
        )
    except Exception as exc:  # noqa: BLE001 - ledger never breaks embeddings
        log.warning("embedding usage ledger failed: %s", exc)
    return vectors
