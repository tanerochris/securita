"""Embedding client: hosted shape validated, every failure degrades to None."""

from types import SimpleNamespace
from unittest import mock

from security_agent.brain import embeddings as emb_mod
from security_agent.db.models import POLICY_EMBEDDING_DIM


def _settings(**overrides):
    base = {
        "embedding_provider": "hosted",
        "embedding_base_url": "https://embed.example.com/v1",
        "embedding_api_key": "k",
        "embedding_model": "emb-test",
        "embedding_timeout_seconds": 5.0,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _resp(payload):
    response = mock.Mock()
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


def test_off_provider_returns_none():
    with mock.patch.object(
        emb_mod, "get_settings", return_value=_settings(embedding_provider="off")
    ):
        with mock.patch("httpx.post") as post:
            assert emb_mod.embed_texts(["hello"]) is None
            post.assert_not_called()


def test_success_returns_validated_vectors():
    vec = [0.5] * POLICY_EMBEDDING_DIM
    with (
        mock.patch.object(emb_mod, "get_settings", return_value=_settings()),
        mock.patch("httpx.post", return_value=_resp({"data": [{"embedding": vec}]})),
        mock.patch("security_agent.control.cost.record_usage") as ledger,
    ):
        out = emb_mod.embed_texts(["hello"])
    assert out == [vec]
    ledger.assert_called_once()


def test_narrow_vectors_zero_pad_to_column_width():
    """Providers narrower than the pinned column width pad with zeros."""
    narrow = [0.25] * 384
    with (
        mock.patch.object(emb_mod, "get_settings", return_value=_settings()),
        mock.patch("httpx.post", return_value=_resp({"data": [{"embedding": narrow}]})),
        mock.patch("security_agent.control.cost.record_usage"),
    ):
        out = emb_mod.embed_texts(["hello"])
    assert out is not None and len(out[0]) == POLICY_EMBEDDING_DIM
    assert out[0][:384] == narrow
    assert out[0][384:] == [0.0] * (POLICY_EMBEDDING_DIM - 384)


def test_oversize_vectors_degrade_to_none():
    with (
        mock.patch.object(emb_mod, "get_settings", return_value=_settings()),
        mock.patch(
            "httpx.post",
            return_value=_resp({"data": [{"embedding": [0.1] * (POLICY_EMBEDDING_DIM + 1)}]}),
        ),
    ):
        assert emb_mod.embed_texts(["hello"]) is None


def test_malformed_vectors_degrade_to_none():
    with (
        mock.patch.object(emb_mod, "get_settings", return_value=_settings()),
        mock.patch("httpx.post", return_value=_resp({"data": [{"embedding": ["x", "y"]}]})),
    ):
        assert emb_mod.embed_texts(["hello"]) is None


def test_http_failure_degrades_to_none():
    with (
        mock.patch.object(emb_mod, "get_settings", return_value=_settings()),
        mock.patch("httpx.post", side_effect=RuntimeError("down")),
    ):
        assert emb_mod.embed_texts(["hello"]) is None


def test_provider_resolution_and_model_defaults():
    import security_agent.config as config_mod

    # Field default (the live value is env-driven; tests pin it to off).
    assert config_mod.Settings.model_fields["embedding_provider"].default == "local"
    settings = _settings(embedding_model="")
    with mock.patch.object(emb_mod, "get_settings", return_value=settings):
        assert emb_mod._model_name("local") == "BAAI/bge-small-en-v1.5"
        assert emb_mod._model_name("ollama") == "nomic-embed-text"
        assert emb_mod._model_name("hosted") == "text-embedding-3-small"


def test_local_provider_uses_fastembed_and_pads():
    import sys
    import types

    fake = types.ModuleType("fastembed")
    calls: list = []

    class _FakeEmbedding:
        def __init__(self, **kwargs):
            calls.append(kwargs)

        def embed(self, texts):
            return [[0.5] * 384 for _ in texts]

    fake.TextEmbedding = _FakeEmbedding  # type: ignore[attr-defined]
    settings = _settings(
        embedding_provider="local",
        embedding_model="",
        embedding_local_cache_dir="/tmp/fake-cache",
    )
    with (
        mock.patch.object(emb_mod, "get_settings", return_value=settings),
        mock.patch.dict(sys.modules, {"fastembed": fake}),
        mock.patch.object(emb_mod, "_local_model", None),
        mock.patch.object(emb_mod, "_local_model_key", None),
        mock.patch("security_agent.control.cost.record_usage"),
    ):
        out = emb_mod.embed_texts(["hello", "world"])
    assert out is not None and len(out) == 2
    assert len(out[0]) == POLICY_EMBEDDING_DIM and out[0][384] == 0.0
    assert calls and calls[0]["model_name"] == "BAAI/bge-small-en-v1.5"
    assert calls[0]["cache_dir"] == "/tmp/fake-cache"


def test_ollama_provider_posts_to_ollama_base():
    settings = _settings(embedding_provider="ollama", embedding_base_url="", embedding_model="")
    vec = [0.5] * 768
    with (
        mock.patch.object(emb_mod, "get_settings", return_value=settings),
        mock.patch("httpx.post", return_value=_resp({"data": [{"embedding": vec}]})) as post,
        mock.patch("security_agent.control.cost.record_usage"),
    ):
        out = emb_mod.embed_texts(["hello"])
    assert out is not None and len(out[0]) == POLICY_EMBEDDING_DIM
    url = post.call_args.args[0]
    assert url == "http://embed:11434/v1/embeddings"
    assert post.call_args.kwargs["json"]["model"] == "nomic-embed-text"


def test_missing_credentials_degrades_to_none():
    settings = _settings(embedding_base_url="", embedding_api_key="")
    with mock.patch.object(emb_mod, "get_settings", return_value=settings):
        with mock.patch("httpx.post") as post:
            assert emb_mod.embed_texts(["hello"]) is None
            post.assert_not_called()
