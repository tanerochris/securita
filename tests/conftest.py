"""Test DB: throwaway SQLite file, tables created once per run."""

import contextlib
import os
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix="agent-test-")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["APP_ENV"] = "dev"
# G7: never inherit MODEL_ADAPT_ENABLED from the workspace .env in tests.
# pydantic-settings reads .env, but real env vars take precedence, so this
# default keeps select_adapt() on the null hook unless a test opts in.
os.environ.setdefault("MODEL_ADAPT_ENABLED", "false")
# Policy RAG: tests run keyword-only unless they stub embeddings.
# Real env vars take precedence over .env, so the suite never calls a
# live embeddings endpoint (hermetic, offline-safe).
os.environ.setdefault("EMBEDDING_PROVIDER", "off")
# PR copy: tests keep the deterministic template unless they inject a
# fake model, so delivery tests never call a live chat endpoint.
os.environ.setdefault("PR_TEXT_MODEL_ENABLED", "false")
# Bot identity: delivery tests assert the committed default identity;
# a customized BOT_NAME/BOT_EMAIL in the workspace .env must not leak in.
os.environ.setdefault("BOT_NAME", "security-agent-bot")
os.environ.setdefault("BOT_EMAIL", "security-agent@localhost")

import security_agent.db.session as sess_mod  # noqa: E402
from security_agent.db.models import Base  # noqa: E402

Base.metadata.create_all(sess_mod.get_engine())


@pytest.fixture(autouse=True)
def _reset_adapt_probe_cache():
    """G7: the adapt probe verdict is cached process-wide; reset per test."""
    import security_agent.brain.adapt as adapt_mod

    adapt_mod._probe_cache = None
    yield
    adapt_mod._probe_cache = None


@contextlib.contextmanager
def mock_notify_http(*, post_side_effect=None):
    """Mock notify HTTP delivery: public-IP DNS + pinned httpx.Client.

    Mirrors the transports' resolve-then-pin path without touching the
    network: DNS resolves to a documentation public IP and the httpx
    client answers healthy (or raises `post_side_effect`). Yields the
    mocked client's `post` mock for call assertions.
    """
    from unittest import mock

    import security_agent.notify.transports as transports

    with (
        mock.patch.object(transports, "_resolve_notify_host_ips", return_value=["93.184.216.34"]),
        mock.patch.object(transports.httpx, "Client") as fake_client_cls,
    ):
        post = fake_client_cls.return_value.__enter__.return_value.post
        if post_side_effect is not None:
            post.side_effect = post_side_effect
        else:
            post.return_value.raise_for_status.return_value = None
        yield post
