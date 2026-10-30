"""Regression tests for medium-high audit patches (subkeys, SSO, tools, health)."""

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

import pytest
from cryptography.exceptions import InvalidTag

from security_agent.app import accounts as svc
from security_agent.audit import InMemoryLogStore
from security_agent.crypto import decrypt_field, derive_subkey, encrypt_field
from security_agent.db.keys import ensure_master_key, get_encryption_key, get_signing_key
from security_agent.db.models import Role
from security_agent.sandbox import tools


def _email(tag: str) -> str:
    return f"{tag}-{datetime.now(UTC).timestamp()}-{os.getpid()}@example.com"


def test_subkeys_independent_and_deterministic():
    master, _ = ensure_master_key()
    enc1 = derive_subkey(master, b"field-encryption-v1")
    enc2 = get_encryption_key()
    sign = get_signing_key()
    assert enc1 == enc2
    assert enc1 != master
    assert sign != master
    assert sign != enc1
    assert derive_subkey(master, b"session-signing-v1") == sign


def test_totp_uses_subkey_with_master_fallback():
    user = svc.create_user(_email("subkey"), None, Role.DEVELOPER)
    _url, _codes = svc.setup_totp(user.id)
    stored = svc.get_user_by_email(user.email)
    assert stored is not None and stored.totp_secret is not None
    # New rows decrypt with the encryption subkey, not the master directly.
    assert decrypt_field(stored.totp_secret, get_encryption_key())
    master, _ = ensure_master_key()
    with pytest.raises(InvalidTag):
        decrypt_field(stored.totp_secret, master)
    # Pre-subkey rows (master-encrypted) still verify via fallback.
    legacy = encrypt_field("JBSWY3DPEHPK3PXP", master)
    assert svc._decrypt_totp_secret(legacy) == "JBSWY3DPEHPK3PXP"


def test_sso_provider_mismatch_rejected():
    email = _email("ssoprov")
    svc.create_user(email, None, Role.DEVELOPER)
    svc.resolve_sso_user(email, "sub-same", "google")
    with pytest.raises(PermissionError, match="mismatch"):
        svc.resolve_sso_user(email, "sub-same", "microsoft")
    # Same provider + sub still accepted.
    user = svc.resolve_sso_user(email, "sub-same", "google")
    assert user.email == email


def test_audit_hourly_purge_triggers_on_append():
    store = InMemoryLogStore()
    store.append(action_class="gate", decision="deny", line="old")
    store._rows[0]["ts"] = (datetime.now(UTC) - timedelta(days=400)).isoformat()
    store._last_purge = datetime.now(UTC) - timedelta(hours=2)
    store.append(action_class="gate", decision="allow", line="new")
    assert len(store.query()) == 1
    assert store.query()[0]["line"] == "new"


def test_audit_store_capped_and_shared():
    from security_agent.audit import get_shared_log
    from security_agent.control import gates, repos

    store = InMemoryLogStore(capacity=3)
    for i in range(5):
        store.append(action_class="tool", decision="allow", line=f"cmd-{i}")
    assert [r["line"] for r in store.query()] == ["cmd-2", "cmd-3", "cmd-4"]
    assert tools.audit is get_shared_log()
    assert gates.audit is get_shared_log()
    assert repos.audit is get_shared_log()


def test_breach_failopen_backs_off():
    svc._breach_cache.clear()
    svc._breach_fail_at.clear()
    with mock.patch.object(svc.httpx, "get", side_effect=TimeoutError("timed out")) as fake_get:
        assert svc.is_breached("unique-backoff-password-12") is False
        assert fake_get.call_count == 1
        # Second call with a different password but same prefix path still
        # fails open; same-prefix retries skip the network during backoff.
        assert svc.is_breached("unique-backoff-password-12") is False
        # Same digest path would hit fail_at only if same prefix; force same
        # password to prove no second network hit via cache miss + backoff.
        assert fake_get.call_count == 1


def test_tool_concurrency_cap_fails_loud():
    # Drain the semaphore so the next run queues out immediately.
    acquired = []
    try:
        for _ in range(tools.MAX_CONCURRENT_TOOLS):
            assert tools._tools_sem.acquire(blocking=False)
            acquired.append(True)
        with pytest.raises(TimeoutError, match="slots are full"):
            tools.run_allowlisted("ripgrep", ["x", "."], timeout=1)
    finally:
        for _ in acquired:
            tools._tools_sem.release()


def test_tool_output_capped():
    big = "y" * (tools.MAX_OUTPUT_CHARS + 100)

    def fake(_argv, **kwargs):
        kwargs["stdout"].write(big.encode())
        return mock.Mock(returncode=0)

    with mock.patch.object(tools.subprocess, "run", side_effect=fake):
        out = tools.run_allowlisted("ripgrep", ["y", "."], timeout=5)
    assert len(out) == tools.MAX_OUTPUT_CHARS


def test_health_reports_db_down():
    from fastapi.testclient import TestClient

    from security_agent.app.main import app

    client = TestClient(app, raise_server_exceptions=False)
    assert client.get("/health").status_code == 200
    with mock.patch("security_agent.db.session.get_engine", side_effect=RuntimeError("db down")):
        r = client.get("/health")
        assert r.status_code == 503
        assert r.json()["db"] == "down"


def test_dockerfile_stays_editable():
    dockerfile = Path("Dockerfile").read_text()
    assert "--no-editable" not in dockerfile
    assert "--editable" in dockerfile
    assert "PYTHONPATH=/app/src" in dockerfile
