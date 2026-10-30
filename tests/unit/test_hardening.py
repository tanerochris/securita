import subprocess
import threading
from datetime import UTC, datetime, timedelta
from unittest import mock

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from security_agent.app import accounts as svc
from security_agent.app.dependencies import make_csrf, require_csrf
from security_agent.app.ratelimit import allow
from security_agent.audit import InMemoryLogStore
from security_agent.db.models import Role, User
from security_agent.db.session import session_scope
from security_agent.sandbox import tools


def _email(tag: str) -> str:
    return f"{tag}-{datetime.now(UTC).timestamp()}@example.com"


def test_totp_secret_encrypted_at_rest():
    user = svc.create_user(_email("totp"), None, Role.DEVELOPER)
    _url, codes = svc.setup_totp(user.id)
    assert len(codes) == 8
    with session_scope() as db:
        row = db.get(User, user.id)
        assert row is not None
        stored = row.totp_secret
    assert stored is not None and len(stored) > 20
    # Backup codes work end-to-end and are single-use.
    assert svc.verify_totp_or_backup(user, codes[0]) is True
    assert svc.verify_totp_or_backup(user, codes[0]) is False


def test_reset_single_use_and_revokes_sessions():
    email = _email("reset")
    user = svc.create_user(email, svc.hash_password("old-password-12"), Role.DEVELOPER)
    sid = svc.create_session(user.id)
    token = svc.issue_reset(email)
    assert token is not None
    assert svc.issue_reset("nobody@example.com") is None
    new_hash = svc.hash_password("new-password-12")
    assert svc.redeem_reset(token, new_hash) is True
    assert svc.redeem_reset(token, new_hash) is False
    assert svc.validate_session(sid) is None
    refreshed = svc.get_user_by_email(email)
    assert refreshed is not None
    assert svc.verify_password(refreshed.password_hash, "new-password-12")


def test_audit_store_purges_expired():
    store = InMemoryLogStore()
    store.append(action_class="gate", decision="deny", line="x")
    store._rows[0]["ts"] = (datetime.now(UTC) - timedelta(days=400)).isoformat()
    assert store.purge_expired() == 1
    assert store.query() == []


def test_tool_timeout_fails_loud():
    with (
        mock.patch.object(
            tools.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd=["osv-scanner"], timeout=1),
        ),
        pytest.raises(TimeoutError, match="timed out"),
    ):
        tools.run_allowlisted("osv-scanner", ["--lockfile", "x"], timeout=1)


def test_csrf_roundtrip():
    require_csrf(make_csrf())
    with pytest.raises(HTTPException):
        require_csrf("not-a-token")


def test_rate_limit_blocks_burst():
    ip, path = "10.0.0.9", "/login"
    results = [allow(ip, path, limit=3, window=60) for _ in range(4)]
    assert results == [True, True, True, False]


def test_rate_limit_bucket_map_is_bounded():
    """Rotating IPs cannot grow the bucket map without limit (H5 #29)."""
    from security_agent.app import ratelimit

    with ratelimit._buckets_lock:
        ratelimit._buckets.clear()
    for i in range(ratelimit._BUCKETS_MAX + 500):
        assert ratelimit.allow(f"10.9.{i // 250}.{i % 250}", "/login") is True
    with ratelimit._buckets_lock:
        assert len(ratelimit._buckets) <= ratelimit._BUCKETS_MAX
        ratelimit._buckets.clear()


def test_rate_limit_concurrent_allow_counts_exactly():
    """Concurrent bursts from one IP admit exactly `limit` (H5 #29)."""
    ip = f"10.8.0.{datetime.now(UTC).microsecond % 250}"
    results: list[bool] = []
    lock = threading.Lock()

    def hammer() -> None:
        for _ in range(10):
            ok = allow(ip, "/login", limit=5, window=60)
            with lock:
                results.append(ok)

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert results.count(True) == 5
    assert len(results) == 80


def test_audit_store_concurrent_append_and_purge():
    """Concurrent appends + purges lose nothing (H4 audit lock)."""
    store = InMemoryLogStore(retention=timedelta(days=36500), capacity=100000)

    def hammer(n: int) -> None:
        for i in range(200):
            store.append(action_class="t", decision="allow", line=f"{n}-{i}")
            if i % 10 == 0:
                store.purge_expired()

    threads = [threading.Thread(target=hammer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert len(store.query()) == 8 * 200


def test_dockerfile_pins_scanner_binaries():
    """Scanners ship pinned in the sandbox image only (H5 #28, follow-up #1)."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    text = (root / "Dockerfile.sandbox").read_text()
    assert "BETTERLEAKS_VERSION=v2.0.0-rc.1" in text  # v2 line: v1 breaks the adapter
    assert "OSV_SCANNER_VERSION=v2.7.0" in text
    assert "sha256sum -c" in text
    assert "BETTERLEAKS_VERSION" not in (root / "Dockerfile").read_text()


def test_kev_concurrent_fetch_single_call():
    """Concurrent KEV refreshes serialize on the lock (H4)."""
    from security_agent.worker import scan as scan_mod

    scan_mod._kev_cache = None
    resp = mock.Mock()
    resp.text = "cveID\nCVE-2026-1\n"
    barrier = threading.Barrier(4)

    def fetch() -> None:
        barrier.wait(timeout=10)
        scan_mod.kev_exploited_ids()

    try:
        with mock.patch.object(scan_mod.httpx, "get", return_value=resp) as fake_get:
            threads = [threading.Thread(target=fetch) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
            assert fake_get.call_count == 1
    finally:
        scan_mod._kev_cache = None


def test_tool_env_passthrough_and_audit_keys():
    """env merges over os.environ; only key names are audit-logged."""
    completed = mock.Mock(returncode=0, stdout="", stderr="")
    with mock.patch.object(tools.subprocess, "run", return_value=completed) as fake_run:
        tools.run_allowlisted("git", ["--version"], env={"PYTHONPATH": "/x", "A_B": "c"})
    _args, kwargs = fake_run.call_args
    assert kwargs["env"]["PYTHONPATH"] == "/x"
    assert kwargs["env"]["A_B"] == "c"
    assert "PATH" in kwargs["env"]
    lines = [r["line"] for r in tools.audit.query(action_class="tool")]
    assert lines and lines[-1].endswith("[env A_B,PYTHONPATH]")
    assert "/x" not in lines[-1]


def test_sso_link_then_mismatch_rejected():
    email = _email("sso")
    svc.create_user(email, None, Role.DEVELOPER)
    user = svc.resolve_sso_user(email, "sub-1", "google")
    assert user.email == email
    with session_scope() as db:
        row = db.scalar(select(User).where(User.email == email))
        assert row is not None and row.sso_subject == "sub-1"
    with pytest.raises(PermissionError, match="mismatch"):
        svc.resolve_sso_user(email, "sub-OTHER", "google")
