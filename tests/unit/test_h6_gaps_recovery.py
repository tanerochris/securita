"""H6 gaps recovery: K3/S3/S4/M2 proof."""

import json
import os
import sqlite3
import stat
import threading
from pathlib import Path

import pytest


def _no_tty(monkeypatch):
    real_open = open

    def fake_open(path, *args, **kwargs):
        if str(path) == "/dev/tty":
            raise OSError("no tty")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open)


def _seed_sqlite(path: Path) -> str:
    con = sqlite3.connect(str(path))
    try:
        con.execute("CREATE TABLE t(x TEXT)")
        con.execute("INSERT INTO t VALUES ('hi')")
        con.commit()
    finally:
        con.close()
    return f"sqlite:///{path}"


def test_threaded_ensure_master_key_emits_once(tmp_path, monkeypatch):
    import security_agent.db.keys as keys_mod
    from security_agent.config import get_settings

    _no_tty(monkeypatch)
    settings = get_settings()
    monkeypatch.setattr(settings, "master_key", "")
    target = tmp_path / "master.key"
    monkeypatch.setattr(settings, "master_key_file", str(target))
    keys_mod._generated = None
    original_emit = keys_mod._emit_generated_key
    calls: list = []
    calls_lock = threading.Lock()

    def counting(key: str) -> str:
        with calls_lock:
            calls.append(key)
        return original_emit(key)

    monkeypatch.setattr(keys_mod, "_emit_generated_key", counting)
    try:
        n = 10
        barrier = threading.Barrier(n)
        out: list = [None] * n

        def worker(i: int) -> None:
            barrier.wait(timeout=10)
            out[i] = keys_mod.ensure_master_key()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert not any(thread.is_alive() for thread in threads)
        keys = {key for key, _ in out}
        assert len(keys) == 1
        assert all(generated is True for _, generated in out)
        assert len(calls) == 1
        single = next(iter(keys))
        assert single == calls[0]
        assert single in target.read_text()
    finally:
        keys_mod._generated = None


def test_existing_0644_key_file_becomes_0600(tmp_path, monkeypatch):
    import security_agent.db.keys as keys_mod
    from security_agent.config import get_settings

    _no_tty(monkeypatch)
    settings = get_settings()
    monkeypatch.setattr(settings, "master_key", "")
    target = tmp_path / "master.key"
    target.write_text("stale")
    os.chmod(target, 0o644)
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644
    monkeypatch.setattr(settings, "master_key_file", str(target))
    keys_mod._generated = None
    try:
        key, generated = keys_mod.ensure_master_key()
        assert generated is True
        assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
        assert key in target.read_text()
    finally:
        keys_mod._generated = None


def test_symlink_key_path_refused(tmp_path, monkeypatch):
    import security_agent.db.keys as keys_mod
    from security_agent.config import get_settings

    _no_tty(monkeypatch)
    settings = get_settings()
    monkeypatch.setattr(settings, "master_key", "")
    real = tmp_path / "real.txt"
    real.write_text("sentinel")
    link = tmp_path / "master.key"
    link.symlink_to(real)
    monkeypatch.setattr(settings, "master_key_file", str(link))
    keys_mod._generated = None
    try:
        with pytest.raises(OSError) as excinfo:
            keys_mod.ensure_master_key()
        assert str(link) in str(excinfo.value)
        assert real.read_text() == "sentinel"
        assert keys_mod._generated is None
    finally:
        keys_mod._generated = None


def test_backup_artifacts_are_0600(tmp_path):
    from security_agent.ops.backup import backup

    src = tmp_path / "src.db"
    url = _seed_sqlite(src)
    dest = tmp_path / "backups"
    outcome = backup(dest_dir=str(dest), db_url=url)
    manifest_path = Path(outcome["manifest"])
    manifest = json.loads(manifest_path.read_text())
    for name in (manifest["db_file"], manifest["settings_file"], manifest_path.name):
        candidate = dest / name
        assert candidate.exists()
        assert stat.S_IMODE(os.stat(candidate).st_mode) == 0o600


def test_tampered_settings_snapshot_rejected(tmp_path):
    from security_agent.ops.backup import BackupError, backup, restore

    src = tmp_path / "src.db"
    url = _seed_sqlite(src)
    dest = tmp_path / "backups"
    outcome = backup(dest_dir=str(dest), db_url=url)
    manifest_path = Path(outcome["manifest"])
    manifest = json.loads(manifest_path.read_text())
    settings_path = dest / manifest["settings_file"]
    with open(settings_path, "a") as fh:
        fh.write("tampered")
    with pytest.raises(BackupError, match="settings"):
        restore(manifest_path, dest=tmp_path / "restored.db")
    settings_path.unlink()
    with pytest.raises(BackupError, match="settings"):
        restore(manifest_path, dest=tmp_path / "restored2.db")


def test_backup_twice_yields_two_manifests(tmp_path):
    from security_agent.ops.backup import backup

    src = tmp_path / "src.db"
    url = _seed_sqlite(src)
    dest = tmp_path / "backups"
    first = backup(dest_dir=str(dest), db_url=url)
    second = backup(dest_dir=str(dest), db_url=url)
    assert first["manifest"] != second["manifest"]
    assert len(list(dest.glob("*.manifest.json"))) == 2
