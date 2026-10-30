"""H6 #16: generated master keys never touch the log stream."""

import logging
import os
import stat


def test_generated_key_goes_to_0600_file_not_logs(tmp_path, monkeypatch, caplog):
    import security_agent.db.keys as keys_mod
    from security_agent.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "master_key", "")
    monkeypatch.setattr(settings, "master_key_file", str(tmp_path / "master.key"))
    monkeypatch.setattr(keys_mod, "_generated", None)
    # No operator console in CI: /dev/tty fails, file fallback engages.
    real_open = open

    def fake_open(path, *args, **kwargs):
        if str(path) == "/dev/tty":
            raise OSError("no tty")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open)
    try:
        with caplog.at_level(logging.WARNING, logger="security_agent.db.keys"):
            key, generated = keys_mod.ensure_master_key()
        assert generated is True and len(key) > 40
        target = tmp_path / "master.key"
        assert key in target.read_text()
        assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
        assert key not in caplog.text  # the #16 disclosure, closed
        # Second call reuses the in-process key without re-emitting.
        assert keys_mod.ensure_master_key() == (key, True)
    finally:
        monkeypatch.setattr(keys_mod, "_generated", None)


def test_configured_key_never_emits(tmp_path, monkeypatch):
    import security_agent.db.keys as keys_mod
    from security_agent.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "master_key", "configured-key")
    monkeypatch.setattr(keys_mod, "_generated", None)
    try:
        assert keys_mod.ensure_master_key() == ("configured-key", False)
        assert not (tmp_path / "master.key").exists()
    finally:
        monkeypatch.setattr(keys_mod, "_generated", None)
