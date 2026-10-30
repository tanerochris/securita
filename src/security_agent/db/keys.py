"""Master-key ceremony (NFR-9 D2): app-generated, shown once, operator-held.

If MASTER_KEY is configured, it is used as-is. Otherwise the app generates a
per-install key on first boot and emits it exactly once for the operator to
store outside the install. Loss means encrypted fields are unrecoverable and
tokens must be re-entered. The generated key is never persisted by the app.

The key NEVER touches the logging stream (H6 #16): log capture would
disclose it. It goes to the operator console (/dev/tty) when one is
attached, else to a 0600 file at MASTER_KEY_FILE for the operator to
move outside the install.
"""

import base64
import logging
import os
import threading
from pathlib import Path

log = logging.getLogger(__name__)

_ENCRYPTION_INFO = b"field-encryption-v1"
_SIGNING_INFO = b"session-signing-v1"

_generated: str | None = None
_lock = threading.Lock()


def _emit_generated_key(key: str) -> str:
    """Deliver a fresh key to the operator; returns where it went."""
    from security_agent.config import get_settings

    banner = (
        "*** MASTER KEY (shown once — store outside this install) ***\n"
        f"{key}\n"
        "*** Loss means encrypted fields are unrecoverable. ***\n"
    )
    try:
        with open("/dev/tty", "w") as tty:
            tty.write(banner)
    except OSError:
        pass
    else:
        log.warning("master key shown once on the operator console; it is not logged.")
        return "tty"
    target = Path(get_settings().master_key_file or "./master.key")
    try:
        fd = os.open(
            str(target),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
    except FileExistsError:
        try:
            fd = os.open(str(target), os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
        except OSError as exc:
            raise OSError(f"refusing to write master key to {target}: {exc}") from exc
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, banner.encode())
        finally:
            os.close(fd)
    except OSError as exc:
        raise OSError(f"refusing to write master key to {target}: {exc}") from exc
    else:
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, banner.encode())
        finally:
            os.close(fd)
    log.warning(
        "no operator console: master key written once to %s (0600). "
        "Move it outside this install, then delete this copy.",
        target,
    )
    return str(target)


def ensure_master_key() -> tuple[str, bool]:
    """Return (key_b64, was_generated_this_boot)."""
    from security_agent.config import get_settings

    global _generated
    configured = get_settings().master_key
    if configured:
        return configured, False
    if _generated is None:
        with _lock:
            if _generated is None:
                fresh = base64.b64encode(os.urandom(32)).decode()
                _emit_generated_key(fresh)
                _generated = fresh
                return fresh, True
            return _generated, True
    return _generated, True


def get_encryption_key() -> str:
    """HKDF subkey for AES-GCM fields; independent from signing (never master)."""
    from security_agent.crypto import derive_subkey

    master, _ = ensure_master_key()
    return derive_subkey(master, _ENCRYPTION_INFO)


def get_signing_key() -> str:
    """HKDF subkey for session cookies + CSRF; independent from encryption."""
    from security_agent.crypto import derive_subkey

    master, _ = ensure_master_key()
    return derive_subkey(master, _SIGNING_INFO)
