"""AES-256-GCM field encryption under a per-install master key (NFR-4)."""

import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_NONCE_BYTES = 12
_SUBKEY_SALT = b"security-agent-v1"


def _decode_key(master_key_b64: str) -> bytes:
    key = base64.b64decode(master_key_b64)
    if len(key) != 32:
        raise ValueError("MASTER_KEY must decode to 32 bytes (AES-256).")
    return key


def derive_subkey(master_key_b64: str, info: bytes) -> str:
    """Derive an independent 32-byte subkey via HKDF-SHA256 (never reuse master)."""
    master = _decode_key(master_key_b64)
    sub = HKDF(algorithm=hashes.SHA256(), length=32, salt=_SUBKEY_SALT, info=info).derive(master)
    return base64.b64encode(sub).decode()


def encrypt_field(plaintext: str, master_key_b64: str) -> str:
    """Encrypt a secret field; returns base64(nonce || ciphertext). Never re-viewed."""
    if not master_key_b64:
        raise ValueError("MASTER_KEY is not configured.")
    key = _decode_key(master_key_b64)
    nonce = os.urandom(_NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_field(token: str, master_key_b64: str, *, purpose: str = "field") -> str:
    """Decrypt a field; every decrypt is audit-logged (NFR-4).

    The audit line carries the purpose label only — never ciphertext,
    plaintext, or key material.
    """
    if not master_key_b64:
        raise ValueError("MASTER_KEY is not configured.")
    key = _decode_key(master_key_b64)
    raw = base64.b64decode(token)
    nonce, ct = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
    plaintext = AESGCM(key).decrypt(nonce, ct, None).decode()
    from security_agent.audit import get_shared_log

    safe_purpose = "".join(c if c.isalnum() or c in "-_:" else "?" for c in purpose)[:100]
    get_shared_log().append(
        action_class="crypto", decision="decrypt", line=f"purpose={safe_purpose}"
    )
    return plaintext
