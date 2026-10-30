import base64
import os

from security_agent.crypto import decrypt_field, encrypt_field


def _key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def test_encrypt_roundtrip():
    k = _key()
    token = encrypt_field("s3cr3t-value", k)
    assert token != "s3cr3t-value"
    assert decrypt_field(token, k) == "s3cr3t-value"
