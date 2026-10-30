"""H6 gaps: notify SSRF pinning + SMTP TLS verification (transports).

No live network: DNS resolution and the HTTP client are mocked; the
pinned backend is proven to dial validated IPs instead of the hostname.
"""

import ssl
from unittest import mock

import pytest

from security_agent.notify.transports import (
    NotifyError,
    _PinnedNotifyBackend,
    _validated_notify_ips,
    send_email,
    send_slack,
    send_webhook,
    validate_email_config,
)

PUBLIC_IP = "93.184.216.34"  # documentation address; never dialed (client mocked)

REJECT_URLS = [
    "http://169.254.169.254/latest/meta-data",  # cloud metadata (link-local)
    "http://localhost:8000/admin",
    "http://127.0.0.1/x",
    "http://10.0.0.5/x",
    "http://192.168.1.1/x",
    "http://172.16.0.1/x",
    "http://[::1]/x",
    "http://0.0.0.0/x",
    "gopher://evil.example.com/x",
    "file:///etc/passwd",
]


def _email_config(**overrides):
    base = {
        "host": "smtp.example.com",
        "port": 587,
        "username": "agent",
        "from_addr": "agent@example.com",
        "to": ["ops@example.com"],
    }
    base.update(overrides)
    return base


@pytest.mark.parametrize("url", REJECT_URLS)
def test_validated_ips_rejects_non_public_targets(url):
    with mock.patch(
        "security_agent.notify.transports._resolve_notify_host_ips",
        return_value=["127.0.0.1"],
    ):
        with pytest.raises(NotifyError):
            _validated_notify_ips(url)


def test_validated_ips_rejects_mixed_public_private():
    with mock.patch(
        "security_agent.notify.transports._resolve_notify_host_ips",
        return_value=[PUBLIC_IP, "10.0.0.5"],
    ):
        with pytest.raises(NotifyError, match="non-public"):
            _validated_notify_ips("https://hooks.example.com/agent")


def test_validated_ips_rejects_unresolvable_host():
    with mock.patch(
        "security_agent.notify.transports._resolve_notify_host_ips",
        side_effect=OSError("no such host"),
    ):
        with pytest.raises(NotifyError, match="cannot resolve"):
            _validated_notify_ips("https://hooks.example.com/agent")


def test_validated_ips_accepts_public_host():
    with mock.patch(
        "security_agent.notify.transports._resolve_notify_host_ips",
        return_value=[PUBLIC_IP],
    ):
        host, ips = _validated_notify_ips("https://hooks.example.com/agent")
    assert host == "hooks.example.com"
    assert ips == (PUBLIC_IP,)


def test_pinned_backend_dials_validated_ip_not_hostname():
    backend = _PinnedNotifyBackend((PUBLIC_IP,))
    with mock.patch.object(backend, "_inner") as inner:
        backend.connect_tcp("hooks.example.com", 443)
    inner.connect_tcp.assert_called_once()
    assert inner.connect_tcp.call_args[0][0] == PUBLIC_IP


def test_send_slack_posts_through_pinned_client():
    with (
        mock.patch(
            "security_agent.notify.transports._resolve_notify_host_ips",
            return_value=[PUBLIC_IP],
        ) as fake_dns,
        mock.patch(
            "security_agent.notify.transports._pinned_notify_transport",
            return_value=mock.sentinel.transport,
        ) as fake_transport,
        mock.patch("security_agent.notify.transports.httpx.Client") as fake_client_cls,
    ):
        send_slack("https://hooks.example.com/agent", "subj", "body")
    fake_dns.assert_called_once_with("hooks.example.com")
    fake_transport.assert_called_once_with((PUBLIC_IP,))
    _, client_kwargs = fake_client_cls.call_args
    assert client_kwargs["transport"] is mock.sentinel.transport
    assert client_kwargs["timeout"] == 15
    assert client_kwargs["follow_redirects"] is False
    client = fake_client_cls.return_value.__enter__.return_value
    (post_url,), post_kwargs = client.post.call_args
    assert post_url == "https://hooks.example.com/agent"  # SNI/hostname unchanged
    assert post_kwargs["json"] == {"text": "subj\nbody"}


def test_send_webhook_pins_resolved_ips_and_signs():
    with (
        mock.patch(
            "security_agent.notify.transports._resolve_notify_host_ips",
            return_value=[PUBLIC_IP],
        ),
        mock.patch(
            "security_agent.notify.transports._pinned_notify_transport",
            return_value=mock.sentinel.transport,
        ) as fake_transport,
        mock.patch("security_agent.notify.transports.httpx.Client") as fake_client_cls,
    ):
        send_webhook("https://hooks.example.com/agent", {"a": 1}, signing_key="k")
    fake_transport.assert_called_once_with((PUBLIC_IP,))
    assert fake_client_cls.call_args[1]["transport"] is mock.sentinel.transport
    client = fake_client_cls.return_value.__enter__.return_value
    (post_url,), post_kwargs = client.post.call_args
    assert post_url == "https://hooks.example.com/agent"
    assert len(post_kwargs["headers"]["X-Agent-Signature"]) == 64


@pytest.mark.parametrize(
    "sender,url",
    [
        (send_slack, "https://169.254.169.254/x"),
        (send_slack, "https://localhost/x"),
        (send_webhook, "http://169.254.169.254/x"),
        (send_webhook, "http://127.0.0.1:8000/x"),
    ],
)
def test_sends_reject_non_public_targets_without_network(sender, url):
    with (
        mock.patch(
            "security_agent.notify.transports._resolve_notify_host_ips",
            return_value=["127.0.0.1"],
        ),
        mock.patch("security_agent.notify.transports.httpx.Client") as fake_client_cls,
    ):
        with pytest.raises(NotifyError):
            sender(url, "s", "b") if sender is send_slack else sender(url, {"s": "b"})
    fake_client_cls.assert_not_called()


def test_send_email_verifies_server_cert():
    with mock.patch("security_agent.notify.transports.smtplib.SMTP") as fake_smtp:
        server = fake_smtp.return_value.__enter__.return_value
        send_email(_email_config(), "pw", "subj", "body")
    server.starttls.assert_called_once()
    ctx = server.starttls.call_args.kwargs["context"]
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_email_config_rejects_plain_fallback():
    with pytest.raises(NotifyError, match="TLS"):
        validate_email_config(_email_config(use_tls=False))
    assert validate_email_config(_email_config())["use_tls"] is True
    assert validate_email_config(_email_config(use_tls=True))["use_tls"] is True
