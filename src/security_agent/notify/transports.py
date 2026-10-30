"""FR-13 channel transports: email (SMTP+STARTTLS), Slack, generic webhook.

Each send opens a fresh short-lived connection (no shared clients, no
leaks across threads), enforces timeouts and payload caps, and raises a
NotifyError the caller converts to an audit warning — delivery must
never break the pipeline that triggered it. Secrets (passwords, webhook
URLs) arrive as arguments and are never logged.
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import smtplib
import socket
import ssl
from datetime import UTC, datetime
from email.message import EmailMessage
from urllib.parse import urlparse

import httpx

log = logging.getLogger(__name__)

TIMEOUT_SECONDS = 15
MAX_BODY_CHARS = 100_000


class NotifyError(RuntimeError):
    """Expected delivery failure: audit-warned, never raised past notify_event."""


def _check_http_url(url: str, *, allow_http: bool, what: str) -> str:
    """Validated absolute URL (scheme + host); operator-configured, shape-checked."""
    if not isinstance(url, str) or len(url) > 2000:
        raise NotifyError(f"{what} URL is missing or oversize")
    try:
        parts = urlparse(url.strip())
    except ValueError as exc:
        raise NotifyError(f"{what} URL is invalid: {exc}") from exc
    ok_schemes = {"http", "https"} if allow_http else {"https"}
    if parts.scheme not in ok_schemes or not parts.hostname:
        raise NotifyError(f"{what} URL must be {'http(s)' if allow_http else 'https'} with a host")
    return url.strip()


def _resolve_notify_host_ips(host: str) -> list[str]:
    """Distinct resolved IP strings for a hostname (patchable in tests)."""
    return list({str(info[4][0]) for info in socket.getaddrinfo(host, None)})


def _validated_notify_ips(url: str) -> tuple[str, tuple[str, ...]]:
    """Validate a notify URL and return (hostname, validated public IPs).

    Self-contained SSRF guard (same idea as the news fetcher's pinned
    backend, without importing it): only http(s) URLs whose every
    resolved address is globally routable are allowed — loopback,
    link-local (incl. 169.254.169.254), private, reserved, and
    unspecified targets raise NotifyError. Callers must POST through
    _pinned_notify_transport so the validated IPs are the ones actually
    dialed (no DNS rebinding window).
    """
    parts = urlparse(url)
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or not host:
        raise NotifyError(f"refusing to notify non-http URL: {url[:100]}")
    try:
        ips = [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            ips = _resolve_notify_host_ips(host)
        except OSError as exc:
            raise NotifyError(f"cannot resolve notify host {host}: {exc}") from exc
    if not ips:
        raise NotifyError(f"cannot resolve notify host {host}: no addresses")
    for ip_text in ips:
        if not ipaddress.ip_address(ip_text).is_global:
            raise NotifyError(f"refusing to notify non-public address {host}: {ip_text}")
    return host, tuple(ips)


class _PinnedNotifyBackend:
    """httpcore backend that dials only pre-validated IPs, never DNS.

    The URL hostname is unchanged, so SNI and certificate verification
    still use the original hostname; only the TCP destination is pinned.
    """

    def __init__(self, ips: tuple[str, ...]) -> None:
        from httpcore._backends.sync import SyncBackend

        self._ips = ips
        self._inner = SyncBackend()

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        last: Exception | None = None
        for ip in self._ips:
            try:
                return self._inner.connect_tcp(
                    ip,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as exc:  # noqa: BLE001 - try the next validated IP
                last = exc
        raise last if last is not None else RuntimeError("no validated IPs")

    def connect_unix_socket(self, path, timeout=None, socket_options=None):  # pragma: no cover
        raise RuntimeError("unix sockets are not used for notifications")


def _pinned_notify_transport(ips: tuple[str, ...]) -> httpx.HTTPTransport:
    """httpx transport whose connections can only reach validated IPs."""
    import httpcore

    transport = httpx.HTTPTransport()
    from typing import cast

    transport._pool = httpcore.ConnectionPool(  # noqa: SLF001 - no public backend hook
        network_backend=cast("httpcore.NetworkBackend", _PinnedNotifyBackend(ips)),
        max_connections=10,
        max_keepalive_connections=5,
    )
    return transport


def _post_pinned(
    url: str,
    *,
    what: str,
    json_body: dict | None = None,
    content: bytes | None = None,
    headers: dict | None = None,
) -> None:
    """POST through a pinned-IP client: validated target, no redirects."""
    _host, ips = _validated_notify_ips(url)
    try:
        with httpx.Client(
            transport=_pinned_notify_transport(ips),
            timeout=TIMEOUT_SECONDS,
            follow_redirects=False,
        ) as client:
            resp = client.post(url, json=json_body, content=content, headers=headers)
            resp.raise_for_status()
    except (httpx.HTTPError, ValueError) as exc:
        raise NotifyError(f"{what} send failed: {exc}") from exc


def _check_email(addr: str, what: str) -> str:
    if not isinstance(addr, str) or "@" not in addr or len(addr) > 320 or " " in addr.strip():
        raise NotifyError(f"{what} is not a valid email address")
    return addr.strip()


def validate_email_config(config: dict) -> dict:
    """Non-secret SMTP config, normalized or raising NotifyError."""
    if not isinstance(config, dict):
        raise NotifyError("email config must be an object")
    host = config.get("host", "")
    if not isinstance(host, str) or not host.strip() or len(host) > 500 or "://" in host:
        raise NotifyError("email host is required (bare hostname, no scheme)")
    try:
        port = int(config.get("port", 587))
    except (TypeError, ValueError) as exc:
        raise NotifyError("email port must be a number") from exc
    if not 1 <= port <= 65535:
        raise NotifyError("email port out of range")
    to = config.get("to", [])
    addrs = [to] if isinstance(to, str) else list(to) if isinstance(to, list) else []
    if not addrs:
        raise NotifyError("email needs at least one recipient")
    if "use_tls" in config and not config["use_tls"]:
        raise NotifyError("email TLS is required (plain SMTP fallback is disabled)")
    return {
        "host": host.strip(),
        "port": port,
        "username": str(config.get("username", ""))[:320],
        "from_addr": _check_email(str(config.get("from_addr", "")), "from address"),
        "to": [_check_email(str(a), "recipient") for a in addrs[:50]],
        "use_tls": True,
    }


def send_email(
    config: dict,
    password: str,
    subject: str,
    body: str,
    *,
    attachments: list[tuple[str, bytes, str]] | None = None,
) -> None:
    """SMTP send with STARTTLS; raises NotifyError on any failure."""
    cfg = validate_email_config(config)
    msg = EmailMessage()
    msg["Subject"] = subject[:500]
    msg["From"] = cfg["from_addr"]
    msg["To"] = ", ".join(cfg["to"])
    msg.set_content(body[:MAX_BODY_CHARS])
    for filename, payload, mime in attachments or []:
        maintype, _, subtype = mime.partition("/") or ("application", "", "octet-stream")
        msg.add_attachment(
            payload[:5_000_000],
            maintype=maintype or "application",
            subtype=subtype or "octet-stream",
            filename=filename[:100],
        )
    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=TIMEOUT_SECONDS) as smtp:
            smtp.ehlo()
            if cfg["use_tls"]:
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
            if cfg["username"]:
                smtp.login(cfg["username"], password or "")
            smtp.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        raise NotifyError(f"SMTP send failed: {exc}") from exc


def send_slack(webhook_url: str, subject: str, body: str, *, link: str = "") -> None:
    """Incoming-webhook POST; raises NotifyError on any failure."""
    url = _check_http_url(webhook_url, allow_http=False, what="Slack")
    text = subject[:500]
    if body:
        text += "\n" + body[:MAX_BODY_CHARS]
    if link:
        text += f"\n<{link[:2000]}|Open dashboard>"
    _post_pinned(url, what="Slack", json_body={"text": text})


def webhook_payload(severity: str, subject: str, body: str, *, link: str = "") -> dict:
    return {
        "severity": severity,
        "subject": subject[:500],
        "body": body[:MAX_BODY_CHARS],
        "link": link[:2000],
        "ts": datetime.now(UTC).isoformat(),
    }


def send_webhook(url: str, payload: dict, *, signing_key: str = "") -> None:
    """Generic JSON POST with an optional HMAC signature header."""
    target = _check_http_url(url, allow_http=True, what="webhook")
    raw = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if signing_key:
        headers["X-Agent-Signature"] = hmac.new(
            signing_key.encode(), raw, hashlib.sha256
        ).hexdigest()
    _post_pinned(target, what="webhook", content=raw, headers=headers)
