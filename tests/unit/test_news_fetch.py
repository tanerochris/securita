"""H3 hardening: SSRF guard, streaming caps, redirect re-validation."""

from unittest import mock

import pytest

from security_agent.worker import news as news_mod
from security_agent.worker.news import FeedError, _assert_public_url, scrape_article

PUBLIC_IP = "93.184.216.34"  # documentation-safe stand-in, globally routable


@pytest.fixture(autouse=True)
def _fake_dns():
    with mock.patch.object(news_mod, "_resolve_host_ips", return_value=[PUBLIC_IP]):
        yield


@pytest.fixture(autouse=True)
def _fresh_throttle():
    news_mod._last_fetch.clear()
    yield
    news_mod._last_fetch.clear()


def _stream_response(
    content: bytes, *, status: int = 200, headers: dict | None = None, location: str | None = None
):
    resp = mock.Mock()
    resp.status_code = status
    resp.headers = dict(headers or {"content-type": "text/html"})
    if location is not None:
        resp.headers["location"] = location
    resp.charset_encoding = "utf-8"
    resp.iter_bytes = lambda chunk_size=65536: (
        content[i : i + chunk_size] for i in range(0, len(content), chunk_size)
    )
    resp.raise_for_status.return_value = None
    stream = mock.MagicMock()
    stream.__enter__.return_value = resp
    stream.__exit__.return_value = False
    return stream


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "https://127.0.0.1:8443/x",
        "http://10.0.0.5/",
        "http://172.16.4.4/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[fe80::1]/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "https://",
    ],
)
def test_assert_public_url_rejects_non_public(url):
    with pytest.raises(FeedError):
        _assert_public_url(url)


def test_assert_public_url_accepts_public_literal():
    assert _assert_public_url(f"http://{PUBLIC_IP}/x") == PUBLIC_IP


def test_assert_public_url_rejects_private_dns():
    with mock.patch.object(news_mod, "_resolve_host_ips", return_value=["10.9.9.9"]):
        with pytest.raises(FeedError, match="non-public"):
            _assert_public_url("https://feed.example/rss")


def test_assert_public_url_rejects_unresolvable():
    import socket

    with mock.patch.object(
        news_mod, "_resolve_host_ips", side_effect=socket.gaierror("no such host")
    ):
        with pytest.raises(FeedError, match="cannot resolve"):
            _assert_public_url("https://missing.example/rss")


def test_scrape_never_requests_private_target():
    with (
        mock.patch.object(news_mod, "_http_stream") as fake,
        pytest.raises(FeedError, match="non-public"),
    ):
        scrape_article("http://169.254.169.254/latest/meta-data/")
    fake.assert_not_called()


def test_redirect_to_private_is_blocked():
    first = _stream_response(b"", status=302, location="http://169.254.169.254/x")
    with (
        mock.patch.object(news_mod, "_http_stream", return_value=first),
        pytest.raises(FeedError, match="non-public"),
    ):
        scrape_article("https://news.example/story")


def test_redirect_chain_followed_with_revalidation():
    hops = [
        _stream_response(b"", status=301, location="/hop2"),
        _stream_response(b"<html><body>CVE-2026-61001 fixed.</body></html>"),
    ]
    with mock.patch.object(news_mod, "_http_stream", side_effect=hops) as fake:
        text = scrape_article("https://news.example/story")
    assert "CVE-2026-61001" in text
    assert fake.call_args_list[1][0][1] == "https://news.example/hop2"


def test_too_many_redirects_aborts():
    hop = _stream_response(b"", status=302, location="https://news.example/loop")
    with (
        mock.patch.object(news_mod, "_http_stream", return_value=hop),
        pytest.raises(FeedError, match="too many redirects"),
    ):
        scrape_article("https://news.example/loop")


def test_streaming_cap_aborts_without_buffering_all():
    seen = []

    def _drip(chunk_size=65536):
        for _ in range(100):
            seen.append(1)
            yield b"x" * chunk_size

    resp = mock.Mock()
    resp.status_code = 200
    resp.headers = {"content-type": "text/html"}
    resp.raise_for_status.return_value = None
    resp.iter_bytes = _drip
    stream = mock.MagicMock()
    stream.__enter__.return_value = resp
    stream.__exit__.return_value = False
    with (
        mock.patch.object(news_mod, "_http_stream", return_value=stream),
        pytest.raises(FeedError, match="exceeds"),
    ):
        scrape_article("https://news.example/huge")
    assert len(seen) < 100  # stopped at the cap, never consumed the rest
