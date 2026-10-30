"""H3 slice E: polite scrape fallback for CVE-less items."""

from datetime import UTC, datetime
from unittest import mock
from urllib.parse import urlparse

import pytest
from sqlalchemy import select

from security_agent.control import repos
from security_agent.db.models import Finding, NewsBoost, NewsItem, RepoKind
from security_agent.db.session import session_scope
from security_agent.worker import news as news_mod
from security_agent.worker.news import FeedError, enrich_item, match_item, scrape_article


@pytest.fixture(autouse=True)
def _public_urls():
    """Skip DNS resolution (hermetic tests) but keep scheme/host validation."""

    def _fake_public(url: str) -> str:
        parts = urlparse(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise FeedError(f"refusing to fetch non-http URL: {url[:100]}")
        return parts.hostname

    def _fake_validated(url: str):
        return _fake_public(url), ("93.184.216.34",)

    with (
        mock.patch.object(news_mod, "_assert_public_url", side_effect=_fake_public),
        mock.patch.object(news_mod, "_validated_ips", side_effect=_fake_validated),
    ):
        yield


@pytest.fixture(autouse=True)
def _fresh_throttle():
    from security_agent.db.models import ScrapeThrottle

    news_mod._last_fetch.clear()
    with session_scope() as db:
        for row in db.scalars(select(ScrapeThrottle)):
            db.delete(row)
    yield
    news_mod._last_fetch.clear()


def _item(title: str, url: str | None = "https://news.example/story") -> int:
    with session_scope() as db:
        row = NewsItem(
            source="rss",
            external_id=f"s-{datetime.now(UTC).timestamp()}",
            url=url,
            title=title,
            summary=None,
            cve_ids=[],
        )
        db.add(row)
        db.flush()
        return row.id


def _stream_page(content: bytes, *, status: int = 200, content_type: str = "text/html"):
    resp = mock.Mock()
    resp.status_code = status
    resp.headers = {"content-type": content_type}
    resp.charset_encoding = "utf-8"
    resp.iter_bytes = lambda chunk_size=65536: (
        content[i : i + chunk_size] for i in range(0, len(content), chunk_size)
    )
    resp.raise_for_status.return_value = None
    stream = mock.MagicMock()
    stream.__enter__.return_value = resp
    stream.__exit__.return_value = False
    return stream


def test_scrape_finds_cve_in_body():
    item = _item("Vendor advisory (no CVE in title)")
    page = b"<html><body><p>Fixes CVE-2026-60001 today.</p><script>var x=1;</script></body></html>"
    with mock.patch.object(news_mod, "_http_stream", return_value=_stream_page(page)) as fake:
        assert enrich_item(item) is True
    assert fake.call_args[1]["headers"]["User-Agent"].startswith("security-agent-bot")
    with session_scope() as db:
        row = db.get(NewsItem, item)
        assert row.cve_ids == ["CVE-2026-60001"]
        assert "<p>" not in (row.body_excerpt or "") and "CVE-2026-60001" in row.body_excerpt
        assert "var x=1" not in (row.body_excerpt or "")  # script code stripped


def test_script_cve_yields_no_match():
    item = _item("Changelog page")
    page = (
        b'<html><body><p>No advisories.</p><script>var id="CVE-2026-60009";</script></body></html>'
    )
    with mock.patch.object(news_mod, "_http_stream", return_value=_stream_page(page)):
        assert enrich_item(item) is True
    with session_scope() as db:
        row = db.get(NewsItem, item)
        assert row.cve_ids == [] and "CVE-2026-60009" not in (row.body_excerpt or "")


def test_scrape_failure_degrades_silently():
    item = _item("Dead link")
    with mock.patch.object(news_mod, "_http_stream", side_effect=RuntimeError("dns down")):
        assert enrich_item(item) is False
    with session_scope() as db:
        row = db.get(NewsItem, item)
        assert row.body_excerpt == "" and row.cve_ids == []
    with mock.patch.object(news_mod, "_http_stream") as fake:
        assert enrich_item(item) is False  # attempted once; never refetched
        fake.assert_not_called()


def test_scrape_refuses_binary_content():
    item = _item("Attached diagram")
    with mock.patch.object(
        news_mod, "_http_stream", return_value=_stream_page(b"\x89PNG", content_type="image/png")
    ):
        assert enrich_item(item) is False
    with session_scope() as db:
        assert db.get(NewsItem, item).body_excerpt == ""


def test_scrape_skips_without_work():
    with session_scope() as db:
        with_cves = NewsItem(
            source="rss",
            external_id=f"s-cve-{datetime.now(UTC).timestamp()}",
            title="t",
            cve_ids=["CVE-2026-1"],
        )
        db.add(with_cves)
        db.flush()
        cve_id = with_cves.id
    no_url = _item("No link", url=None)
    with mock.patch.object(news_mod, "_http_stream") as fake:
        assert enrich_item(cve_id) is False
        assert enrich_item(no_url) is False
        assert enrich_item(999999999) is False
        fake.assert_not_called()


def test_scrape_rejects_non_http_and_oversize():
    with pytest.raises(Exception, match="non-http"):
        scrape_article("file:///etc/passwd")
    big = b"x" * (news_mod.SCRAPE_MAX_BYTES + 1)
    with (
        mock.patch.object(news_mod, "_http_stream", return_value=_stream_page(big)),
        pytest.raises(Exception, match="exceeds"),
    ):
        scrape_article("https://news.example/huge")


def test_scrape_throttles_per_host():
    with (
        mock.patch.object(news_mod, "_http_stream", return_value=_stream_page(b"<p>hi</p>")),
        mock.patch.object(news_mod.time, "sleep") as fake_sleep,
    ):
        scrape_article("https://news.example/a")
        scrape_article("https://news.example/b")
        fake_sleep.assert_called_once()
        scrape_article("https://other.example/a")
        assert fake_sleep.call_count == 1  # different host: no wait


def test_throttle_state_evicted_and_bounded():
    now = 1_000_000.0
    news_mod._last_fetch.update({f"old-{i}.example": now - 60.0 for i in range(10)})
    news_mod._last_fetch["fresh.example"] = now
    with (
        mock.patch.object(news_mod, "_http_stream", return_value=_stream_page(b"<p>hi</p>")),
        mock.patch.object(news_mod.time, "sleep"),
        mock.patch.object(news_mod.time, "monotonic", return_value=now),
    ):
        scrape_article("https://new.example/x")
    assert "fresh.example" in news_mod._last_fetch
    assert "new.example" in news_mod._last_fetch
    assert not any(k.startswith("old-") for k in news_mod._last_fetch)
    news_mod._last_fetch.update({f"flood-{i}.example": now for i in range(5000)})
    with (
        mock.patch.object(news_mod, "_http_stream", return_value=_stream_page(b"<p>hi</p>")),
        mock.patch.object(news_mod.time, "sleep"),
        mock.patch.object(news_mod.time, "monotonic", return_value=now),
    ):
        scrape_article("https://flood-new.example/x")
    assert len(news_mod._last_fetch) <= news_mod._THROTTLE_MAX_HOSTS


def test_match_item_scrapes_then_boosts():
    repo = repos.connect_repo("scrape-m", RepoKind.GIT, url="https://example.com/s.git")
    with session_scope() as db:
        finding = Finding(
            repo_id=repo.id,
            package="left-pad",
            installed_version="1.0.0",
            advisory_id="CVE-2026-60002",
        )
        db.add(finding)
        db.flush()
        fid = finding.id
    item = _item("Advisory text forthcoming")
    page = b"<html><body>CVE-2026-60002 patched.</body></html>"
    with mock.patch.object(news_mod, "_http_stream", return_value=_stream_page(page)):
        assert match_item(item) >= 1
    with session_scope() as db:
        rows = list(db.scalars(select(NewsBoost).where(NewsBoost.finding_id == fid)))
        assert [(b.weight, b.matched_on) for b in rows] == [(100, "CVE-2026-60002")]
