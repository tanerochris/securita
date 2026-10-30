"""H3 slice B: HN + RSS pollers with recorded fixtures."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

import pytest
from sqlalchemy import select

from security_agent.db.models import NewsItem, NewsPoll
from security_agent.db.session import session_scope
from security_agent.worker import news as news_mod
from security_agent.worker.news import (
    FeedError,
    _feed_source,
    extract_cve_ids,
    fetch_feed_items,
    fetch_hn_stories,
    parse_feed,
    poll_news,
    store_news_items,
)

FIXTURES = Path(__file__).parent / "fixtures"


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


def _stream_fixture(
    *,
    content: bytes,
    status: int = 200,
    headers: dict | None = None,
    location: str | None = None,
):
    resp = mock.Mock()
    resp.status_code = status
    resp.headers = dict(headers or {"content-type": "application/rss+xml"})
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


def test_extract_cve_ids_sorted_unique():
    assert extract_cve_ids("cve-2026-20002 and CVE-2026-0001", "CVE-2026-0001!") == [
        "CVE-2026-0001",
        "CVE-2026-20002",
    ]
    assert extract_cve_ids(None, "") == []


def test_fetch_hn_stories_from_fixture():
    body = (FIXTURES / "hn-recorded.json").read_bytes()
    with mock.patch.object(
        news_mod, "_http_stream", return_value=_stream_fixture(content=body)
    ) as fake:
        drafts = fetch_hn_stories("CVE")
    url = fake.call_args[0][1]
    assert "query=CVE" in url and "tags=story" in url and "hitsPerPage=" in url
    by_id = {d["external_id"]: d for d in drafts}
    assert set(by_id) == {"hn-1001", "hn-1002", "hn-1004"}  # untitled skipped
    assert by_id["hn-1001"]["cve_ids"] == ["CVE-2026-10001"]
    assert by_id["hn-1002"]["cve_ids"] == ["CVE-2026-20002", "CVE-2026-20003"]
    assert by_id["hn-1004"]["cve_ids"] == [] and by_id["hn-1004"]["published_at"] is None


def test_fetch_hn_encodes_query():
    body = b'{"hits": []}'
    with mock.patch.object(
        news_mod, "_http_stream", return_value=_stream_fixture(content=body)
    ) as fake:
        assert fetch_hn_stories("CVE 2026&tags=evil") == []
    url = fake.call_args[0][1]
    assert "query=CVE+2026%26tags%3Devil" in url
    assert url.count("tags=") == 1  # injected param stayed inside the query value


def test_fetch_hn_reads_story_text_summary():
    body = (
        b'{"hits": [{"objectID": "st-1", "title": "Ask HN: postmortem", '
        b'"created_at": "2026-10-29T10:00:00Z", '
        b'"story_text": "Root cause was CVE-2026-77701 in our parser."}]}'
    )
    with mock.patch.object(news_mod, "_http_stream", return_value=_stream_fixture(content=body)):
        (draft,) = fetch_hn_stories("CVE")
    assert draft["cve_ids"] == ["CVE-2026-77701"]
    assert draft["summary"] is not None and "CVE-2026-77701" in draft["summary"]


def test_parse_rss_and_atom_fixtures():
    (rss,) = [d for d in parse_feed((FIXTURES / "rss-recorded.xml").read_text()) if d["cve_ids"]]
    assert rss["external_id"] == "rss-1"
    assert rss["cve_ids"] == ["CVE-2026-30001"]
    assert rss["published_at"] is not None and rss["published_at"].tzinfo is not None
    assert rss["summary"] is not None and "CVE-2026-30001" in rss["summary"]
    (atom,) = parse_feed((FIXTURES / "atom-recorded.xml").read_text())
    assert atom["external_id"] == "atom-1"
    assert atom["url"] == "https://example.com/atom/1"
    assert atom["cve_ids"] == ["CVE-2026-40001"]


def test_parse_feed_rejects_doctype_and_garbage():
    with pytest.raises(FeedError, match="DOCTYPE"):
        parse_feed('<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY x "y">]><rss/>')
    with pytest.raises(FeedError, match="unparseable"):
        parse_feed("<rss><broken")
    with pytest.raises(FeedError, match="unsupported"):
        parse_feed("<html><body>not a feed</body></html>")


def test_fetch_rejects_oversize():
    big = b"x" * (news_mod._MAX_FEED_BYTES + 1)
    with mock.patch.object(news_mod, "_http_stream", return_value=_stream_fixture(content=big)):
        with pytest.raises(FeedError, match="exceeds"):
            fetch_feed_items("https://example.com/feed.xml")


def test_fetch_follows_redirect_to_public_url():
    rss = (FIXTURES / "rss-recorded.xml").read_bytes()
    redirect = _stream_fixture(content=b"", status=302, location="https://cdn.example/feed.xml")
    final = _stream_fixture(content=rss)
    with mock.patch.object(news_mod, "_http_stream", side_effect=[redirect, final]) as fake:
        drafts = fetch_feed_items("https://example.com/feed.xml")
    assert fake.call_args[0][1] == "https://cdn.example/feed.xml"
    assert any(d["cve_ids"] == ["CVE-2026-30001"] for d in drafts)


def test_store_dedupes_on_repoll():
    drafts = [
        {
            "source": "rss",
            "external_id": f"dup-{datetime.now(UTC).timestamp()}",
            "url": None,
            "title": "t",
            "summary": None,
            "published_at": None,
            "cve_ids": [],
        }
    ]
    assert store_news_items(drafts) == 1
    assert store_news_items(drafts) == 0


def test_same_guid_across_feeds_both_stored():
    xml = (
        '<?xml version="1.0"?><rss version="2.0"><channel>'
        "<item><title>CVE-2026-90001 wave</title><link>https://x.example/1</link>"
        "<guid>shared-guid</guid></item></channel></rss>"
    )
    with mock.patch.object(
        news_mod, "_http_stream", return_value=_stream_fixture(content=xml.encode())
    ):
        first = fetch_feed_items("https://a.example/feed.xml")
        second = fetch_feed_items("https://b.example/feed.xml")
    assert first[0]["source"] != second[0]["source"]
    assert store_news_items(first) == 1
    assert store_news_items(second) == 1  # same guid, different feed: no collision


def test_poll_news_gates_on_cadence_and_records():
    hn_body = (FIXTURES / "hn-recorded.json").read_bytes()
    settings = mock.Mock(news_hn_query="CVE", news_rss_feeds="", news_poll_hours=1.0)
    http = _stream_fixture(content=hn_body)
    with session_scope() as db:  # earlier tests may have polled; force due
        for row in db.scalars(select(NewsPoll).where(NewsPoll.source == "hn")):
            row.finished_at = datetime.now(UTC) - timedelta(hours=2)
    with (
        mock.patch.object(news_mod, "get_settings", return_value=settings),
        mock.patch.object(news_mod, "_http_stream", return_value=http) as fake,
    ):
        first = poll_news()
        assert "hn" in first  # count varies: earlier tests may own the fixture rows
        assert poll_news() == {}  # within cadence: nothing polled
        assert fake.call_count == 1
    with session_scope() as db:
        row = db.scalar(
            select(NewsPoll).where(NewsPoll.source == "hn").order_by(NewsPoll.id.desc())
        )
        row.finished_at = datetime.now(UTC) - timedelta(hours=2)
    with (
        mock.patch.object(news_mod, "get_settings", return_value=settings),
        mock.patch.object(news_mod, "_http_stream", return_value=_stream_fixture(content=hn_body)),
    ):
        assert poll_news() == {"hn": 0}  # re-polled, all dupes
    with session_scope() as db:
        assert db.scalar(select(NewsItem).where(NewsItem.source == "hn")) is not None


def test_hn_failure_does_not_starve_rss():
    rss_body = (FIXTURES / "rss-recorded.xml").read_bytes()
    feed = f"https://rss-fallback-{datetime.now(UTC).timestamp()}.example/feed.xml"
    settings = mock.Mock(news_hn_query="CVE", news_rss_feeds=feed, news_poll_hours=0.0)

    def _route(method, url, **kwargs):
        if "algolia" in url:
            raise RuntimeError("HN down")
        return _stream_fixture(content=rss_body)

    with session_scope() as db:
        for row in db.scalars(select(NewsPoll)):
            row.finished_at = datetime.now(UTC) - timedelta(hours=2)
    with (
        mock.patch.object(news_mod, "get_settings", return_value=settings),
        mock.patch.object(news_mod, "_http_stream", side_effect=_route),
    ):
        result = poll_news()
    assert result["hn"] == 0  # attempted, failed, recorded
    assert result["rss"] == 2  # RSS still polled despite the HN outage
    with session_scope() as db:
        assert db.scalar(select(NewsPoll).where(NewsPoll.source == _feed_source(feed))) is not None


def test_feeds_gated_independently_per_feed():
    rss_body = (FIXTURES / "rss-recorded.xml").read_bytes()
    hn_body = (FIXTURES / "hn-recorded.json").read_bytes()
    stamp = datetime.now(UTC).timestamp()
    feed_a = f"https://gate-a-{stamp}.example/feed.xml"
    feed_b = f"https://gate-b-{stamp}.example/feed.xml"
    settings = mock.Mock(news_hn_query="CVE", news_rss_feeds=f"{feed_a}, {feed_b}")
    settings.news_poll_hours = 1.0

    def _route(method, url, **kwargs):
        return _stream_fixture(content=hn_body if "algolia" in url else rss_body)

    with (
        mock.patch.object(news_mod, "get_settings", return_value=settings),
        mock.patch.object(news_mod, "_http_stream", side_effect=_route) as fake,
    ):
        assert poll_news()["rss"] >= 0
        feed_calls = [c for c in fake.call_args_list if "algolia" not in c[0][1]]
        assert len(feed_calls) == 2  # one fetch per feed
        assert poll_news() == {}  # HN and both feeds gated now
    with session_scope() as db:
        row = db.scalar(select(NewsPoll).where(NewsPoll.source == _feed_source(feed_a)))
        assert row is not None
        row.finished_at = datetime.now(UTC) - timedelta(hours=2)
    with (
        mock.patch.object(news_mod, "get_settings", return_value=settings),
        mock.patch.object(news_mod, "_http_stream", side_effect=_route) as fake,
    ):
        poll_news()
        assert fake.call_count == 1  # only the due feed refetched
        assert fake.call_args[0][1] == feed_a
