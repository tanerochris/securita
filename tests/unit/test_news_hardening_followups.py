"""Cross-phase follow-ups #5-#10: retention pushdown, pinning,
cross-worker throttle, HN pagination, feed content-type allowlist."""

import json
from datetime import UTC, datetime, timedelta
from unittest import mock
from urllib.parse import urlparse

import pytest
from sqlalchemy import select

from security_agent.control import repos
from security_agent.control.lifecycle import apply_verdict, purge_old_news, transition_finding
from security_agent.db.models import (
    Finding,
    FindingStatus,
    NewsBoost,
    NewsItem,
    RepoKind,
    ScanRun,
    ScrapeThrottle,
)
from security_agent.db.session import session_scope
from security_agent.worker import news as news_mod
from security_agent.worker.news import FeedError, fetch_feed_items, fetch_hn_stories


@pytest.fixture(autouse=True)
def _public():
    def fake_validated(url: str):
        parts = urlparse(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise FeedError(f"refusing to fetch non-http URL: {url[:100]}")
        return parts.hostname, ("93.184.216.34",)

    with (
        mock.patch.object(news_mod, "_validated_ips", side_effect=fake_validated),
        mock.patch.object(news_mod, "enrich_item", return_value=False),
    ):
        yield


def _stream(content: bytes, *, status=200, content_type="application/rss+xml", location=None):
    resp = mock.Mock()
    resp.status_code = status
    resp.headers = {"content-type": content_type}
    if location:
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


def _seed(tag: str, status=FindingStatus.OPEN):
    repo = repos.connect_repo(tag, RepoKind.GIT, url=f"https://example.com/{tag}.git")
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        if run is None:
            run = ScanRun(repo_id=repo.id, trigger="manual")
            db.add(run)
            db.flush()
        finding = Finding(
            repo_id=repo.id,
            package="left-pad",
            installed_version="1.0.0",
            advisory_id="CVE-2026-90001",
            status=status,
        )
        db.add(finding)
        db.flush()
        item = NewsItem(
            source="hn",
            external_id=f"it-{tag}-{datetime.now(UTC).timestamp()}",
            url="https://news.example/story",
            title="CVE-2026-90001 left-pad",
            cve_ids=["CVE-2026-90001"],
        )
        db.add(item)
        db.flush()
        db.add(NewsBoost(finding_id=finding.id, news_item_id=item.id, weight=100, matched_on="CVE"))
        finding.news_weight = 100
        finding.news_url = "https://news.example/story"
        return repo.id, finding.id, item.id, run.id


# --- #5 + #7 (news is standalone: transitions never touch news columns) ---


def test_transitions_and_verdicts_leave_news_columns_alone():
    _repo, fid, _item, run_id = _seed("revoke-t")
    transition_finding(fid, FindingStatus.SILENT, reason="unreachable")
    with session_scope() as db:
        row = db.get(Finding, fid)
        assert row.status == FindingStatus.SILENT
        assert (row.news_weight, row.news_url) == (100, "https://news.example/story")

    _r2, fid2, _i2, run2 = _seed("revoke-v")
    apply_verdict(fid2, run2, False, reason_code="unreachable")
    with session_scope() as db:
        row = db.get(Finding, fid2)
        assert row.status == FindingStatus.SILENT
        assert row.silent_reason == "unreachable"


def test_purge_drops_stale_items_and_legacy_boosts():
    _repo, fid, old_item, _run = _seed("purge-rem")
    with session_scope() as db:
        fresh = NewsItem(
            source="hn",
            external_id=f"fresh-{datetime.now(UTC).timestamp()}",
            url="https://news.example/fresh",
            title="fresh",
            cve_ids=[],
        )
        db.add(fresh)
        db.flush()
        fresh_id = fresh.id
        db.add(NewsBoost(finding_id=fid, news_item_id=fresh.id, weight=10, matched_on="left-pad"))
        db.get(NewsItem, old_item).fetched_at = datetime.now(UTC) - timedelta(days=91)
    assert purge_old_news() >= 1
    with session_scope() as db:
        assert db.get(NewsItem, old_item) is None
        assert db.get(NewsItem, fresh_id) is not None
        assert (
            db.scalar(
                select(NewsBoost).where(
                    NewsBoost.finding_id == fid, NewsBoost.news_item_id == old_item
                )
            )
            is None
        )


# --- #6 ---


def test_pinned_transport_dials_only_validated_ips():
    backend = news_mod._PinnedBackend(("10.0.0.1", "93.184.216.34"))
    dialed = []

    def fake_connect(ip, port, **kw):
        dialed.append(ip)
        if ip == "10.0.0.1":
            raise OSError("refused")
        return mock.sentinel.stream

    backend._inner = mock.Mock(connect_tcp=fake_connect)
    assert backend.connect_tcp("evil.example", 443) is mock.sentinel.stream
    assert dialed == ["10.0.0.1", "93.184.216.34"]  # hostname never dialed/resolved


def test_rebinding_second_resolution_never_used():
    # Validation resolves public; the transport is built from that result,
    # so a later private answer cannot be reached through this fetch.
    with mock.patch.object(
        news_mod, "_resolve_host_ips", side_effect=[["93.184.216.34"], ["10.0.0.5"]]
    ):
        host, ips = news_mod._validated_ips("https://feed.example/rss")
    assert (host, ips) == ("feed.example", ("93.184.216.34",))
    transport = news_mod._pinned_transport(ips)
    assert transport._pool._network_backend._ips == ("93.184.216.34",)


# --- #8 ---


def test_db_throttle_blocks_second_worker():
    host = f"throttle-{datetime.now(UTC).timestamp()}.example"
    news_mod._last_fetch.clear()
    assert news_mod._try_claim_db_throttle(host) == 0.0
    # Simulated second worker: no in-process state, DB row still blocks.
    news_mod._last_fetch.clear()
    assert news_mod._try_claim_db_throttle(host) > 0
    with session_scope() as db:
        assert db.get(ScrapeThrottle, host) is not None


# --- #9 ---


def _hn_page(page: int, nb_pages: int, ids: list[str]) -> bytes:
    return json.dumps(
        {
            "nbPages": nb_pages,
            "hits": [
                {"objectID": i, "title": f"Story {i}", "created_at": "2026-01-01T00:00:00Z"}
                for i in ids
            ],
        }
    ).encode()


def test_hn_pagination_merges_and_dedupes():
    pages = [_hn_page(0, 3, ["1", "2"]), _hn_page(1, 3, ["2", "3"]), _hn_page(2, 3, ["4"])]
    calls = []

    def fake_stream(method, url, **kw):
        calls.append(url)
        return pages[len(calls) - 1] and _stream(
            pages[len(calls) - 1], content_type="application/json"
        )

    settings = mock.Mock(news_hn_max_pages=5)
    with (
        mock.patch.object(news_mod, "get_settings", return_value=settings),
        mock.patch.object(news_mod, "_http_stream", side_effect=fake_stream),
    ):
        drafts = fetch_hn_stories("CVE")
    assert [d["external_id"] for d in drafts] == ["1", "2", "3", "4"]
    assert [c.split("page=")[-1] for c in calls] == ["0", "1", "2"]


def test_hn_page_failure_stores_nothing():
    def fake_stream(method, url, **kw):
        if "page=1" in url:
            raise RuntimeError("boom")
        return _stream(_hn_page(0, 3, ["1"]), content_type="application/json")

    settings = mock.Mock(news_hn_max_pages=5)
    with (
        mock.patch.object(news_mod, "get_settings", return_value=settings),
        mock.patch.object(news_mod, "_http_stream", side_effect=fake_stream),
    ):
        with pytest.raises(RuntimeError, match="boom"):
            fetch_hn_stories("CVE")


# --- #10 ---


def test_feed_content_type_allowlist():
    rss = b'<?xml version="1.0"?><rss><channel><item><title>CVE-2026-1 x</title><link>https://n/1</link><guid>g1</guid></item></channel></rss>'
    with mock.patch.object(
        news_mod, "_http_stream", return_value=_stream(rss, content_type="image/png")
    ):
        with pytest.raises(FeedError, match="content-type"):
            fetch_feed_items("https://feed.example/rss")
    with mock.patch.object(
        news_mod, "_http_stream", return_value=_stream(rss, content_type="text/xml; charset=utf-8")
    ):
        assert fetch_feed_items("https://feed.example/rss")
    no_type = _stream(rss, content_type="")
    with mock.patch.object(news_mod, "_http_stream", return_value=no_type):
        assert fetch_feed_items("https://feed.example/rss")  # missing stays lenient
