"""Tier-2 news pollers: HN Algolia + RSS/Atom feeds (FR-6, H3 slice B).

Pollers fetch and store news items with extracted CVE IDs. Matching
against findings lives in slice C; this module never touches findings.
"""

import hashlib
import ipaddress
import logging
import re
import socket
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager as _contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urlencode, urljoin, urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from security_agent.config import get_settings
from security_agent.db.models import Finding, FindingStatus, NewsBoost, NewsItem, NewsPoll
from security_agent.db.session import session_scope

log = logging.getLogger(__name__)

_HN_API = "https://hn.algolia.com/api/v1/search_by_date"
_HN_HITS_PER_PAGE = 100
_FETCH_TIMEOUT = 15
_MAX_JSON_BYTES = 2_000_000
_MAX_FEED_BYTES = 1_000_000
_MAX_REDIRECTS = 5
_CHUNK_BYTES = 65_536
_USER_AGENT = "security-agent-bot/1.0"
_SUMMARY_CHARS = 4000

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class FeedError(RuntimeError):
    """Unparseable or oversize feed; the source is skipped, not fatal."""


def extract_cve_ids(*texts: str | None) -> list[str]:
    """Sorted unique CVE IDs across the given texts."""
    found: set[str] = set()
    for text in texts:
        if text:
            found.update(m.upper() for m in CVE_RE.findall(text))
    return sorted(found)


def _resolve_host_ips(host: str) -> list[str]:
    """Distinct resolved IP strings for a hostname (patchable in tests)."""
    return list({str(info[4][0]) for info in socket.getaddrinfo(host, None)})


def _validated_ips(url: str) -> tuple[str, tuple[str, ...]]:
    """Validate a URL and return (hostname, validated public IPs).

    Raises FeedError so callers degrade (skip the source, keep a
    rumor-only item) instead of fetching internal targets. Callers must
    connect through _pinned_transport so the validated IPs are the ones
    actually dialed (follow-up #6: no DNS rebinding window).
    """
    parts = urlparse(url)
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or not host:
        raise FeedError(f"refusing to fetch non-http URL: {url[:100]}")
    try:
        ips = [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            ips = _resolve_host_ips(host)
        except OSError as exc:
            raise FeedError(f"cannot resolve {host}: {exc}") from exc
    if not ips:
        raise FeedError(f"cannot resolve {host}: no addresses")
    for ip_text in ips:
        if not ipaddress.ip_address(ip_text).is_global:
            raise FeedError(f"refusing to fetch non-public address {host}: {ip_text}")
    return host, tuple(ips)


def _assert_public_url(url: str) -> str:
    """Reject non-http URLs and hosts that resolve to non-public addresses."""
    return _validated_ips(url)[0]


class _PinnedBackend:
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
        raise RuntimeError("unix sockets are not used for news fetches")


@_contextmanager
def _http_stream(method: str, url: str, *, timeout: float, headers: dict, ips: tuple[str, ...]):
    """One pinned-IP HTTP request; the single news fetch seam (mocked in tests)."""
    with httpx.Client(transport=_pinned_transport(ips), timeout=timeout) as client:
        with client.stream(method, url, headers=headers) as resp:
            yield resp


def _pinned_transport(ips: tuple[str, ...]) -> httpx.HTTPTransport:
    """httpx transport whose connections can only reach validated IPs."""
    import httpcore

    transport = httpx.HTTPTransport()
    from typing import cast

    transport._pool = httpcore.ConnectionPool(  # noqa: SLF001 - no public backend hook
        network_backend=cast("httpcore.NetworkBackend", _PinnedBackend(ips)),
        max_connections=10,
        max_keepalive_connections=5,
    )
    return transport


def _read_capped_text(resp: httpx.Response, url: str, max_bytes: int) -> str:
    """Stream the body, aborting past the cap instead of buffering first."""
    chunks: list[bytes] = []
    total = 0
    for chunk in resp.iter_bytes(chunk_size=_CHUNK_BYTES):
        total += len(chunk)
        if total > max_bytes:
            raise FeedError(f"response from {url} exceeds {max_bytes} bytes")
        chunks.append(chunk)
    encoding = resp.charset_encoding or "utf-8"
    return b"".join(chunks).decode(encoding, errors="replace")


_FEED_CONTENT_TYPES = (
    "application/rss+xml",
    "application/atom+xml",
    "application/xml",
    "text/xml",
    "application/rdf+xml",
)


def _assert_feed_response(resp: httpx.Response, host: str) -> None:
    """Feed content-type allowlist (follow-up #10); missing type stays lenient."""
    ctype = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
    if ctype and ctype not in _FEED_CONTENT_TYPES:
        raise FeedError(f"refusing feed content-type {ctype} from {host}")


def _fetch_text(url: str, max_bytes: int, *, feed: bool = False) -> str:
    """GET with pinned-IP validation, redirect re-validation, streaming caps."""
    current = url
    for _ in range(_MAX_REDIRECTS + 1):
        host, ips = _validated_ips(current)
        with _http_stream(
            "GET", current, timeout=_FETCH_TIMEOUT, headers={"User-Agent": _USER_AGENT}, ips=ips
        ) as resp:
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                if not location:
                    raise FeedError(f"redirect from {host} lacks a Location header")
                current = urljoin(current, location)
                continue
            resp.raise_for_status()
            if feed:
                _assert_feed_response(resp, host)
            return _read_capped_text(resp, host, max_bytes)
    raise FeedError(f"too many redirects fetching {url[:100]}")


def _hn_max_pages() -> int:
    value = getattr(get_settings(), "news_hn_max_pages", 5)
    return max(1, min(value, 20)) if isinstance(value, int) else 5


def fetch_hn_stories(query: str) -> list[dict]:
    """Recent HN stories matching the query → news-item drafts.

    Paginates the Algolia API (follow-up #9) up to NEWS_HN_MAX_PAGES.
    Pages are collected before returning, so a mid-pagination failure
    stores nothing instead of a partial page set.
    """
    import json

    hits: list = []
    seen_ids: set[str] = set()
    page = 0
    while page < _hn_max_pages():
        params = urlencode(
            {"query": query, "tags": "story", "hitsPerPage": _HN_HITS_PER_PAGE, "page": page}
        )
        body = _fetch_text(f"{_HN_API}?{params}", _MAX_JSON_BYTES)
        try:
            payload = json.loads(body)
        except ValueError as exc:
            raise FeedError(f"HN API returned invalid JSON: {exc}") from exc
        page_hits = payload.get("hits", []) if isinstance(payload, dict) else []
        if not isinstance(page_hits, list) or not page_hits:
            break
        for hit in page_hits:
            oid = str(hit.get("objectID") or "") if isinstance(hit, dict) else ""
            if oid and oid in seen_ids:
                continue
            if oid:
                seen_ids.add(oid)
            hits.append(hit)
        nb_pages = payload.get("nbPages") if isinstance(payload, dict) else None
        total_pages = nb_pages if isinstance(nb_pages, int) and nb_pages > 0 else page + 1
        page += 1
        if page >= total_pages:
            break
    drafts = []
    for hit in hits:
        title = (hit.get("title") or "").strip()
        if not title or not hit.get("objectID"):
            continue
        published = None
        try:
            raw = str(hit.get("created_at", "")).replace("Z", "+00:00")
            published = datetime.fromisoformat(raw)
        except ValueError:
            pass
        summary = (hit.get("story_text") or "").strip()[:_SUMMARY_CHARS] or None
        drafts.append(
            {
                "source": "hn",
                "external_id": str(hit["objectID"])[:500],
                "url": (str(hit.get("url") or "")[:2000] or None),
                "title": title[:1000],
                "summary": summary,
                "published_at": published,
                "cve_ids": extract_cve_ids(title, summary),
            }
        )
    return drafts


def _entry_text(entry: ET.Element, names: tuple[str, ...]) -> str:
    for name in names:
        child = entry.find(f"{{*}}{name}")
        if child is not None and child.text and child.text.strip():
            return child.text.strip()
    return ""


def _entry_link(entry: ET.Element) -> str:
    link = entry.find("{*}link")
    if link is None:
        return ""
    if link.text and link.text.strip():
        return link.text.strip()  # RSS <link>url</link>
    return (link.get("href") or "").strip()  # Atom <link href/>


def _entry_published(entry: ET.Element) -> datetime | None:
    for name in ("published", "updated", "pubDate", "date"):
        child = entry.find(f"{{*}}{name}")
        if child is None or not (child.text or "").strip():
            continue
        raw = (child.text or "").strip()
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            try:
                parsed = parsedate_to_datetime(raw)
            except (TypeError, ValueError):
                continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
    return None


def _feed_source(feed_url: str) -> str:
    """Stable per-feed source key so identical GUIDs on two feeds don't collide."""
    digest = hashlib.sha256(feed_url.encode()).hexdigest()[:12]
    return f"rss:{digest}"


def parse_feed(xml_text: str, *, source: str = "rss") -> list[dict]:
    """RSS2/Atom → news-item drafts. DOCTYPE is rejected (entity expansion)."""
    if "<!doctype" in xml_text.lower():
        raise FeedError("feed declares a DOCTYPE; refusing to parse")
    try:
        root = ET.fromstring(xml_text)  # noqa: S314 DOCTYPE rejected above, size capped
    except ET.ParseError as exc:
        raise FeedError(f"feed XML unparseable: {exc}") from exc
    tag = root.tag.rsplit("}", 1)[-1].lower()
    if tag == "rss":
        entries = root.findall("./channel/item")
    elif tag == "feed":
        entries = root.findall("./{*}entry")
    else:
        raise FeedError(f"unsupported feed root: {root.tag}")
    drafts = []
    for entry in entries:
        title = _entry_text(entry, ("title",))
        if not title:
            continue
        link = _entry_link(entry)
        guid = _entry_text(entry, ("guid", "id")) or link
        if not guid:
            continue
        summary = _entry_text(entry, ("description", "summary"))
        drafts.append(
            {
                "source": source,
                "external_id": guid[:500],
                "url": (link[:2000] or None),
                "title": title[:1000],
                "summary": (summary[:_SUMMARY_CHARS] or None),
                "published_at": _entry_published(entry),
                "cve_ids": extract_cve_ids(title, summary),
            }
        )
    return drafts


def fetch_feed_items(feed_url: str) -> list[dict]:
    """Fetch one RSS/Atom feed → news-item drafts."""
    return parse_feed(
        _fetch_text(feed_url, _MAX_FEED_BYTES, feed=True), source=_feed_source(feed_url)
    )


def store_news_items(drafts: list[dict]) -> int:
    """Persist drafts; re-polls of known (source, external_id) are skipped."""
    stored = 0
    with session_scope() as db:
        for draft in drafts:
            try:
                with db.begin_nested():
                    db.add(NewsItem(**draft))
                    db.flush()
            except IntegrityError:
                continue
            stored += 1
    return stored


def poll_due(source: str, *, hours: float, now: datetime | None = None) -> bool:
    """True when the source has no poll within the cadence window."""
    now = now or datetime.now(UTC)
    with session_scope() as db:
        latest = db.scalar(
            select(NewsPoll).where(NewsPoll.source == source).order_by(NewsPoll.id.desc()).limit(1)
        )
        if latest is None:
            return True
        finished = latest.finished_at
        if finished.tzinfo is None:
            finished = finished.replace(tzinfo=UTC)
        return (now - finished).total_seconds() >= hours * 3600


def _record_poll(source: str, items: int) -> None:
    with session_scope() as db:
        db.add(NewsPoll(source=source, items=items))


STRONG_WEIGHT = 100  # CVE/advisory match on a Tier-1 finding
WEAK_WEIGHT = 10  # package-name mention in the story title

SCRAPE_TIMEOUT = 15
SCRAPE_MAX_BYTES = 512_000
SCRAPE_THROTTLE_SECONDS = 2.0  # per-host minimum gap between fetches
EXCERPT_CHARS = 4000
_THROTTLE_MAX_HOSTS = 4096

_last_fetch: dict[str, float] = {}


def _try_claim_db_throttle(host: str) -> float:
    """Atomically claim a scrape slot across workers (follow-up #8).

    Returns 0 when claimed, else seconds to wait. The claim commits
    before any sleep/fetch so no transaction is held open. The update
    is conditional on the observed timestamp, so concurrent claimants
    cannot both win the same slot.
    """
    from sqlalchemy import update as _update

    from security_agent.db.models import ScrapeThrottle

    now = datetime.now(UTC)
    with session_scope() as db:
        row = db.get(ScrapeThrottle, host)
        if row is None:
            try:
                with db.begin_nested():
                    db.add(ScrapeThrottle(host=host, last_fetch_at=now))
                    db.flush()
                return 0.0
            except IntegrityError:
                row = db.get(ScrapeThrottle, host)
                if row is None:
                    return 0.0
        last = row.last_fetch_at
        last_aware = last if last.tzinfo else last.replace(tzinfo=UTC)
        elapsed = (now - last_aware).total_seconds()
        if elapsed < SCRAPE_THROTTLE_SECONDS:
            return SCRAPE_THROTTLE_SECONDS - elapsed
        from typing import Any, cast

        from sqlalchemy.engine import CursorResult

        result = db.execute(
            _update(ScrapeThrottle)
            .where(
                ScrapeThrottle.host == host,
                ScrapeThrottle.last_fetch_at == last,
            )
            .values(last_fetch_at=now)
        )
        claimed = cast("CursorResult[Any]", result).rowcount
        return 0.0 if claimed else SCRAPE_THROTTLE_SECONDS


def _record_db_throttle(host: str) -> None:
    """Record a scrape after waiting out the gap (best-effort upsert)."""
    from security_agent.db.models import ScrapeThrottle

    now = datetime.now(UTC)
    with session_scope() as db:
        row = db.get(ScrapeThrottle, host)
        if row is None:
            try:
                with db.begin_nested():
                    db.add(ScrapeThrottle(host=host, last_fetch_at=now))
                    db.flush()
            except IntegrityError:
                row = db.get(ScrapeThrottle, host)
                if row is not None:
                    row.last_fetch_at = now
        else:
            row.last_fetch_at = now


def _throttle_wait(host: str) -> None:
    """Per-host gap: in-process L1 plus the cross-worker DB claim."""
    now = time.monotonic()
    for known, at in list(_last_fetch.items()):
        if now - at >= SCRAPE_THROTTLE_SECONDS:
            del _last_fetch[known]
    if len(_last_fetch) >= _THROTTLE_MAX_HOSTS:
        # Many distinct hosts inside one window: drop the oldest half.
        for known in list(_last_fetch)[: _THROTTLE_MAX_HOSTS // 2]:
            del _last_fetch[known]
    wait = SCRAPE_THROTTLE_SECONDS - (now - _last_fetch.get(host, 0.0))
    if wait <= 0:
        # Another process may have fetched recently; the DB row decides.
        try:
            wait = _try_claim_db_throttle(host)
        except Exception:  # noqa: BLE001 - DB hiccup must not break scraping
            wait = 0.0
    if wait > 0:
        time.sleep(wait)
        try:
            _record_db_throttle(host)
        except Exception:  # noqa: BLE001
            log.debug("throttle record failed for %s", host)
    _last_fetch[host] = time.monotonic()


@dataclass(frozen=True)
class _Candidate:
    """Match-relevant finding columns; avoids ORM-loading every finding per item."""

    id: int
    advisory_id: str
    aliases: tuple[str, ...]
    package: str


def _strong_match(cves: list[str], finding: _Candidate) -> str | None:
    """CVE ID equal to the advisory or one of its aliases."""
    known = {(finding.advisory_id or "").upper()}
    known.update(str(a).upper() for a in (finding.aliases or []))
    for cve in cves:
        if cve in known:
            return cve
    return None


def _weak_match(title: str | None, summary: str | None, finding: _Candidate) -> str | None:
    """Package name mentioned in title/summary (whole token, case-insensitive)."""
    package = (finding.package or "").lower()
    text = f"{title or ''}\n{summary or ''}".lower()
    if not package:
        return None
    if "/" in package:
        hit = package in text
    else:
        hit = re.search(rf"\b{re.escape(package)}\b", text) is not None
    return f"package:{finding.package}" if hit else None


def _refresh_finding(db, finding_id: int) -> None:
    """Denormalize the strongest boost onto the finding for ordering/badges."""
    top = db.scalar(
        select(NewsBoost)
        .where(NewsBoost.finding_id == finding_id)
        .order_by(NewsBoost.weight.desc(), NewsBoost.id.desc())
        .limit(1)
    )
    row = db.get(Finding, finding_id)
    if row is None:
        return
    if top is None:
        row.news_weight = 0
        row.news_url = None
        return
    item = db.get(NewsItem, top.news_item_id)
    row.news_weight = top.weight
    row.news_url = item.url if item else None


_SCRAPE_TEXT_MARKERS = ("text/", "html", "xml", "json")


def _assert_textual_response(resp: httpx.Response, host: str) -> None:
    """Refuse binary payloads; a missing content-type is allowed (lenient)."""
    ctype = (resp.headers.get("content-type") or "").lower()
    if ctype and not any(marker in ctype for marker in _SCRAPE_TEXT_MARKERS):
        raise FeedError(f"refusing to scrape {ctype} from {host}")


def _html_to_text(html: str) -> str:
    """Strip script/style blocks (code must not yield CVE hits), then tags."""
    without_code = re.sub(
        r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.DOTALL | re.IGNORECASE
    )
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", without_code)).strip()


def scrape_article(url: str) -> str:
    """Fetch an article body as plain text. Raises on any failure.

    Polite by construction: http(s) only, public addresses only, bot UA,
    timeout, streaming size cap, text content only, and a per-host
    throttle gap. Every redirect hop is re-validated.
    """
    host, _ips = _validated_ips(url)
    _throttle_wait(host)
    current = url
    for _ in range(_MAX_REDIRECTS + 1):
        hop_host, hop_ips = _validated_ips(current)
        if hop_host != host:
            _throttle_wait(hop_host)  # redirect hops are throttled too (#8)
        with _http_stream(
            "GET",
            current,
            timeout=SCRAPE_TIMEOUT,
            headers={"User-Agent": _USER_AGENT},
            ips=hop_ips,
        ) as resp:
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                if not location:
                    raise FeedError(f"redirect from {hop_host} lacks a Location header")
                current = urljoin(current, location)
                continue
            resp.raise_for_status()
            _assert_textual_response(resp, hop_host)
            return _html_to_text(_read_capped_text(resp, hop_host, SCRAPE_MAX_BYTES))
    raise FeedError(f"too many redirects scraping {url[:100]}")


def enrich_item(item_id: int) -> bool:
    """Scrape the linked article when the item has no CVE IDs. Returns scraped.

    Failures degrade silently: the item is marked attempted (empty
    excerpt) so a dead link is not refetched on every matcher run.
    """
    with session_scope() as db:
        item = db.get(NewsItem, item_id)
        if item is None or (item.cve_ids or []) or not item.url or item.body_excerpt is not None:
            return False
        url = item.url
    try:
        body = scrape_article(url)
    except Exception as exc:  # noqa: BLE001 - scrape is best-effort by design
        log.debug("article scrape failed for item %d: %s", item_id, exc)
        with session_scope() as db:
            row = db.get(NewsItem, item_id)
            if row is not None:
                row.body_excerpt = ""
        return False
    with session_scope() as db:
        row = db.get(NewsItem, item_id)
        if row is None:
            return False
        row.body_excerpt = body[:EXCERPT_CHARS]
        row.cve_ids = extract_cve_ids(body)
        return True


@dataclass(frozen=True)
class _MatchIndex:
    """Per-run candidate index (follow-up #5): built once, not per item."""

    by_advisory: dict[str, tuple[_Candidate, ...]]
    by_package: dict[str, tuple[_Candidate, ...]]
    all_candidates: tuple[_Candidate, ...]


def _build_match_index(db) -> _MatchIndex:
    candidates = [
        _Candidate(
            id=row[0],
            advisory_id=row[1] or "",
            aliases=tuple(row[2] or []),
            package=row[3] or "",
        )
        for row in db.execute(
            select(Finding.id, Finding.advisory_id, Finding.aliases, Finding.package).where(
                Finding.status.in_([FindingStatus.OPEN, FindingStatus.PROPOSED])
            )
        ).all()
    ]
    by_advisory: dict[str, list[_Candidate]] = {}
    by_package: dict[str, list[_Candidate]] = {}
    for cand in candidates:
        for key in {(cand.advisory_id or "").upper(), *(str(a).upper() for a in cand.aliases)}:
            if key:
                by_advisory.setdefault(key, []).append(cand)
        if cand.package:
            by_package.setdefault(cand.package.lower(), []).append(cand)
    return _MatchIndex(
        by_advisory={k: tuple(v) for k, v in by_advisory.items()},
        by_package={k: tuple(v) for k, v in by_package.items()},
        all_candidates=tuple(candidates),
    )


def match_item(item_id: int, *, index: _MatchIndex | None = None) -> int:
    """Match one news item against queue-visible findings. Returns new boosts.

    Rumor-only items (no Tier-1 finding) match nothing and change nothing;
    a boost alone can never trigger action.
    """
    enrich_item(item_id)  # no-op unless CVE-less with an unscraped URL
    with session_scope() as db:
        item = db.get(NewsItem, item_id)
        if item is None:
            return 0
        cves = [str(c).upper() for c in (item.cve_ids or [])]
        title, summary, item_id_value = item.title, item.summary, item.id
        if index is None:
            index = _build_match_index(db)
        # Strong candidates come from the advisory index; weak matching
        # tests each distinct package once, never items x findings.
        strong_ids = {c.id for cve in cves for c in index.by_advisory.get(cve, ())}
        weak_ids = {
            c.id
            for cands in index.by_package.values()
            if _weak_match(title, summary, cands[0]) is not None
            for c in cands
        }
        candidates = [c for c in index.all_candidates if c.id in strong_ids | weak_ids]
        new = 0
        for finding in candidates:
            matched = _strong_match(cves, finding)
            weight = STRONG_WEIGHT
            if matched is None:
                matched = _weak_match(title, summary, finding)
                weight = WEAK_WEIGHT
            if matched is None:
                continue
            try:
                with db.begin_nested():
                    db.add(
                        NewsBoost(
                            finding_id=finding.id,
                            news_item_id=item_id_value,
                            weight=weight,
                            matched_on=matched[:200],
                        )
                    )
                    db.flush()
            except IntegrityError:
                _upgrade_boost(db, finding.id, item_id_value, weight, matched)
                continue
            new += 1
            _refresh_finding(db, finding.id)
        return new


def _upgrade_boost(db, finding_id: int, item_id: int, weight: int, matched: str) -> None:
    """Raise an existing weak boost when the same item later matches strongly."""
    existing = db.scalar(
        select(NewsBoost).where(
            NewsBoost.finding_id == finding_id, NewsBoost.news_item_id == item_id
        )
    )
    if existing is not None and existing.weight < weight:
        existing.weight = weight
        existing.matched_on = matched[:200]
        _refresh_finding(db, finding_id)


def run_matcher() -> dict[str, int]:
    """Match every stored item; re-runs are idempotent via the boost key."""
    with session_scope() as db:
        ids = [i for (i,) in db.execute(select(NewsItem.id)).all()]
        index = _build_match_index(db)
    return {"items": len(ids), "boosts": sum(match_item(i, index=index) for i in ids)}


def poll_news() -> dict[str, int]:
    """Poll due sources; failures are logged per source, never fatal.

    Attempts are recorded (even failed ones, with zero items) so a dead
    source backs off to the hourly cadence instead of hammering every tick.
    """
    settings = get_settings()
    hours = settings.news_poll_hours
    counts: dict[str, int] = {}
    if poll_due("hn", hours=hours):
        try:
            counts["hn"] = store_news_items(fetch_hn_stories(settings.news_hn_query))
        except Exception as exc:  # noqa: BLE001 - one bad source never fails the poll
            log.warning("HN poll failed: %s", exc)
            counts["hn"] = 0
        _record_poll("hn", counts["hn"])
    feeds = list(dict.fromkeys(f.strip() for f in settings.news_rss_feeds.split(",")))
    feeds = [f for f in feeds if f]
    rss_total = 0
    rss_polled = False
    for feed_url in feeds:
        source = _feed_source(feed_url)
        if not poll_due(source, hours=hours):
            continue
        rss_polled = True
        try:
            stored = store_news_items(fetch_feed_items(feed_url))
        except Exception as exc:  # noqa: BLE001 - one bad feed never fails the poll
            log.warning("RSS poll failed for %s: %s", feed_url, exc)
            stored = 0
        rss_total += stored
        _record_poll(source, stored)
    if rss_polled:
        counts["rss"] = rss_total
    return counts
