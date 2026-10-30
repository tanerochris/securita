"""H3 slice A: boost-aware ordering + news retention."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from security_agent.control import repos
from security_agent.control.lifecycle import list_open_findings, purge_old_news, purge_old_polls
from security_agent.db.models import Finding, NewsBoost, NewsItem, NewsPoll, RepoKind
from security_agent.db.session import session_scope


def _seed_finding(repo_id: int, advisory: str, **fields) -> int:
    with session_scope() as db:
        row = Finding(
            repo_id=repo_id,
            package="left-pad",
            installed_version="1.0.0",
            advisory_id=advisory,
            **fields,
        )
        db.add(row)
        db.flush()
        return row.id


def _seed_item(**fields) -> int:
    with session_scope() as db:
        row = NewsItem(source="hn", external_id=f"e-{datetime.now(UTC).timestamp()}", **fields)
        db.add(row)
        db.flush()
        return row.id


def test_boost_breaks_ties_after_severity():
    repo = repos.connect_repo("news-ord", RepoKind.GIT, url="https://example.com/n.git")
    plain = _seed_finding(repo.id, "CVE-PLAIN", severity_score=5.0)
    boosted = _seed_finding(repo.id, "CVE-BOOST", severity_score=5.0)
    item = _seed_item(title="CVE-BOOST discussed", url="https://news.example/1")
    with session_scope() as db:
        db.add(NewsBoost(finding_id=boosted, news_item_id=item, weight=100, matched_on="CVE-BOOST"))
        row = db.get(Finding, boosted)
        row.news_weight = 100
        row.news_url = "https://news.example/1"
    ordered = [f.id for f in list_open_findings(repo.id)]
    assert ordered.index(boosted) < ordered.index(plain)


def test_purge_old_news_recomputes_findings():
    repo = repos.connect_repo("news-purge", RepoKind.GIT, url="https://example.com/p.git")
    fid = _seed_finding(repo.id, "CVE-OLD", news_weight=100, news_url="https://news.example/old")
    old = _seed_item(title="old", url="https://news.example/old")
    with session_scope() as db:
        db.add(NewsBoost(finding_id=fid, news_item_id=old, weight=100, matched_on="CVE-OLD"))
        db.get(NewsItem, old).fetched_at = datetime.now(UTC) - timedelta(days=91)
    assert purge_old_news() == 1
    with session_scope() as db:
        row = db.get(Finding, fid)
        assert (row.news_weight, row.news_url) == (0, None)
        assert db.scalar(select(NewsBoost).where(NewsBoost.finding_id == fid)) is None
    fresh = _seed_item(title="fresh")
    with session_scope() as db:
        db.add(NewsBoost(finding_id=fid, news_item_id=fresh, weight=10, matched_on="left-pad"))
    assert purge_old_news() == 0


def test_purge_old_polls_removes_stale_rows():
    with session_scope() as db:
        stale = NewsPoll(source=f"stale-{datetime.now(UTC).timestamp()}", items=0)
        db.add(stale)
        db.flush()
        stale_id = stale.id
        stale.finished_at = datetime.now(UTC) - timedelta(days=91)
    assert purge_old_polls() == 1
    with session_scope() as db:
        assert db.get(NewsPoll, stale_id) is None
