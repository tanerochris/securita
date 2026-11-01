"""H3 slice A: relevance ordering (no news join) + news retention."""

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


def test_severity_orders_without_news_join():
    repo = repos.connect_repo("news-ord", RepoKind.GIT, url="https://example.com/n.git")
    low = _seed_finding(repo.id, "CVE-PLAIN", severity_score=5.0)
    high = _seed_finding(repo.id, "CVE-HIGH", severity_score=9.0)
    ordered = [f.id for f in list_open_findings(repo.id)]
    assert ordered.index(high) < ordered.index(low)


def test_purge_old_news_drops_stale_items_and_legacy_boosts():
    repo = repos.connect_repo("news-purge", RepoKind.GIT, url="https://example.com/p.git")
    fid = _seed_finding(repo.id, "CVE-OLD")
    old = _seed_item(title="old", url="https://news.example/old")
    with session_scope() as db:
        db.add(NewsBoost(finding_id=fid, news_item_id=old, weight=100, matched_on="CVE-OLD"))
        db.get(NewsItem, old).fetched_at = datetime.now(UTC) - timedelta(days=91)
    assert purge_old_news() == 1
    with session_scope() as db:
        assert db.get(NewsItem, old) is None
        assert db.scalar(select(NewsBoost).where(NewsBoost.finding_id == fid)) is None
        assert db.get(Finding, fid) is not None  # findings never purged with news
    fresh = _seed_item(title="fresh")
    assert purge_old_news() == 0
    with session_scope() as db:
        assert db.get(NewsItem, fresh) is not None


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
