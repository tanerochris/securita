"""H3 slice C: stack matcher (strong/weak boosts, rumor-only silent)."""

from datetime import UTC, datetime
from unittest import mock

import pytest
from sqlalchemy import select

from security_agent.control import repos
from security_agent.db.models import Finding, FindingStatus, NewsBoost, NewsItem, RepoKind
from security_agent.db.session import session_scope
from security_agent.worker import news as news_mod
from security_agent.worker.news import match_item, run_matcher


@pytest.fixture(autouse=True)
def _no_scrape():
    """Slice C behavior: the scrape hook (slice E) stays out of matcher tests."""
    with mock.patch.object(news_mod, "enrich_item", return_value=False):
        yield


def _repo(tag: str) -> int:
    return repos.connect_repo(tag, RepoKind.GIT, url=f"https://example.com/{tag}.git").id


def _finding(repo_id: int, advisory: str, **fields) -> int:
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


def _item(
    title: str,
    cves: list[str],
    url: str | None = "https://news.example/x",
    summary: str | None = None,
) -> int:
    with session_scope() as db:
        row = NewsItem(
            source="hn",
            external_id=f"m-{datetime.now(UTC).timestamp()}",
            url=url,
            title=title,
            summary=summary,
            cve_ids=cves,
        )
        db.add(row)
        db.flush()
        return row.id


def _boosts(fid: int) -> list:
    with session_scope() as db:
        return list(db.scalars(select(NewsBoost).where(NewsBoost.finding_id == fid)))


def test_strong_match_on_advisory_and_alias():
    repo_id = _repo("match-s")
    direct = _finding(repo_id, "CVE-2026-11111")
    aliased = _finding(repo_id, "OSV-2026-9", aliases=["cve-2026-11111"])
    item = _item("CVE-2026-11111: RCE", ["CVE-2026-11111"])
    assert match_item(item) == 2
    assert [(b.weight, b.matched_on) for b in _boosts(direct)] == [(100, "CVE-2026-11111")]
    assert [(b.weight, b.matched_on) for b in _boosts(aliased)] == [(100, "CVE-2026-11111")]
    with session_scope() as db:
        row = db.get(Finding, direct)
        assert (row.news_weight, row.news_url) == (100, "https://news.example/x")


def test_weak_match_on_package_mention():
    repo_id = _repo("match-w")
    fid = _finding(repo_id, "CVE-2026-55555")
    item = _item("left-pad 1.0.0 yanked from registry", [])
    assert match_item(item) >= 1  # other tests' left-pad findings match too
    assert [(b.weight, b.matched_on) for b in _boosts(fid)] == [(10, "package:left-pad")]


def test_weak_match_on_summary_mention():
    repo_id = _repo("match-ws")
    fid = _finding(repo_id, "CVE-2026-55556")
    item = _item("Vendor postmortem", [], summary="Root cause: left-pad 1.0.0 behavior.")
    assert match_item(item) >= 1
    assert [(b.weight, b.matched_on) for b in _boosts(fid)] == [(10, "package:left-pad")]


def test_weak_boost_upgrades_to_strong():
    repo_id = _repo("match-up")
    fid = _finding(repo_id, "CVE-2026-99998")
    item = _item("left-pad drama", [])
    assert match_item(item) >= 1
    assert [(b.weight, b.matched_on) for b in _boosts(fid)] == [(10, "package:left-pad")]
    with session_scope() as db:
        db.get(NewsItem, item).cve_ids = ["CVE-2026-99998"]
    assert match_item(item) == 0  # no new row, but the weak boost upgrades
    assert [(b.weight, b.matched_on) for b in _boosts(fid)] == [(100, "CVE-2026-99998")]
    with session_scope() as db:
        row = db.get(Finding, fid)
        assert (row.news_weight, row.news_url) == (100, "https://news.example/x")


def test_no_match_for_silent_findings_and_rumors():
    repo_id = _repo("match-r")
    silent = _finding(repo_id, "CVE-2026-77777", status=FindingStatus.SILENT)
    assert match_item(_item("CVE-2026-77777 discussed", ["CVE-2026-77777"])) == 0
    assert match_item(_item("CVE-99999-99999 rumor", ["CVE-99999-99999"])) == 0
    assert _boosts(silent) == []
    with session_scope() as db:
        assert db.get(Finding, silent).news_weight == 0


def test_strong_beats_weak_and_reruns_idempotent():
    repo_id = _repo("match-b")
    fid = _finding(repo_id, "CVE-2026-88888")
    weak = _item("left-pad drama", [], url="https://news.example/weak")
    strong = _item(
        "CVE-2026-88888 confirmed", ["CVE-2026-88888"], url="https://news.example/strong"
    )
    assert match_item(weak) >= 1
    assert match_item(strong) >= 1
    assert sorted(b.weight for b in _boosts(fid)) == [10, 100]
    with session_scope() as db:
        row = db.get(Finding, fid)
        assert (row.news_weight, row.news_url) == (100, "https://news.example/strong")
    run_matcher()  # backfills older items against newer findings
    assert run_matcher()["boosts"] == 0  # then idempotent
