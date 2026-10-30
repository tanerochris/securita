"""H3 slice F: news-booster validation.

Known-discussed CVE rises with a link; rumor-only input yields no patch.
HN traffic is replayed from the recorded slice-B fixture (no network).
"""

from pathlib import Path
from unittest import mock

from sqlalchemy import select

from security_agent.control import repos as repo_svc
from security_agent.control.lifecycle import list_open_findings
from security_agent.db.models import Finding, NewsBoost, Proposal, RepoKind
from security_agent.db.session import session_scope
from security_agent.worker import build_graph
from security_agent.worker import news as news_mod

HN_FIXTURE = Path(__file__).parent.parent / "unit" / "fixtures" / "hn-recorded.json"


def _hn_http():
    content = HN_FIXTURE.read_bytes()
    resp = mock.Mock()
    resp.status_code = 200
    resp.headers = {"content-type": "application/json"}
    resp.charset_encoding = "utf-8"
    resp.iter_bytes = lambda chunk_size=65536: (
        content[i : i + chunk_size] for i in range(0, len(content), chunk_size)
    )
    resp.raise_for_status.return_value = None
    stream = mock.MagicMock()
    stream.__enter__.return_value = resp
    stream.__exit__.return_value = False
    return stream


def _finding(repo_id: int, advisory: str) -> int:
    with session_scope() as db:
        row = Finding(
            repo_id=repo_id,
            package="left-pad",
            installed_version="1.0.0",
            advisory_id=advisory,
            severity_score=5.0,
        )
        db.add(row)
        db.flush()
        return row.id


def _poll_and_match():
    settings = mock.Mock(news_hn_query="CVE", news_rss_feeds="", news_poll_hours=0.0)
    with (
        mock.patch.object(news_mod, "get_settings", return_value=settings),
        mock.patch.object(news_mod, "_http_stream", return_value=_hn_http()),
        mock.patch.object(news_mod, "_assert_public_url", return_value="hn.algolia.com"),
        mock.patch.object(
            news_mod, "_validated_ips", return_value=("hn.algolia.com", ("93.184.216.34",))
        ),
    ):
        news_mod.poll_news()
    with (
        mock.patch.object(news_mod, "_assert_public_url", return_value="news.example"),
        mock.patch.object(
            news_mod, "_validated_ips", return_value=("news.example", ("93.184.216.34",))
        ),
        # Scrape fallback stays hermetic: dead links degrade to rumor-only.
        mock.patch.object(news_mod, "_http_stream", side_effect=RuntimeError("no network")),
    ):
        return news_mod.run_matcher()


def test_known_discussed_cve_rises_with_link():
    repo = repo_svc.connect_repo("h3-rise", RepoKind.GIT, url="https://example.com/h3.git")
    plain = _finding(repo.id, "CVE-2026-000099")
    discussed = _finding(repo.id, "CVE-2026-10001")  # in the recorded HN fixture
    summary = _poll_and_match()
    assert summary["boosts"] >= 1
    with session_scope() as db:
        row = db.get(Finding, discussed)
        assert row.news_weight == 100
        assert row.news_url == "https://example.com/advisory/left-pad"
    ordered = [f.id for f in list_open_findings(repo.id)]
    assert ordered.index(discussed) < ordered.index(plain)


def test_rumor_only_yields_no_patch():
    from security_agent.worker import patch as patch_mod

    repo = repo_svc.connect_repo("h3-rumor", RepoKind.GIT, url="https://example.com/hr.git")
    with session_scope() as db:
        from security_agent.db.models import ScanRun

        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    summary = _poll_and_match()  # fixture CVEs match no finding in this repo
    assert summary["items"] >= 1
    result = patch_mod.run_patch(repo.id, run_id)
    assert result["proposal_ids"] == []
    with session_scope() as db:
        assert db.scalar(select(Proposal).where(Proposal.repo_id == repo.id)) is None
        assert (  # boosts may exist globally from other tests; none for this repo
            db.scalar(
                select(NewsBoost).where(
                    NewsBoost.finding_id.in_(select(Finding.id).where(Finding.repo_id == repo.id))
                )
            )
            is None
        )


def test_graph_fetch_signals_polls_and_matches():
    with (
        mock.patch.object(news_mod, "poll_news", return_value={"hn": 1}) as fake_poll,
        mock.patch.object(
            news_mod, "run_matcher", return_value={"items": 1, "boosts": 0}
        ) as fake_match,
    ):
        result = build_graph().invoke({"repo": "demo"})
    fake_poll.assert_called_once_with()
    fake_match.assert_called_once_with()
    assert result["done"][0] == "fetch_signals"
