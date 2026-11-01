"""H3 slice F: news-intel validation.

Classified-major stories with OSV-verified CVEs mint findings in repos
carrying the package; rumor-only input mints nothing and patches nothing.
HN traffic is replayed from the recorded slice-B fixture (no network).
"""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sqlalchemy import select

from security_agent.control import repos as repo_svc
from security_agent.db.models import Finding, Proposal, RepoKind
from security_agent.db.session import session_scope
from security_agent.worker import build_graph
from security_agent.worker import news as news_mod
from security_agent.worker import news_intel as intel_mod

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


class _FakeModel:
    def __init__(self, content: str):
        self._content = content

    def invoke(self, prompt: str):
        return SimpleNamespace(content=self._content, usage_metadata={})


def _finding(repo_id: int, package: str, advisory: str) -> int:
    with session_scope() as db:
        row = Finding(
            repo_id=repo_id,
            package=package,
            installed_version="1.0.0",
            advisory_id=advisory,
            severity_score=5.0,
        )
        db.add(row)
        db.flush()
        return row.id


def _poll():
    settings = mock.Mock(news_hn_query="CVE", news_rss_feeds="", news_poll_hours=0.0)
    with (
        mock.patch.object(news_mod, "get_settings", return_value=settings),
        mock.patch.object(news_mod, "_http_stream", return_value=_hn_http()),
        mock.patch.object(news_mod, "_assert_public_url", return_value="hn.algolia.com"),
        mock.patch.object(
            news_mod, "_validated_ips", return_value=("hn.algolia.com", ("93.184.216.34",))
        ),
    ):
        return news_mod.poll_news()


def _process(verdict: str, verified):
    settings = mock.Mock(
        news_classify_enabled=True, news_classify_max_items=100, news_mint_enabled=True
    )
    model = _FakeModel(json.dumps({"verdict": verdict, "category": "vulnerability"}))
    with (
        mock.patch.object(intel_mod, "get_settings", return_value=settings),
        mock.patch("security_agent.brain.get_chat_model", return_value=model),
        mock.patch.object(news_mod, "enrich_item", return_value=False),
        mock.patch.object(intel_mod, "verify_advisory", return_value=verified),
        mock.patch.object(intel_mod, "kev_exploited_ids", return_value=set()),
    ):
        return intel_mod.process_news()


def test_major_verified_story_mints_finding_in_carrying_repo():
    repo = repo_svc.connect_repo("h3-mint", RepoKind.GIT, url="https://example.com/h3.git")
    _finding(repo.id, "left-pad", "CVE-SEED-H3")
    assert _poll()["hn"] >= 1
    verified = {
        "cve": "CVE-2026-10001",
        "severity": 9.8,
        "affected": [("npm", "left-pad", ["1.0.1"])],
    }
    summary = _process("major", verified)
    assert summary["major"] >= 1 and summary["minted"] >= 1
    with session_scope() as db:
        minted = db.scalar(
            select(Finding).where(
                Finding.repo_id == repo.id, Finding.advisory_id == "CVE-2026-10001"
            )
        )
        assert minted is not None
        assert minted.provenance == "news"
        assert minted.package == "left-pad"
        assert "https://example.com/advisory/left-pad" in (minted.citations or [])


def test_rumor_only_yields_no_patch():
    from security_agent.worker import patch as patch_mod

    repo = repo_svc.connect_repo("h3-rumor", RepoKind.GIT, url="https://example.com/hr.git")
    with session_scope() as db:
        from security_agent.db.models import ScanRun

        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    _poll()  # fixture stories stored; nothing classified major here
    summary = _process("not_security", None)
    assert summary["minted"] == 0
    result = patch_mod.run_patch(repo.id, run_id)
    assert result["proposal_ids"] == []
    with session_scope() as db:
        assert db.scalar(select(Proposal).where(Proposal.repo_id == repo.id)) is None
        assert (
            db.scalar(
                select(Finding).where(Finding.repo_id == repo.id, Finding.provenance == "news")
            )
            is None
        )


def test_graph_fetch_signals_polls_and_processes():
    with (
        mock.patch.object(news_mod, "poll_news", return_value={"hn": 1}) as fake_poll,
        mock.patch.object(
            intel_mod,
            "process_news",
            return_value={"classified": 1, "major": 0, "minted": 0, "linked": 0},
        ) as fake_process,
    ):
        result = build_graph().invoke({"repo": "demo"})
    fake_poll.assert_called_once_with()
    fake_process.assert_called_once_with()
    assert result["done"][0] == "fetch_signals"
