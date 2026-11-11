"""Standalone news intel: strict classification + OSV-verified minting."""

import json
import uuid
from types import SimpleNamespace
from unittest import mock

import pytest
from sqlalchemy import select

from security_agent.control import repos
from security_agent.db.models import Finding, NewsFindingLink, NewsItem, RepoKind
from security_agent.db.session import session_scope
from security_agent.worker import news_intel as intel_mod
from security_agent.worker.news_intel import (
    classify_item,
    classify_pending,
    list_feed,
    list_repo_news,
    mint_from_item,
    process_news,
    repo_tags,
    verify_advisory,
)


class _FakeModel:
    """Chat model stub: canned content, char-estimated usage via tracked_invoke."""

    prompts: list = []

    def __init__(self, content: str):
        self._content = content

    def invoke(self, prompt: str):
        _FakeModel.prompts.append(prompt)
        return SimpleNamespace(content=self._content, usage_metadata={})


def _seed_item(**fields) -> int:
    with session_scope() as db:
        row = NewsItem(
            source="hn",
            external_id=f"intel-{uuid.uuid4().hex}",
            title=fields.pop("title", "story"),
            **fields,
        )
        db.add(row)
        db.flush()
        return row.id


def _seed_package(repo_id: int, package: str, advisory: str = "CVE-SEED") -> int:
    with session_scope() as db:
        row = Finding(
            repo_id=repo_id,
            package=package,
            installed_version="1.0.0",
            advisory_id=advisory,
        )
        db.add(row)
        db.flush()
        return row.id


def _osv_record(package: str, fixed: str = "1.0.1") -> dict:
    return {
        "severity": [{"type": "CVSS_V3", "score": 9.8}],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": package},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
            }
        ],
    }


# --- Verdict parsing (fail closed) ---


def test_parse_verdict_accepts_plain_and_fenced_json():
    assert intel_mod._parse_verdict('{"verdict": "major", "category": "breach"}') == (
        "major",
        "breach",
    )
    assert intel_mod._parse_verdict('```json\n{"verdict": "minor", "category": "patch"}\n```') == (
        "minor",
        "patch",
    )


def test_parse_verdict_rejects_garbage_and_bad_enums():
    assert intel_mod._parse_verdict("major, obviously") is None
    assert intel_mod._parse_verdict('["major"]') is None
    assert intel_mod._parse_verdict('{"verdict": "huge", "category": "breach"}') is None
    assert intel_mod._parse_verdict('{"verdict": "major", "category": "gossip"}') is None
    assert intel_mod._parse_verdict('{"verdict": "major"}') is None


def test_prompt_sets_strict_bar():
    prompt = intel_mod._classify_prompt("t", "s", "e")
    assert "personal blog" in prompt
    assert "not_security" in prompt
    assert "headline" in prompt


# --- Classification ---


def test_classify_item_stores_verdict_and_category():
    item = _seed_item(
        title="Critical RCE exploited in the wild",
        summary="widely used library",
        body_excerpt="CVE-2026-0001 ...",
        cve_ids=["CVE-2026-0001"],
    )
    model = _FakeModel(json.dumps({"verdict": "major", "category": "exploit"}))
    assert classify_item(item, model=model) == "major"
    with session_scope() as db:
        row = db.get(NewsItem, item)
        assert (row.verdict, row.category) == ("major", "exploit")
        assert row.classified_at is not None


def test_classify_item_raises_brain_error_but_garbage_stays_closed():
    from security_agent.brain import BrainError

    bad_model = mock.Mock()
    bad_model.invoke.side_effect = RuntimeError("model down")
    item = _seed_item(title="x", body_excerpt="y")
    with pytest.raises(BrainError, match="Brain call failed"):
        classify_item(item, model=bad_model)
    garbage = _seed_item(title="x", body_excerpt="y")
    assert classify_item(garbage, model=_FakeModel("not json")) is None
    with session_scope() as db:
        assert db.get(NewsItem, item).verdict is None
        assert db.get(NewsItem, garbage).verdict is None


def test_classify_item_skips_already_classified():
    item = _seed_item(title="x", body_excerpt="y")
    with session_scope() as db:
        row = db.get(NewsItem, item)
        row.verdict, row.category = "minor", "patch"
    model = mock.Mock()
    assert classify_item(item, model=model) == "minor"
    model.invoke.assert_not_called()


def test_classify_pending_bounds_and_counts():
    items = [_seed_item(title=f"pending-{i}", body_excerpt="e") for i in range(3)]
    model = _FakeModel(json.dumps({"verdict": "major", "category": "leak"}))
    with mock.patch("security_agent.brain.get_chat_model", return_value=model):
        assert classify_pending(limit=1) == {"classified": 1, "major": 1}
        counts = classify_pending(limit=1000)
    assert counts["classified"] >= 3 and counts["major"] == counts["classified"]
    with session_scope() as db:
        for item in items:
            assert db.get(NewsItem, item).verdict == "major"


# --- OSV verification ---


def _http_response(status: int, payload: dict | None = None):
    resp = mock.Mock()
    resp.status_code = status
    resp.json.return_value = payload
    return resp


def test_verify_advisory_parses_affected_packages():
    package = f"intel-pkg-{uuid.uuid4().hex[:8]}"
    with mock.patch.object(
        intel_mod.httpx, "get", return_value=_http_response(200, _osv_record(package))
    ) as fake:
        verified = verify_advisory("cve-2026-0001")
    assert fake.call_args[0][0] == "https://api.osv.dev/v1/vulns/CVE-2026-0001"
    assert verified is not None
    assert verified["cve"] == "CVE-2026-0001"
    assert verified["severity"] == 9.8
    assert verified["affected"] == [("npm", package, ["1.0.1"])]


def test_verify_advisory_unknown_or_malformed_never_fetches():
    with mock.patch.object(intel_mod.httpx, "get", return_value=_http_response(404, None)) as fake:
        assert verify_advisory("CVE-2026-0001") is None
        assert fake.call_count == 1
    with mock.patch.object(intel_mod.httpx, "get") as fake:
        assert verify_advisory("CVE-XXXX") is None
        assert verify_advisory("not a cve; DROP TABLE") is None
        fake.assert_not_called()


def test_verify_advisory_propagates_transient_errors():
    with mock.patch.object(intel_mod.httpx, "get", side_effect=TimeoutError("osv down")):
        try:
            verify_advisory("CVE-2026-0001")
        except TimeoutError:
            pass
        else:
            raise AssertionError("transient OSV errors must propagate for retry")


# --- Minting ---


def test_mint_from_item_creates_per_repo_findings():
    package = f"mint-pkg-{uuid.uuid4().hex[:8]}"
    repo = repos.connect_repo(f"mint-{package}", RepoKind.GIT, url="https://example.com/m.git")
    _seed_package(repo.id, package)
    item = _seed_item(
        title="major vuln",
        url="https://news.example/major",
        cve_ids=["CVE-2026-0001"],
    )
    with session_scope() as db:
        row = db.get(NewsItem, item)
        row.verdict, row.category = "major", "vulnerability"
    verified = {"cve": "CVE-2026-0001", "severity": 9.8, "affected": [("npm", package, ["9.9.9"])]}
    with (
        mock.patch.object(intel_mod, "verify_advisory", return_value=verified),
        mock.patch.object(intel_mod, "kev_exploited_ids", return_value=set()),
    ):
        assert mint_from_item(item) == {"minted": 1, "linked": 0}
    with session_scope() as db:
        minted = db.scalar(
            select(Finding).where(
                Finding.repo_id == repo.id,
                Finding.package == package,
                Finding.advisory_id == "CVE-2026-0001",
            )
        )
        assert minted is not None
        assert minted.provenance == "news"
        assert minted.installed_version == ""
        assert minted.fixed_versions == ["9.9.9"]
        assert minted.severity_score == 9.8
        assert "https://news.example/major" in (minted.citations or [])
        assert any("osv.dev" in c for c in (minted.citations or []))
        assert db.get(NewsItem, item).minted_at is not None
    # Second pass is a no-op (minted marker), never a duplicate.
    with (
        mock.patch.object(intel_mod, "verify_advisory", return_value=verified),
        mock.patch.object(intel_mod, "kev_exploited_ids", return_value=set()),
    ):
        assert mint_from_item(item) == {"minted": 0, "linked": 0}


def test_mint_from_item_links_existing_finding_instead_of_duplicating():
    package = f"dup-pkg-{uuid.uuid4().hex[:8]}"
    repo = repos.connect_repo(f"dup-{package}", RepoKind.GIT, url="https://example.com/d.git")
    _seed_package(repo.id, package, advisory="CVE-2026-0002")
    item = _seed_item(title="major vuln", url="https://news.example/dup", cve_ids=["CVE-2026-0002"])
    with session_scope() as db:
        db.get(NewsItem, item).verdict = "major"
    verified = {"cve": "CVE-2026-0002", "severity": None, "affected": [("npm", package, [])]}
    with (
        mock.patch.object(intel_mod, "verify_advisory", return_value=verified),
        mock.patch.object(intel_mod, "kev_exploited_ids", return_value=set()),
    ):
        assert mint_from_item(item) == {"minted": 0, "linked": 1}
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(Finding).where(
                    Finding.repo_id == repo.id,
                    Finding.package == package,
                    Finding.advisory_id == "CVE-2026-0002",
                )
            )
        )
        assert len(rows) == 1
        assert "https://news.example/dup" in (rows[0].citations or [])


def test_mint_from_item_skips_unqualified_items():
    package = f"skip-pkg-{uuid.uuid4().hex[:8]}"
    repo = repos.connect_repo(f"skip-{package}", RepoKind.GIT, url="https://example.com/s.git")
    _seed_package(repo.id, package)
    unclassified = _seed_item(title="u", cve_ids=["CVE-2026-0003"])
    minor = _seed_item(title="m", cve_ids=["CVE-2026-0003"])
    no_cve = _seed_item(title="n", cve_ids=[])
    with session_scope() as db:
        db.get(NewsItem, minor).verdict = "minor"
        db.get(NewsItem, no_cve).verdict = "major"
    with mock.patch.object(intel_mod, "verify_advisory") as fake:
        assert mint_from_item(unclassified) == {"minted": 0, "linked": 0}
        assert mint_from_item(minor) == {"minted": 0, "linked": 0}
        assert mint_from_item(no_cve) == {"minted": 0, "linked": 0}
        fake.assert_not_called()


def test_mint_from_item_unknown_cve_mints_nothing():
    package = f"unk-pkg-{uuid.uuid4().hex[:8]}"
    repo = repos.connect_repo(f"unk-{package}", RepoKind.GIT, url="https://example.com/u.git")
    _seed_package(repo.id, package)
    item = _seed_item(title="rumor", cve_ids=["CVE-2026-99999"])
    with session_scope() as db:
        db.get(NewsItem, item).verdict = "major"
    with (
        mock.patch.object(intel_mod, "verify_advisory", return_value=None),
        mock.patch.object(intel_mod, "kev_exploited_ids", return_value=set()),
    ):
        assert mint_from_item(item) == {"minted": 0, "linked": 0}
    with session_scope() as db:
        assert (
            db.scalar(
                select(Finding).where(
                    Finding.repo_id == repo.id, Finding.advisory_id == "CVE-2026-99999"
                )
            )
            is None
        )


def test_mint_from_item_transient_osv_error_retries_later():
    package = f"retry-pkg-{uuid.uuid4().hex[:8]}"
    repo = repos.connect_repo(f"retry-{package}", RepoKind.GIT, url="https://example.com/r.git")
    _seed_package(repo.id, package)
    item = _seed_item(title="flaky", cve_ids=["CVE-2026-0004"])
    with session_scope() as db:
        db.get(NewsItem, item).verdict = "major"
    with (
        mock.patch.object(intel_mod, "verify_advisory", side_effect=TimeoutError("osv down")),
        mock.patch.object(intel_mod, "kev_exploited_ids", return_value=set()),
    ):
        assert mint_from_item(item) == {"minted": 0, "linked": 0}
    with session_scope() as db:
        assert db.get(NewsItem, item).minted_at is None  # retry on the next pass


def test_process_news_classifies_then_mints():
    package = f"proc-pkg-{uuid.uuid4().hex[:8]}"
    repo = repos.connect_repo(f"proc-{package}", RepoKind.GIT, url="https://example.com/p.git")
    _seed_package(repo.id, package)
    _seed_item(
        title="wormable RCE everywhere",
        summary="critical",
        body_excerpt="details",
        cve_ids=["CVE-2026-0005"],
    )
    settings = mock.Mock(
        news_classify_enabled=True, news_classify_max_items=1000, news_mint_enabled=True
    )
    verified = {"cve": "CVE-2026-0005", "severity": 10.0, "affected": [("npm", package, ["2.0.0"])]}
    with (
        mock.patch.object(intel_mod, "get_settings", return_value=settings),
        mock.patch(
            "security_agent.brain.get_chat_model",
            return_value=_FakeModel(json.dumps({"verdict": "major", "category": "worm"})),
        ),
        # OSV unknown in this pass: backlog majors mark attempted, mint nothing.
        mock.patch.object(intel_mod, "verify_advisory", return_value=None),
        mock.patch.object(intel_mod, "kev_exploited_ids", return_value=set()),
    ):
        # "worm" is not a valid category: fail-closed, nothing classified.
        failed = process_news()
        assert (failed["classified"], failed["major"]) == (0, 0)
    with (
        mock.patch.object(intel_mod, "get_settings", return_value=settings),
        mock.patch(
            "security_agent.brain.get_chat_model",
            return_value=_FakeModel(json.dumps({"verdict": "major", "category": "exploit"})),
        ),
        mock.patch.object(intel_mod, "verify_advisory", return_value=verified),
        mock.patch.object(intel_mod, "kev_exploited_ids", return_value=set()),
    ):
        counts = process_news()
    assert counts["classified"] >= 1 and counts["major"] >= 1 and counts["minted"] >= 1
    with session_scope() as db:
        minted = db.scalar(
            select(Finding).where(
                Finding.repo_id == repo.id, Finding.advisory_id == "CVE-2026-0005"
            )
        )
        assert minted is not None and minted.provenance == "news"


def test_mint_writes_minted_and_linked_rows():
    package = f"link-pkg-{uuid.uuid4().hex[:8]}"
    repo = repos.connect_repo(f"link-{package}", RepoKind.GIT, url="https://example.com/l.git")
    _seed_package(repo.id, package, advisory="CVE-2026-0011")
    item = _seed_item(title="linky", cve_ids=["CVE-2026-0011", "CVE-2026-0012"])
    with session_scope() as db:
        db.get(NewsItem, item).verdict = "major"
    records = {
        "CVE-2026-0011": {
            "cve": "CVE-2026-0011",
            "severity": None,
            "affected": [("npm", package, [])],
        },
        "CVE-2026-0012": {
            "cve": "CVE-2026-0012",
            "severity": 7.0,
            "affected": [("npm", package, ["3.0.0"])],
        },
    }
    with (
        mock.patch.object(intel_mod, "verify_advisory", side_effect=lambda c: records[c]),
        mock.patch.object(intel_mod, "kev_exploited_ids", return_value=set()),
    ):
        assert mint_from_item(item) == {"minted": 1, "linked": 1}
    with session_scope() as db:
        kinds = {
            db.get(Finding, link.finding_id).advisory_id: link.kind
            for link in db.scalars(
                select(NewsFindingLink).where(NewsFindingLink.news_item_id == item)
            )
        }
    assert kinds == {"CVE-2026-0011": "linked", "CVE-2026-0012": "minted"}


def test_list_repo_news_and_feed_filter_and_tags():
    package = f"tag-pkg-{uuid.uuid4().hex[:8]}"
    repo_a = repos.connect_repo(f"tag-a-{package}", RepoKind.GIT, url="https://example.com/a.git")
    repo_b = repos.connect_repo(f"tag-b-{package}", RepoKind.GIT, url="https://example.com/b.git")
    fid_a = _seed_package(repo_a.id, package, advisory="CVE-2026-0021")
    fid_b = _seed_package(repo_b.id, package, advisory="CVE-2026-0021")
    item = _seed_item(title="tagged story")
    other = _seed_item(title="elsewhere story")
    with session_scope() as db:
        db.get(NewsItem, item).verdict = "major"
        db.get(NewsItem, other).verdict = "major"
        db.add(NewsFindingLink(news_item_id=item, finding_id=fid_a, kind="minted"))
        db.add(NewsFindingLink(news_item_id=item, finding_id=fid_b, kind="linked"))
    assert [i.id for i in list_repo_news(repo_a.id)] == [item]
    assert [i.id for i in list_repo_news(repo_b.id)] == [item]
    assert other not in [i.id for i in list_repo_news(repo_a.id)]
    assert item in [i.id for i in list_feed(repo_id=repo_a.id)]
    assert other not in [i.id for i in list_feed(repo_id=repo_a.id)]
    assert item in [i.id for i in list_feed()]
    tags = repo_tags([item, other])
    assert sorted(n for _, n in tags[item]) == sorted([repo_a.name, repo_b.name])
    assert tags.get(other) in (None, [])
    assert repo_tags([]) == {}


def test_process_news_respects_kill_switches():
    settings = mock.Mock(
        news_classify_enabled=False, news_classify_max_items=20, news_mint_enabled=False
    )
    with (
        mock.patch.object(intel_mod, "get_settings", return_value=settings),
        mock.patch.object(intel_mod, "classify_pending") as fake_classify,
        mock.patch.object(intel_mod, "mint_from_item") as fake_mint,
    ):
        assert process_news() == {"classified": 0, "major": 0, "minted": 0, "linked": 0}
        fake_classify.assert_not_called()
        fake_mint.assert_not_called()
