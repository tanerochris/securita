"""Localized news: per-repo relevance against the repo's own profile."""

import json
import uuid
from types import SimpleNamespace
from unittest import mock

from sqlalchemy import select

from security_agent.control import repos
from security_agent.db.models import Finding, NewsItem, NewsRepoRelevance, RepoKind
from security_agent.db.session import session_scope
from security_agent.worker import news_intel as intel_mod
from security_agent.worker.news_intel import (
    assess_pending_relevance,
    assess_relevance,
    list_feed,
    list_repo_news,
    mint_from_item,
    relevance_repo_tags,
    repo_relevance_map,
    repo_tags,
)
from security_agent.worker.repo_profile import build_repo_profile, mentioned_platforms


class _FakeModel:
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
            external_id=f"rel-{uuid.uuid4().hex}",
            title=fields.pop("title", "story"),
            **fields,
        )
        db.add(row)
        db.flush()
        return row.id


def _seed_finding(repo_id: int, package: str, ecosystem: str, advisory: str) -> int:
    with session_scope() as db:
        row = Finding(
            repo_id=repo_id,
            package=package,
            installed_version="1.0.0",
            advisory_id=advisory,
            ecosystem=ecosystem,
        )
        db.add(row)
        db.flush()
        return row.id


def _repo(package: str, ecosystem: str = "npm") -> object:
    repo = repos.connect_repo(
        f"rel-{uuid.uuid4().hex[:8]}", RepoKind.GIT, url="https://example.com/r.git"
    )
    _seed_finding(repo.id, package, ecosystem, f"CVE-2026-{uuid.uuid4().int % 9000 + 1000}")
    return repo


def _set_verdict(item_id: int, verdict: str, category: str = "vulnerability") -> None:
    with session_scope() as db:
        row = db.get(NewsItem, item_id)
        row.verdict, row.category = verdict, category


def _relevance_row(item_id: int, repo_id: int):
    with session_scope() as db:
        row = db.scalar(
            select(NewsRepoRelevance).where(
                NewsRepoRelevance.news_item_id == item_id,
                NewsRepoRelevance.repo_id == repo_id,
            )
        )
        if row is None:
            return None
        return (row.relevance, row.score, row.rationale, list(row.matched_signals or []))


# --- Repo profile ---


def test_profile_derives_stack_and_plausible_deployment():
    package = f"@aws-sdk/client-{uuid.uuid4().hex[:6]}"
    repo = _repo(package, "npm")
    profile = build_repo_profile(repo.id)
    assert profile is not None
    assert profile["ecosystems"] == ["npm"]
    assert package in profile["packages"]
    assert "nodejs" in profile["deployment_signals"]  # npm runtime
    assert "linux" in profile["deployment_signals"]  # plausible server target
    assert "aws" in profile["deployment_signals"]  # cloud SDK package hint
    assert package in profile["summary"]
    assert "aws" in profile["summary"]


def test_profile_unknown_repo_and_platform_mentions():
    assert build_repo_profile(999_999_999) is None
    assert mentioned_platforms("Linux kernel flaw on AWS EC2") == ["aws", "linux"]
    assert "windows" in mentioned_platforms("Windows Server patch")


def test_profile_probes_local_checkout(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("jobs:\n  build:\n    runs-on: windows-latest\n")
    repo = repos.connect_repo(
        f"local-{uuid.uuid4().hex[:8]}", RepoKind.LOCAL, local_path=str(tmp_path)
    )
    profile = build_repo_profile(repo.id)
    assert profile is not None
    assert {"docker", "linux", "windows"} <= set(profile["deployment_signals"])


# --- Relevance parsing (fail closed) ---


def test_parse_relevance_accepts_clamps_and_rejects():
    parsed = intel_mod._parse_relevance(
        '{"relevance": "platform", "score": 95, "rationale": "runs on AWS",'
        ' "matched_signals": ["platform:aws"]}'
    )
    assert parsed is not None
    relevance, score, rationale, signals = parsed
    assert relevance == "platform" and score == 69  # clamped into the platform band
    assert rationale == "runs on AWS" and signals == ["platform:aws"]
    assert intel_mod._parse_relevance("platform, obviously") is None
    assert intel_mod._parse_relevance('{"relevance": "huge", "score": 10}') is None
    assert intel_mod._parse_relevance('{"relevance": "direct", "score": "high"}') is None
    assert intel_mod._parse_relevance('{"relevance": "direct"}') is None


def test_relevance_prompt_carries_repo_profile():
    package = f"prompt-pkg-{uuid.uuid4().hex[:6]}"
    repo = _repo(package, "PyPI")
    profile = build_repo_profile(repo.id)
    item = _seed_item(title="t", summary="s", body_excerpt="e")
    with session_scope() as db:
        row = db.get(NewsItem, item)
        prompt = intel_mod._relevance_prompt(profile["summary"], row)
    assert package in prompt
    assert "REPOSITORY PROFILE" in prompt
    assert "direct" in prompt and "platform" in prompt


# --- Deterministic direct (no model call) ---


def test_assess_direct_via_package_mention_without_model():
    package = f"direct-pkg-{uuid.uuid4().hex[:6]}"
    repo = _repo(package)
    item = _seed_item(title=f"Critical flaw in {package} exploited", body_excerpt="details")
    _set_verdict(item, "major", "exploit")
    model = mock.Mock()
    assert assess_relevance(item, repo.id, model=model) == "direct"
    model.invoke.assert_not_called()
    row = _relevance_row(item, repo.id)
    assert row is not None and row[0] == "direct" and row[1] == 90
    assert f"package:{package}" in row[3]


def test_assess_direct_via_finding_link_without_model():
    from security_agent.db.models import NewsFindingLink

    package = f"linked-pkg-{uuid.uuid4().hex[:6]}"
    repo = _repo(package)
    with session_scope() as db:
        finding_id = db.scalar(select(Finding.id).where(Finding.repo_id == repo.id))
    item = _seed_item(title="unrelated headline", body_excerpt="nothing")
    _set_verdict(item, "major")
    with session_scope() as db:
        db.add(NewsFindingLink(news_item_id=item, finding_id=finding_id, kind="linked"))
    model = mock.Mock()
    assert assess_relevance(item, repo.id, model=model) == "direct"
    model.invoke.assert_not_called()
    assert _relevance_row(item, repo.id)[1] == 100


# --- Model-judged platform relevance is per-repo (localization) ---


def test_same_story_scores_differently_per_repo():
    aws_pkg = f"@aws-sdk/client-{uuid.uuid4().hex[:6]}"
    repo_aws = _repo(aws_pkg, "npm")
    repo_plain = _repo(f"plain-pkg-{uuid.uuid4().hex[:6]}", "PyPI")
    item = _seed_item(
        title="AWS EC2 hypervisor flaw disclosed",
        summary="cloud isolation issue",
        body_excerpt="details",
    )
    _set_verdict(item, "major")
    platform_model = _FakeModel(
        json.dumps(
            {
                "relevance": "platform",
                "score": 60,
                "rationale": "Repo deploys via AWS SDK workloads.",
                "matched_signals": ["platform:aws"],
            }
        )
    )
    irrelevant_model = _FakeModel(
        json.dumps(
            {
                "relevance": "irrelevant",
                "score": 5,
                "rationale": "No AWS link.",
                "matched_signals": [],
            }
        )
    )
    assert assess_relevance(item, repo_aws.id, model=platform_model) == "platform"
    assert assess_relevance(item, repo_plain.id, model=irrelevant_model) == "irrelevant"
    # The localized feed is the payoff: present for one repo, absent for the other.
    assert item in [i.id for i in list_feed(repo_id=repo_aws.id)]
    assert item not in [i.id for i in list_feed(repo_id=repo_plain.id)]
    assert item in [i.id for i in list_repo_news(repo_aws.id)]
    assert repo_relevance_map([item], repo_aws.id)[item][0] == "platform"
    tags = relevance_repo_tags([item])
    assert (repo_aws.id, repo_aws.name, "platform", 60) in tags[item]
    assert repo_plain.id not in [t[0] for t in tags.get(item, [])]


def test_assess_fails_closed_and_skips_assessed():
    repo = _repo(f"closed-pkg-{uuid.uuid4().hex[:6]}")
    item = _seed_item(title="Some cloud story", body_excerpt="e")
    _set_verdict(item, "major")
    assert assess_relevance(item, repo.id, model=_FakeModel("not json")) is None
    assert _relevance_row(item, repo.id) is None  # retried later, never guessed
    good = _FakeModel(
        json.dumps(
            {"relevance": "irrelevant", "score": 1, "rationale": "n/a", "matched_signals": []}
        )
    )
    assert assess_relevance(item, repo.id, model=good) == "irrelevant"
    second = mock.Mock()
    assert assess_relevance(item, repo.id, model=second) == "irrelevant"
    second.invoke.assert_not_called()


def test_minor_item_surfaces_only_for_direct_repo():
    package = f"minor-pkg-{uuid.uuid4().hex[:6]}"
    repo = _repo(package)
    other = _repo(f"other-pkg-{uuid.uuid4().hex[:6]}")
    item = _seed_item(title=f"Small advisory for {package}", body_excerpt="e")
    _set_verdict(item, "minor", "patch")
    assert assess_relevance(item, repo.id, model=mock.Mock()) == "direct"
    # Direct code relevance localizes even a globally minor story...
    assert item in [i.id for i in list_repo_news(repo.id)]
    assert item not in [i.id for i in list_repo_news(other.id)]
    # ...while the global feed stays major-only.
    assert item not in [i.id for i in list_feed()]


def test_localized_feed_orders_direct_before_platform():
    direct_pkg = f"ord-pkg-{uuid.uuid4().hex[:6]}"
    repo = _repo(direct_pkg)
    platform_item = _seed_item(title="Linux kernel update", body_excerpt="e")
    direct_item = _seed_item(title=f"Flaw in {direct_pkg}", body_excerpt="e")
    _set_verdict(platform_item, "major")
    _set_verdict(direct_item, "major")
    with session_scope() as db:
        db.add(
            NewsRepoRelevance(
                news_item_id=platform_item,
                repo_id=repo.id,
                relevance="platform",
                score=55,
                rationale="linux",
            )
        )
    assert assess_relevance(direct_item, repo.id, model=mock.Mock()) == "direct"
    ids = [i.id for i in list_repo_news(repo.id)]
    assert ids.index(direct_item) < ids.index(platform_item)


def test_assess_pending_relevance_assesses_major_pairs():
    repo = _repo(f"pend-pkg-{uuid.uuid4().hex[:6]}")
    item = _seed_item(title="Generic cloud outage story", body_excerpt="e")
    _set_verdict(item, "major", "other")
    model = _FakeModel(
        json.dumps(
            {"relevance": "irrelevant", "score": 2, "rationale": "n/a", "matched_signals": []}
        )
    )
    counts = assess_pending_relevance(limit=100_000, model=model)
    assert counts["assessed"] >= 1
    assert set(counts) == {"assessed", "direct", "platform", "irrelevant"}
    assert _relevance_row(item, repo.id) is not None


def test_relevance_badge_renders_in_feed_and_repo_pages():
    from fastapi.testclient import TestClient

    from security_agent.app import accounts as accounts_svc
    from security_agent.app.main import app
    from security_agent.db.models import Role

    package = f"ui-pkg-{uuid.uuid4().hex[:6]}"
    repo = _repo(package, "npm")
    item = _seed_item(title="Linux kernel flaw disclosed", body_excerpt="e")
    _set_verdict(item, "major")
    with session_scope() as db:
        db.add(
            NewsRepoRelevance(
                news_item_id=item,
                repo_id=repo.id,
                relevance="platform",
                score=58,
                rationale="Runs on Linux hosts.",
                matched_signals=["platform:linux"],
            )
        )
    user = accounts_svc.create_user(f"rel-ui-{uuid.uuid4().hex[:8]}@example.com", None, Role.OWNER)
    client = TestClient(app, raise_server_exceptions=False)
    client.cookies.set("app_session", accounts_svc.create_session(user.id))
    feed = client.get(f"/news?repo={repo.id}")
    assert feed.status_code == 200
    assert "platform" in feed.text and "Runs on Linux hosts." in feed.text
    detail = client.get(f"/repos/{repo.id}")
    assert detail.status_code == 200
    assert "Runs on Linux hosts." in detail.text
    assert "plausible deployment targets" in detail.text


def test_pending_migration_degrades_to_finding_links():
    """A missing news_repo_relevance table must degrade, never 500.

    Regression for the deployed crash: watch mode synced src without the
    migration, so /repos/<id> and /news?repo= died on UndefinedTable.
    With the relevance table absent, feeds fall back to finding links.
    """
    from fastapi.testclient import TestClient
    from sqlalchemy import select as sa_select

    from security_agent.app import accounts as accounts_svc
    from security_agent.app.main import app
    from security_agent.db.models import Finding as FindingModel
    from security_agent.db.models import NewsFindingLink, Role

    package = f"degraded-pkg-{uuid.uuid4().hex[:6]}"
    repo = _repo(package)
    with session_scope() as db:
        finding_id = db.scalar(sa_select(FindingModel.id).where(FindingModel.repo_id == repo.id))
    item = _seed_item(title="degraded story", body_excerpt="e")
    _set_verdict(item, "major")
    with session_scope() as db:
        db.add(NewsFindingLink(news_item_id=item, finding_id=finding_id, kind="linked"))
    with mock.patch.object(intel_mod, "_relevance_table_ok", return_value=False):
        assert [i.id for i in list_repo_news(repo.id)] == [item]
        assert [i.id for i in list_feed(repo_id=repo.id)] == [item]
        assert repo.id in [r for r, _ in repo_tags([item])[item]]
        assert repo_relevance_map([item], repo.id) == {}
        assert relevance_repo_tags([item]) == {}
        model = mock.Mock()
        assert assess_relevance(item, repo.id, model=model) is None
        model.invoke.assert_not_called()
        user = accounts_svc.create_user(
            f"rel-deg-{uuid.uuid4().hex[:8]}@example.com", None, Role.OWNER
        )
        client = TestClient(app, raise_server_exceptions=False)
        client.cookies.set("app_session", accounts_svc.create_session(user.id))
        assert client.get(f"/repos/{repo.id}").status_code == 200
        assert client.get(f"/news?repo={repo.id}").status_code == 200
        assert client.get("/news").status_code == 200


def test_mint_writes_direct_relevance():
    package = f"mintrel-pkg-{uuid.uuid4().hex[:8]}"
    repo = _repo(package)
    item = _seed_item(title="major vuln", url="https://news.example/x", cve_ids=["CVE-2026-7777"])
    _set_verdict(item, "major")
    verified = {"cve": "CVE-2026-7777", "severity": 9.0, "affected": [("npm", package, ["9.9.9"])]}
    with (
        mock.patch.object(intel_mod, "verify_advisory", return_value=verified),
        mock.patch.object(intel_mod, "kev_exploited_ids", return_value=set()),
    ):
        assert mint_from_item(item) == {"minted": 1, "linked": 0}
    assert repo_relevance_map([item], repo.id)[item][0] == "direct"
