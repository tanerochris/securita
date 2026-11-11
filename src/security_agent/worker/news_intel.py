"""Standalone news intel: LLM classification + news-driven findings (FR-6).

News is a standalone feed now, no longer joined onto vulnerability lists.
Every polled item is classified by the model under a strict bar — only
major, impactful security stories (vulnerability, exploit, patch, breach,
leak) reach the feed. A major item whose CVE verifies against OSV.dev
mints one finding per tracked repo that carries the affected package;
minted findings flow through the normal reachability → patch → approval
gates like scanner findings.

Trust posture (NFR-5): feed content is untrusted data, so model output
is validated against strict enums, minting requires a real OSV
advisory (a hostile feed cannot invent a CVE into existence), and
human approval still gates every merge.
"""

import json
import logging
import re
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from security_agent.config import get_settings
from security_agent.db.models import (
    Finding,
    FindingScope,
    FindingStatus,
    NewsFindingLink,
    NewsItem,
    NewsRepoRelevance,
    Repo,
)
from security_agent.db.session import session_scope
from security_agent.prompts import render_prompt
from security_agent.worker.news import enrich_item
from security_agent.worker.scan import kev_exploited_ids, valid_fixed_version

log = logging.getLogger(__name__)

VERDICTS = ("major", "minor", "not_security")
CATEGORIES = ("vulnerability", "exploit", "patch", "breach", "leak", "other")

_CVE_STRICT = re.compile(r"^CVE-\d{4}-\d{4,}$")
_OSV_URL = "https://api.osv.dev/v1/vulns/"
_OSV_TIMEOUT = 15
_MAX_AFFECTED_PACKAGES = 20
_MAX_MINT_CVES = 10
_MAX_CITATIONS = 5
_PROMPT_TITLE_CHARS = 500
_PROMPT_SUMMARY_CHARS = 1000
_PROMPT_EXCERPT_CHARS = 2000


def _classify_prompt(title: str, summary: str | None, excerpt: str | None) -> str:
    return render_prompt(
        "news_classify",
        title=(title or "")[:_PROMPT_TITLE_CHARS],
        summary=(summary or "")[:_PROMPT_SUMMARY_CHARS],
        excerpt=(excerpt or "")[:_PROMPT_EXCERPT_CHARS],
    )


def _parse_verdict(content: str) -> tuple[str, str] | None:
    """(verdict, category) from model output, else None (fail closed)."""
    text = (content or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    verdict, category = data.get("verdict"), data.get("category")
    if verdict not in VERDICTS or category not in CATEGORIES:
        return None
    return verdict, category


def classify_item(item_id: int, *, model=None) -> str | None:
    """Classify one item; returns the verdict, None when unclassified.

    Fail-closed: model errors, unparseable output, and enum violations
    leave the item unclassified (excluded from the feed, never minted).
    """
    from security_agent.brain import get_chat_model, tracked_invoke

    with session_scope() as db:
        item = db.get(NewsItem, item_id)
        if item is None or item.verdict is not None:
            return item.verdict if item is not None else None
        title, summary, excerpt = item.title, item.summary, item.body_excerpt
    if not excerpt:
        enrich_item(item_id)  # best-effort: more context for the verdict
        with session_scope() as db:
            item = db.get(NewsItem, item_id)
            excerpt = item.body_excerpt if item is not None else None
    from security_agent.brain import BrainError

    try:
        bound = model if model is not None else get_chat_model()
        result = tracked_invoke(
            bound, _classify_prompt(title, summary, excerpt), task="news-classify"
        )
        parsed = _parse_verdict(str(getattr(result, "content", "") or ""))
    except BrainError:
        raise
    except Exception as exc:  # noqa: BLE001 - classification never breaks the poll
        log.warning("news classification failed for item %d: %s", item_id, exc)
        return None
    if parsed is None:
        log.debug("news classification unparseable for item %d", item_id)
        return None
    verdict, category = parsed
    with session_scope() as db:
        row = db.get(NewsItem, item_id)
        if row is not None:
            row.verdict, row.category = verdict, category
            row.classified_at = datetime.now(UTC)
    return verdict


def classify_pending(limit: int | None = None) -> dict[str, int]:
    """Classify unclassified items, oldest first; bounded per call."""
    from security_agent.control.cost import CostCapExceeded

    if limit is None:
        configured = getattr(get_settings(), "news_classify_max_items", 20)
        limit = configured if isinstance(configured, int) and configured > 0 else 20
    with session_scope() as db:
        ids = [
            i
            for (i,) in db.execute(
                select(NewsItem.id).where(NewsItem.verdict.is_(None)).order_by(NewsItem.id)
            ).all()[:limit]
        ]
    from security_agent.brain import BrainError

    counts = {"classified": 0, "major": 0}
    for item_id in ids:
        try:
            verdict = classify_item(item_id)
        except CostCapExceeded:
            log.warning("news classification stopped: cost cap reached")
            break
        except BrainError as exc:
            log.warning("news classification stopped: %s", exc)
            break
        if verdict is None:
            continue
        counts["classified"] += 1
        counts["major"] += verdict == "major"
    return counts


# --- Per-repo relevance (localized feed) ---
#
# Global classification decides whether a story is major at all. Relevance
# is the additional, per-repository judgement the feed was missing: the
# model sees the repository's own profile (stack it uses + platforms it
# can plausibly be deployed to) alongside the story, so a Linux-kernel,
# Windows Server, AWS, or chip story can matter to one repo and be noise
# to another. `direct` outranks `platform`: source-code relevance first,
# deployment relevance second, everything else stays out of the repo feed.

RELEVANCE_LEVELS = ("direct", "platform", "irrelevant")
_SCORE_BANDS = {"direct": (70, 100), "platform": (40, 69), "irrelevant": (0, 39)}
_MAX_RATIONALE_CHARS = 500
_MAX_SIGNALS = 10


def _relevance_prompt(profile_summary: str, item) -> str:
    return render_prompt(
        "news_relevance",
        profile_summary=profile_summary,
        verdict=item.verdict or "unclassified",
        category=item.category or "other",
        cve_ids=", ".join(item.cve_ids or []) or "none",
        title=(item.title or "")[:_PROMPT_TITLE_CHARS],
        summary=(item.summary or "")[:_PROMPT_SUMMARY_CHARS],
        excerpt=(item.body_excerpt or "")[:_PROMPT_EXCERPT_CHARS],
    )


def _parse_relevance(content: str) -> tuple[str, int, str, list[str]] | None:
    """(relevance, score, rationale, signals) from model output, else None."""
    text = (content or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    relevance = data.get("relevance")
    score = data.get("score")
    if relevance not in RELEVANCE_LEVELS:
        return None
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return None
    low, high = _SCORE_BANDS[relevance]
    clamped = max(low, min(high, int(score)))
    rationale = data.get("rationale")
    rationale = str(rationale)[:_MAX_RATIONALE_CHARS] if rationale else ""
    raw_signals = data.get("matched_signals")
    signals = (
        [str(s)[:80] for s in raw_signals if isinstance(s, (str, int))][:_MAX_SIGNALS]
        if isinstance(raw_signals, list)
        else []
    )
    return relevance, clamped, rationale, signals


def _store_relevance(
    db, item_id: int, repo_id: int, relevance: str, score: int, rationale: str, signals: list
) -> None:
    """Upsert one relevance row inside the caller's session (idempotent).

    A `direct` verdict is sticky: a later weaker assessment never demotes
    evidence-backed direct relevance (finding link / CVE / package match).
    A pending migration degrades to a no-op so minting still links.
    """
    if not _relevance_table_ok(db):
        return
    existing = db.scalar(
        select(NewsRepoRelevance).where(
            NewsRepoRelevance.news_item_id == item_id,
            NewsRepoRelevance.repo_id == repo_id,
        )
    )
    if existing is not None:
        if existing.relevance == "direct" and relevance != "direct":
            return
        existing.relevance, existing.score = relevance, score
        existing.rationale, existing.matched_signals = rationale or None, signals or None
        existing.assessed_at = datetime.now(UTC)
        return
    try:
        with db.begin_nested():
            db.add(
                NewsRepoRelevance(
                    news_item_id=item_id,
                    repo_id=repo_id,
                    relevance=relevance,
                    score=score,
                    rationale=rationale or None,
                    matched_signals=signals or None,
                )
            )
            db.flush()
    except IntegrityError:
        pass  # concurrent assessment won; its row stands


def _deterministic_direct(item, profile: dict) -> tuple[int, str, list[str]] | None:
    """Evidence-backed direct relevance without a model call, else None.

    Only `direct` is ever decided deterministically — CVE overlap with an
    advisory already on the repo, or a story naming a package the repo
    depends on. Platform relevance always needs the model's judgement,
    because every server stack plausibly touches Linux/AWS and a keyword
    hit alone would re-globalize the localized feed.
    """
    text = " ".join(p for p in (item.title, item.summary, item.body_excerpt) if p).lower()
    item_cves = {str(c).upper() for c in (item.cve_ids or [])}
    shared = sorted(item_cves & set(profile.get("advisories") or []))
    if shared:
        return (
            100,
            f"Story covers {shared[0]}, already affecting this repository.",
            [f"cve:{c}" for c in shared[:3]],
        )
    for package in profile.get("packages") or []:
        if len(package) >= 3 and package.lower() in text:
            return (
                90,
                f"Story mentions {package}, a dependency of this repository.",
                [f"package:{package}"],
            )
    return None


def assess_relevance(item_id: int, repo_id: int, *, model=None) -> str | None:
    """Assess one (item, repo) pair; returns the relevance level or None.

    Fail-closed like classification: model errors and unparseable output
    store nothing, so the pair is retried on a later pass instead of
    being silently marked irrelevant. Already-assessed pairs are skipped
    (a finding link or mint can still upgrade a row to `direct`).
    """
    from security_agent.worker.repo_profile import build_repo_profile

    with session_scope() as db:
        item = db.get(NewsItem, item_id)
        if item is None or db.get(Repo, repo_id) is None:
            return None
        if not _relevance_table_ok(db):
            return None  # migration pending: skip, retry after the table lands
        existing = db.scalar(
            select(NewsRepoRelevance).where(
                NewsRepoRelevance.news_item_id == item_id,
                NewsRepoRelevance.repo_id == repo_id,
            )
        )
        if existing is not None:
            return existing.relevance
        linked = db.scalar(
            select(NewsFindingLink.id)
            .join(Finding, Finding.id == NewsFindingLink.finding_id)
            .where(NewsFindingLink.news_item_id == item_id, Finding.repo_id == repo_id)
            .limit(1)
        )
        title, summary, excerpt = item.title, item.summary, item.body_excerpt
        verdict, category, cve_ids = item.verdict, item.category, list(item.cve_ids or [])
    if linked is not None:
        with session_scope() as db:
            _store_relevance(
                db,
                item_id,
                repo_id,
                "direct",
                100,
                "Story is linked to a finding on this repository.",
                ["finding-link"],
            )
        return "direct"
    profile = build_repo_profile(repo_id)
    if profile is None:
        return None
    story = type(
        "Story",
        (),
        {
            "title": title,
            "summary": summary,
            "body_excerpt": excerpt,
            "verdict": verdict,
            "category": category,
            "cve_ids": cve_ids,
        },
    )()
    direct = _deterministic_direct(story, profile)
    if direct is not None:
        score, rationale, signals = direct
        with session_scope() as db:
            _store_relevance(db, item_id, repo_id, "direct", score, rationale, signals)
        return "direct"
    from security_agent.brain import get_chat_model, tracked_invoke
    from security_agent.policy.retrieve import retrieve_policy_context

    policy_block = ""
    try:
        policy_block, _ = retrieve_policy_context(
            repo_id,
            "news-relevance",
            f"{title or ''} {summary or ''}",
        )
    except Exception as exc:  # noqa: BLE001 - guidance never breaks relevance
        log.warning("policy guidance for relevance failed: %s", exc)
    from security_agent.brain import BrainError

    try:
        bound = model if model is not None else get_chat_model()
        prompt = _relevance_prompt(profile["summary"], story)
        if policy_block:
            prompt += f"\n\n{policy_block}"
        result = tracked_invoke(bound, prompt, task="news-relevance")
        parsed = _parse_relevance(str(getattr(result, "content", "") or ""))
    except BrainError:
        raise
    except Exception as exc:  # noqa: BLE001 - relevance never breaks the poll
        log.warning("news relevance failed for item %d repo %d: %s", item_id, repo_id, exc)
        return None
    if parsed is None:
        log.debug("news relevance unparseable for item %d repo %d", item_id, repo_id)
        return None
    relevance, score, rationale, signals = parsed
    with session_scope() as db:
        _store_relevance(db, item_id, repo_id, relevance, score, rationale, signals)
    return relevance


def assess_pending_relevance(limit: int | None = None, *, model=None) -> dict[str, int]:
    """Assess unassessed (major item, repo) pairs, bounded per call.

    Pool: every `major` item against every tracked repo (the localized
    judgement), plus `minor` items only where a finding link already
    proves direct relevance (stored deterministically, no model call).
    Oldest items first so the backlog drains in poll order.
    """
    if limit is None:
        configured = getattr(get_settings(), "news_relevance_max_pairs", 50)
        limit = configured if isinstance(configured, int) and configured > 0 else 50
    with session_scope() as db:
        repo_ids = [r for (r,) in db.execute(select(Repo.id).order_by(Repo.id)).all()]
        major_ids = [
            i
            for (i,) in db.execute(
                select(NewsItem.id).where(NewsItem.verdict == "major").order_by(NewsItem.id)
            ).all()
        ]
        assessed = (
            {
                (n, r)
                for n, r in db.execute(
                    select(NewsRepoRelevance.news_item_id, NewsRepoRelevance.repo_id)
                ).all()
            }
            if _relevance_table_ok(db)
            else set()
        )
        linked_pairs = [
            (n, r)
            for n, r in db.execute(
                select(NewsFindingLink.news_item_id, Finding.repo_id)
                .join(Finding, Finding.id == NewsFindingLink.finding_id)
                .join(NewsItem, NewsItem.id == NewsFindingLink.news_item_id)
                .where(NewsItem.verdict == "minor")
                .distinct()
            ).all()
        ]
    pairs: list[tuple[int, int]] = [(i, r) for i in major_ids for r in repo_ids]
    pairs += [p for p in linked_pairs if p not in set(pairs)]
    pairs = [p for p in pairs if p not in assessed][:limit]
    counts = {"assessed": 0, "direct": 0, "platform": 0, "irrelevant": 0}
    from security_agent.brain import BrainError
    from security_agent.control.cost import CostCapExceeded

    for item_id, repo_id in pairs:
        try:
            relevance = assess_relevance(item_id, repo_id, model=model)
        except CostCapExceeded:
            log.warning("news relevance stopped: cost cap reached")
            break
        except BrainError as exc:
            log.warning("news relevance stopped: %s", exc)
            break
        if relevance is None:
            continue
        counts["assessed"] += 1
        counts[relevance] += 1
    return counts


def repo_relevance_map(item_ids: list[int], repo_id: int) -> dict[int, tuple[str, int, str]]:
    """news_item_id -> (relevance, score, rationale) for one repo."""
    if not item_ids:
        return {}
    with session_scope() as db:
        if not _relevance_table_ok(db):
            return {}
        rows = db.execute(
            select(
                NewsRepoRelevance.news_item_id,
                NewsRepoRelevance.relevance,
                NewsRepoRelevance.score,
                NewsRepoRelevance.rationale,
            ).where(
                NewsRepoRelevance.news_item_id.in_(item_ids),
                NewsRepoRelevance.repo_id == repo_id,
            )
        ).all()
    return {n: (rel, score, why or "") for n, rel, score, why in rows}


def relevance_repo_tags(item_ids: list[int]) -> dict[int, list[tuple[int, str, str, int]]]:
    """news_item_id -> [(repo_id, repo_name, relevance, score)] (direct/platform only)."""
    if not item_ids:
        return {}
    with session_scope() as db:
        if not _relevance_table_ok(db):
            return {}
        pairs = db.execute(
            select(
                NewsRepoRelevance.news_item_id,
                NewsRepoRelevance.repo_id,
                Repo.name,
                NewsRepoRelevance.relevance,
                NewsRepoRelevance.score,
            )
            .join(Repo, Repo.id == NewsRepoRelevance.repo_id)
            .where(
                NewsRepoRelevance.news_item_id.in_(item_ids),
                NewsRepoRelevance.relevance.in_(("direct", "platform")),
            )
            .order_by(NewsRepoRelevance.score.desc())
        ).all()
    tags: dict[int, dict[int, tuple[int, str, str, int]]] = {}
    for news_id, repo_id, name, relevance, score in pairs:
        tags.setdefault(news_id, {})[repo_id] = (
            repo_id,
            name or f"repo#{repo_id}",
            relevance,
            score,
        )
    return {nid: sorted(repos.values(), key=lambda t: -t[3]) for nid, repos in tags.items()}


def _osv_severity(record: dict) -> float | None:
    for entry in record.get("severity", []) or []:
        score = entry.get("score") if isinstance(entry, dict) else None
        if isinstance(score, (int, float)):
            return float(score)
        if isinstance(score, str):
            try:
                return float(score)
            except ValueError:
                continue
    return None


def _osv_fixed_versions(affected: dict) -> list[str]:
    fixed: list[str] = []
    for rng in affected.get("ranges", []) or []:
        for event in rng.get("events", []) or []:
            version = event.get("fixed") if isinstance(event, dict) else None
            if isinstance(version, str) and version not in fixed and valid_fixed_version(version):
                fixed.append(version)
    return fixed


def verify_advisory(cve_id: str) -> dict | None:
    """OSV.dev record for a CVE, else None when the CVE is unknown.

    The CVE format is strictly validated and the host is fixed, so this
    fetch needs no SSRF guard. Transport errors propagate so the caller
    can retry later; only a 404 (or malformed ID) means "no ground
    truth". Returns {"cve", "severity", "affected":
    [(ecosystem, package, fixed_versions)]}.
    """
    cve = (cve_id or "").strip().upper()
    if not _CVE_STRICT.match(cve):
        return None
    resp = httpx.get(f"{_OSV_URL}{cve}", timeout=_OSV_TIMEOUT)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    record = resp.json()
    if not isinstance(record, dict):
        return None
    affected: list[tuple[str, str, list[str]]] = []
    for entry in record.get("affected", []) or []:
        if not isinstance(entry, dict) or len(affected) >= _MAX_AFFECTED_PACKAGES:
            break
        package = entry.get("package") or {}
        name = package.get("name") if isinstance(package, dict) else None
        ecosystem = package.get("ecosystem") if isinstance(package, dict) else None
        if not isinstance(name, str) or not name or len(name) > 500:
            continue
        affected.append(
            (
                str(ecosystem)[:50] if ecosystem else "",
                name,
                _osv_fixed_versions(entry),
            )
        )
    return {"cve": cve, "severity": _osv_severity(record), "affected": affected}


def _repos_with_package(package: str) -> list[int]:
    """Repo IDs whose findings mention the package (any status: presence signal)."""
    with session_scope() as db:
        return [
            r
            for (r,) in db.execute(
                select(Finding.repo_id).where(Finding.package == package).distinct()
            ).all()
        ]


def mint_from_item(item_id: int) -> dict[str, int]:
    """Mint findings for a major item's verified CVEs. Idempotent per item.

    One finding per (repo carrying the package, CVE); repos without the
    package get nothing, and an existing finding gains a citation instead
    of a duplicate. Returns {"minted": n, "linked": m}.
    """
    counts = {"minted": 0, "linked": 0}
    freshly_minted: list[tuple[int, int]] = []
    with session_scope() as db:
        item = db.get(NewsItem, item_id)
        if item is None or item.verdict != "major" or item.minted_at is not None:
            return counts
        cves = [str(c).upper() for c in (item.cve_ids or [])][:_MAX_MINT_CVES]
        news_url = item.url
    if not cves:
        return counts
    kev_ids = kev_exploited_ids()
    transient_error = False
    for cve in cves:
        try:
            verified = verify_advisory(cve)
        except Exception as exc:  # noqa: BLE001 - one CVE never blocks the rest
            log.debug("OSV verification errored for %s: %s", cve, exc)
            transient_error = True
            continue
        if verified is None:
            continue  # unknown CVE: no ground truth, no mint
        osv_url = f"https://osv.dev/vulnerability/{verified['cve']}"
        for ecosystem, package, fixed in verified["affected"]:
            for repo_id in _repos_with_package(package):
                with session_scope() as db:
                    row = Finding(
                        repo_id=repo_id,
                        package=package,
                        installed_version="",
                        advisory_id=verified["cve"],
                        ecosystem=ecosystem or None,
                        aliases=[],
                        severity_score=verified["severity"],
                        severity_source="osv" if verified["severity"] is not None else None,
                        kev_exploited=verified["cve"] in kev_ids,
                        dep_path=None,
                        scope=FindingScope.PROD,
                        fixed_versions=fixed,
                        citations=[u for u in (news_url, osv_url) if u][:_MAX_CITATIONS],
                        status=FindingStatus.OPEN,
                        provenance="news",
                        guidance=(
                            "Minted from classified security news; the next "
                            "scheduled scan confirms the installed version."
                        ),
                    )
                    try:
                        with db.begin_nested():
                            db.add(row)
                            db.flush()
                    except IntegrityError:
                        existing = db.scalar(
                            select(Finding).where(
                                Finding.repo_id == repo_id,
                                Finding.package == package,
                                Finding.advisory_id == verified["cve"],
                            )
                        )
                        if existing is not None:
                            current = list(existing.citations or [])
                            for url in (news_url, osv_url):
                                if url and url not in current:
                                    current.append(url)
                            existing.citations = current[:_MAX_CITATIONS]
                            _link_news_finding(db, item_id, existing.id, "linked")
                            _store_relevance(
                                db,
                                item_id,
                                repo_id,
                                "direct",
                                100,
                                "Story is linked to a finding on this repository.",
                                ["finding-link"],
                            )
                            counts["linked"] += 1
                        continue
                    _link_news_finding(db, item_id, row.id, "minted")
                    _store_relevance(
                        db,
                        item_id,
                        repo_id,
                        "direct",
                        100,
                        "Story minted a finding on this repository.",
                        ["finding-link"],
                    )
                    counts["minted"] += 1
                    freshly_minted.append((repo_id, row.id))
    if freshly_minted:
        from security_agent.policy.enforce import apply_ingest_silence

        for repo_id, finding_id in freshly_minted:
            apply_ingest_silence(repo_id, [finding_id])
    if not transient_error:
        with session_scope() as db:
            item_row = db.get(NewsItem, item_id)
            if item_row is not None:
                item_row.minted_at = datetime.now(UTC)
    return counts


def _link_news_finding(db, news_item_id: int, finding_id: int, kind: str) -> None:
    """Record that a news item concerns a finding (idempotent)."""
    try:
        with db.begin_nested():
            db.add(NewsFindingLink(news_item_id=news_item_id, finding_id=finding_id, kind=kind))
            db.flush()
    except IntegrityError:
        pass  # already linked; the first kind wins


_relevance_table_cache: bool | None = None


def _relevance_table_ok(db) -> bool:
    """True when the relevance table exists; cached per process.

    A pending migration (e.g. `compose up --watch` syncing src without
    rebuilding the image that carries migrations/) must degrade the
    feed to finding links, never 500 the repo page. The cache is safe
    because a migration landing always comes with a fresh process.
    """
    global _relevance_table_cache
    if _relevance_table_cache is None:
        try:
            from sqlalchemy import inspect

            bind = db.get_bind()
            _relevance_table_cache = bind is not None and (
                NewsRepoRelevance.__tablename__ in inspect(bind).get_table_names()
            )
        except Exception:  # noqa: BLE001 - inspection failure degrades, never crashes
            _relevance_table_cache = False
        if not _relevance_table_cache:
            log.warning("news_repo_relevance table absent; relevance degraded to finding links")
    return _relevance_table_cache


def _deduped(rows: list[NewsItem]) -> list[NewsItem]:
    """Collapse join fan-out: one item links several findings."""
    seen: set[int] = set()
    unique: list[NewsItem] = []
    for row in rows:
        if row.id not in seen:
            seen.add(row.id)
            unique.append(row)
    return unique


def _localized_repo_items(repo_id: int, limit: int) -> list[NewsItem]:
    """News localized to one repo, most relevant first.

    Membership is the union of evidence-backed finding links and assessed
    relevance (`direct`/`platform`), so the feed works before, during,
    and after the relevance rollout (mixed-version safe). Global-major
    items qualify at either level; a globally `minor` item qualifies
    only when it is directly relevant to this repo's code. Ordering is
    relevance score, then recency — direct code relevance always
    outranks platform relevance.
    """
    scored: dict[int, tuple[int, NewsItem]] = {}
    with session_scope() as db:
        linked = list(
            db.scalars(
                select(NewsItem)
                .join(NewsFindingLink, NewsFindingLink.news_item_id == NewsItem.id)
                .join(Finding, Finding.id == NewsFindingLink.finding_id)
                .where(Finding.repo_id == repo_id, NewsItem.verdict == "major")
            )
        )
        for item in linked:
            scored[item.id] = (100, item)
        relevant = (
            db.execute(
                select(NewsItem, NewsRepoRelevance.score, NewsRepoRelevance.relevance)
                .join(NewsRepoRelevance, NewsRepoRelevance.news_item_id == NewsItem.id)
                .where(
                    NewsRepoRelevance.repo_id == repo_id,
                    NewsRepoRelevance.relevance.in_(("direct", "platform")),
                )
            ).all()
            if _relevance_table_ok(db)
            else []
        )
        for item, score, relevance in relevant:
            qualifies = item.verdict == "major" or (
                item.verdict == "minor" and relevance == "direct"
            )
            if qualifies and (item.id not in scored or score > scored[item.id][0]):
                scored[item.id] = (score, item)
        ordered = [item for _, item in sorted(scored.values(), key=lambda p: (-p[0], -p[1].id))]
        chosen = ordered[:limit]
        for row in chosen:
            db.expunge(row)
        return chosen


def list_repo_news(repo_id: int, *, limit: int = 10) -> list[NewsItem]:
    """News concerning one repo, most relevant first (repo page section)."""
    return _localized_repo_items(repo_id, limit)


def list_feed(*, repo_id: int | None = None, limit: int = 100) -> list[NewsItem]:
    """Feed items, newest first; with `repo_id`, localized to that repo."""
    if repo_id is not None:
        return _localized_repo_items(repo_id, limit)
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(NewsItem)
                .where(NewsItem.verdict == "major")
                .order_by(NewsItem.id.desc())
                .limit(limit)
            )
        )
        for row in rows:
            db.expunge(row)
        return rows


def repo_tags(item_ids: list[int]) -> dict[int, list[tuple[int, str]]]:
    """news_item_id → sorted [(repo_id, repo_name)] via links + relevance."""
    if not item_ids:
        return {}
    with session_scope() as db:
        pairs = db.execute(
            select(NewsFindingLink.news_item_id, Finding.repo_id, Repo.name)
            .join(Finding, Finding.id == NewsFindingLink.finding_id)
            .join(Repo, Repo.id == Finding.repo_id)
            .where(NewsFindingLink.news_item_id.in_(item_ids))
        ).all()
        rel_pairs = (
            db.execute(
                select(NewsRepoRelevance.news_item_id, NewsRepoRelevance.repo_id, Repo.name)
                .join(Repo, Repo.id == NewsRepoRelevance.repo_id)
                .where(
                    NewsRepoRelevance.news_item_id.in_(item_ids),
                    NewsRepoRelevance.relevance.in_(("direct", "platform")),
                )
            ).all()
            if _relevance_table_ok(db)
            else []
        )
    tags: dict[int, dict[int, str]] = {}
    for news_id, repo_id, name in [*pairs, *rel_pairs]:
        tags.setdefault(news_id, {})[repo_id] = name or f"repo#{repo_id}"
    return {nid: sorted(repos.items()) for nid, repos in tags.items()}


def process_news() -> dict[str, int]:
    """Classify globally, mint verified findings, then localize per repo.

    Pipeline: (1) global classification — is the story major at all;
    (2) OSV-verified minting for major CVEs; (3) per-repo relevance —
    the model judges each major story against each repository's own
    profile (code it uses + platforms it can be deployed to), which is
    what makes the feed localized instead of one global list. Step 3 is
    gated by NEWS_RELEVANCE_ENABLED (strictly `True`, so an unconfigured
    settings double never triggers model calls).

    Never raises past the caller: classification is fail-closed and
    minting degrades per CVE, so a bad model day or an OSV outage
    still leaves the poll stored and the feed serving.
    """
    from security_agent.brain import BrainError
    from security_agent.control.cost import CostCapExceeded

    settings = get_settings()
    counts = {"classified": 0, "major": 0, "minted": 0, "linked": 0}
    try:
        if getattr(settings, "news_classify_enabled", True):
            for key, value in classify_pending().items():
                counts[key] += value
        if getattr(settings, "news_mint_enabled", True):
            with session_scope() as db:
                ids = [
                    i
                    for (i,) in db.execute(
                        select(NewsItem.id)
                        .where(NewsItem.verdict == "major", NewsItem.minted_at.is_(None))
                        .order_by(NewsItem.id)
                    ).all()
                ][: max(1, getattr(settings, "news_classify_max_items", 20) or 20)]
            for item_id in ids:
                for key, value in mint_from_item(item_id).items():
                    counts[key] += value
        if getattr(settings, "news_relevance_enabled", True) is True:
            relevance_counts = assess_pending_relevance()
            log.info("news relevance assessed: %s", relevance_counts)
    except CostCapExceeded:
        log.warning("news intel stopped: cost cap reached")
    except BrainError as exc:
        log.warning("news intel stopped: %s", exc)
    except Exception as exc:  # noqa: BLE001 - intel never breaks the poll
        log.warning("news intel failed: %s", exc)
    return counts
