# H3 — Phase 2: News Boosters (detailed sub-plan)

Status: done (2026-10-30). Parent: [implementation plan](2026-10-29-implementation-plan.md)
plus [architecture.md](../architecture.md) (Integration Plane, Signals).

## Goal

Tier-2 signals raise finding priority but never trigger action alone.
A CVE discussed on HN or in outlet RSS rises in the queue with a link;
rumor-only input (no Tier-1 finding) is stored and yields no patch.

## FR-6 closure (just-in-time, decided here)

- Sources: HN via the Algolia search API (configurable query, default
  `CVE`, recent-first) + operator-configured RSS/Atom feeds
  (`NEWS_RSS_FEEDS`, comma-separated; empty default). RSS/Atom is
  hand-parsed with DOCTYPE rejection + size caps (no new dependency).
- Matching: CVE-ID regex over title/summary first. Exact advisory or
  alias match on a Tier-1 finding = strong boost (weight 100);
  package-name mention = weak boost (weight 10). Records carry the
  matched token and the source link as evidence.
- Boost mechanics: denormalized `Finding.news_weight` /
  `Finding.news_url` (strongest link wins). Queue ordering becomes
  KEV → severity → boost → recency. Patch candidates still require a
  reachable verdict, so a boost alone can never cause a patch.
- Scrape fallback: only when title+summary carry no CVE ID, fetch the
  linked article once (bot UA, 15s timeout, 512KB cap, per-host
  1 req/2s throttle, excerpt cached on the item). Fetch failure keeps
  the item with zero CVE IDs — the rumor path, never an error.
- Cadence + state: hourly per-source polls, gated by a `news_polls`
  log table (last finished row per source). The graph `fetch_signals`
  stub runs poll + match. Retention: items past 90d purged, boosts
  deleted, affected finding fields recomputed.

## Slices (build order; each lands tested)

- **A. Data foundation.** Tables: news_items, news_boosts, news_polls;
  `Finding.news_weight/news_url`; boost-aware queue ordering; news
  retention purge with finding recompute. Done when: migration 0005
  applies clean, ordering + purge tests green. Landed 2026-10-30.
- **B. Pollers.** HN Algolia client + RSS/Atom parser (caps,
  DOCTYPE-reject) + hourly gating + recorded fixtures. Done when:
  fixture feeds yield news_items with extracted CVE IDs.
  Landed 2026-10-30.
- **C. Stack matcher.** CVE + package-mention matching, boost upsert,
  finding field refresh, rumor-only stores silently. Done when:
  matched CVE boosts its finding; rumor-only input yields no patch.
  Landed 2026-10-30.
- **D. Dashboard.** Boost badge + source link in findings views.
  Done when: boosted finding renders first with a working link.
  Landed 2026-10-30.
- **E. Scrape fallback.** Polite article fetch on the no-CVE path.
  Done when: CVE found in body boosts; fetch failure degrades silently.
  Landed 2026-10-30.
- **F. Validation.** Graph `fetch_signals` wired; H3 checks green:
  known-discussed CVE rises with link; rumor-only yields no patch.
  Landed 2026-10-30.

Dependencies: A gates everything; B/C gate D; D gates E; F last.

## Hardening pass (2026-10-30, post-review)

Implemented in phase: SSRF guard on all news fetches (public IPs only,
per-hop redirect re-validation), streaming size caps, HN failure no
longer starves RSS (failures recorded, hourly backoff), per-feed poll
sources (no cross-feed GUID collision), weak→strong boost upsert,
`fetch_signals` isolation (news never blocks scans), bounded throttle
state, text-only scrape with script/style stripping, stored summaries
(migration 0006) with title/summary matching + HN `story_text`, encoded
HN query with `hitsPerPage=100`, poll-log retention, NEWS vars in
`.env.example`. Residual scale work parked in
[follow-ups 5–10](../cross-phase-followups.md).
