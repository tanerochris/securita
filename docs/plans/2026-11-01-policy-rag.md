# Policy RAG for Worker Models — Decision Record

Status: Final — accepted by the user on 2026-11-01.

Parent context: worker prompts in `brain/adapt.py` and `worker/news_intel.py`
are fixed strings today; no policy concept, vector store, or README
extraction exists yet. This record settles the design before implementation.

## Goal

Let operators give worker models knowledge of company policy via uploaded
files, hand-written policies, and README extraction, scoped platform-wide,
per-repo, or per-task, retrieved into prompts at run time.

## Decisions

### D1. Enforcement strength (advisory RAG vs hard rules)
- Status: SETTLED in interview (record Final).
- Decision: strict restrictions in policy are guardrails and MUST be
  respected — enforced, not merely advised. Owners and Maintainers author
  and update policies. Pure prompt-only compliance is rejected: a stated
  guardrail that the model can silently ignore does not satisfy this.

### D1b. How guardrails are declared
- Status: SETTLED in interview (record Final).
- Decision: A with B available. On upload, the model drafts candidate
  guardrails as structured rules, each quoted against its source sentence.
  Nothing blocks until an Owner/Maintainer confirms the rule. Unconfirmed
  text still reaches prompts as guidance. A hand-written structured rule
  form (option B) is also available for direct authoring. Every confirmed
  rule carries an audit trail: who confirmed it, from which source text.

### D1c. Guardrail effects in v1
- Status: SETTLED in interview (record Final).
- Decision: three effects only — `block` (stop patch/delivery, leave
  report-only finding citing the rule), `require_approval` (route through
  an FR-9 gate even where normally free), and `silence` (close finding as
  silent-with-policy-reason). Each firing writes an audit record naming
  the rule. Severity/scheduling/notification knobs stay in existing
  settings, out of the policy engine.

### D2. Scope model and conflict precedence
- Status: SETTLED in interview (record Final).
- Decision: most restrictive wins — block > require_approval > silence.
  A repo rule may tighten a platform rule freely, never loosen it, unless
  the platform rule's author marked it "repos may override this." Every
  override is a confirmed, audited rule. Scope shape stays `scope`
  (platform | repo) + nullable task filter.

### D3. README-derived policy trust
- Status: SETTLED in interview (record Final).
- Decision: README extraction is guidance-only, low power by design.
  README text can never create or become an enforced guardrail — if a
  restriction matters, an Owner/Maintainer re-authors it in an uploaded
  or hand-written policy and confirms it there. Rationale: anyone able
  to edit a README could otherwise prompt-inject the worker. README
  chunks are provenance-badged, delimited as untrusted data in prompts,
  and cannot override operator-authored policy. Per-repo opt-out stays.

### D4. Embedding source and offline behavior
- Status: SETTLED in interview (record Final).
- Decision: hosted embeddings by default via the OpenAI-compatible
  endpoint (same trust boundary as existing model calls), local
  embedding model as a supported alternative behind the same interface,
  keyword retrieval as fallback when neither is available. Policy
  features never hard-fail for lack of embeddings.

### D5. Worker surfaces in v1
- Status: SETTLED in interview (record Final).
- Decision: patch path plus per-repo news relevance. Guidance reaches
  patch adaptation, unpatchable-advice generation, and per-repo news
  relevance. Guardrails are checked before patch, before deliver, and
  silence rules apply at finding ingestion. Global news classification
  stays policy-free (no repo context; one shared feed must not be
  skewed). Task filters let owners narrow any policy further.

### D6. File formats
- Status: SETTLED in interview (record Final).
- Decision: `.md`, `.txt`, and PDF in v1. PDF chunks keep page numbers
  so confirmed guardrails cite a checkable source ("page 4").
  Scanned-image PDFs with no text layer are rejected with a visible
  error, never silently indexed empty. DOCX deferred.

### D7. Edit timing, versioning, deletion
- Status: SETTLED in interview (record Final).
- Decision: stable guidance, live guardrails, everything versioned.
  A run snapshots retrieved guidance at start (coherent prompts);
  guardrails re-check latest confirmed rules at each checkpoint, so
  mid-run tightening still stops delivery. Documents and rules are
  immutably versioned; edits create new versions; deletes are disables.
  Every block/approval/silence records the rule version that fired.

### D8. Failure behavior
- Status: SETTLED in interview (record Final).
- Decision: guidance fails open, enforcement fails closed. Retrieval
  failure → run continues with a visible "policy unavailable" warning.
  Guardrail checkpoint unable to evaluate confirmed rules → protected
  action parks and alerts (same pattern as cost-cap park); nothing
  irreversible proceeds unverified.

### D9. Roles and separation of duties
- Status: SETTLED in interview (record Final).
- Decision: Owners and Maintainers may upload, write, confirm, disable,
  and override (where a rule permits) at platform and repo scope. No
  four-eyes requirement in v1; accountability comes from the audit
  trail and immutable versions. Developers/Reporters are read-only:
  they can see guidance and which rule blocked an action, change nothing.

## Scope Contract (Final — accepted 2026-11-01)

In scope (v1 deliverable):
- Policy store on pgvector in existing Postgres; documents + chunks +
  confirmed structured guardrails, all immutably versioned.
- Ingestion: `.md` / `.txt` / PDF upload, dashboard editor, hand-written
  structured rules, README guidance extraction on scan (hash-gated).
- Guardrail extraction queue: model-drafted candidates with source
  quotes; Owner/Maintainer confirmation before anything blocks.
- Retrieval into patch adaptation, unpatchable guidance, and per-repo
  news relevance; checkpoints before patch, before deliver, and at
  finding ingestion (silence). Global news classification untouched.
- Dashboard: platform Policies under Settings, per-repo Policies panel,
  confirmation queue, retrieval preview, per-repo README toggle.
- Audit: every author/confirm/override/fire/failure recorded; runs
  record retrieved chunk IDs and fired rule versions.

Out of scope:
- DOCX ingestion; local embedding model packaging beyond the interface
  (hosted default ships first); deterministic rules beyond the three
  effects; policy effects on severity/scheduling/notifications;
  policy authoring inside the sandbox; four-eyes confirmation.

Done means:
- [ ] Upload → confirm a `block` rule → matching patch is blocked
      report-only, citing rule + version; non-matching patch proceeds.
- [ ] Guidance from platform + repo policies appears, source-labelled,
      in adapt/relevance prompts; zero-policy runs unchanged.
- [ ] README edit + rescan updates guidance; README text alone never
      blocks anything (injection fixture proves it).
- [ ] Mid-run guardrail tightening stops the pending delivery;
      policy-store outage parks enforcement, warns on guidance.
- [ ] `uv run pytest` green, including new policy suites; migration
      0016 up/down proven on Postgres.

## Risks

- Extractor misses a paraphrased restriction: confirmation queue plus
  source quotes mitigate; unconfirmed text still guides via prompts.
- Hosted embedding endpoint may lack embeddings support: probe early;
  local interface + keyword fallback keep the feature shippable.
- PDF extraction quality varies: page-cited chunks and the visible
  no-text-layer rejection keep failures loud, not silent.

## Unresolved

- None. Implemented 2026-11-01 on `go`.

## Implementation notes (factual, post-acceptance; decisions unchanged)

- Embeddings probe (2026-11-01): `POST {MODEL_BASE_URL}/embeddings`
  returns 404 and `/models` lists no embedding model, so the hosted
  default degrades to keyword retrieval in practice until the endpoint
  (or an `EMBEDDING_BASE_URL` override) serves embeddings. The client,
  ledger task, and provider seam ship as decided; `EMBEDDING_PROVIDER=off`
  makes keyword-only explicit.
- `allow` exists as an override-only effect value: a repo exception that
  lifts a platform rule entirely. The three enforcement effects stand;
  `allow` is rejected anywhere except `override_of` rules, at creation,
  edit, and confirmation.
- Silence also applies to news-minted findings at mint time (same
  ingestion checkpoint as scanner findings).
- `require_approval` gates reuse the FR-9 queue as a new `policy` gate
  action; approval unblocks the next run, denial behaves as a block.
- Migration 0016 proven on real Postgres (2026-11-01): scratch-DB
  upgrade → downgrade → upgrade roundtrip plus live-DB object checks.
- Embeddings follow-up (2026-11-01): the model gets a `search_policies`
  tool in adapt (bounded to two searches, same scope/snapshot/audit as
  pre-loaded retrieval, with when-to-call instructions in the tool
  description and prompt). Provider is operator-chosen by
  `EMBEDDING_PROVIDER`: `local` (default, in-process fastembed ONNX,
  ~130 MB model, no extra service), `ollama` (opt-in compose profile,
  heavier), `hosted` (any OpenAI-compatible API), `off`. Narrow
  provider vectors zero-pad to the pinned 1536 width (cosine-invariant).
  Live proof: keyword scores 0.0 on the "TLS library" vs `openssl`
  paraphrase while local cosine ranks it 0.63 vs 0.38 noise; existing
  chunks backfilled via `backfill_embeddings()`.
