"""Guardrail extraction queue (D1b): the model drafts, humans confirm.

Extraction proposes `pending` rules from an operator-authored document;
each candidate carries the source sentence it came from, and candidates
whose quote is not found verbatim in the document are discarded — the
extractor may not invent restrictions. README documents are refused
here as well as at rule creation (D3 defense in depth).
"""

import json
import logging
import re

from sqlalchemy import select

from security_agent.audit import get_shared_log
from security_agent.policy.constants import EFFECTS
from security_agent.policy.rules import validate_match
from security_agent.policy.service import PolicyError
from security_agent.prompts import render_prompt

log = logging.getLogger(__name__)
audit = get_shared_log()

_EXTRACTABLE_EFFECTS = tuple(e for e in EFFECTS if e != "allow")
_PROMPT_DOC_CHARS = 12000


def _parse_candidates(content: str) -> list[dict] | None:
    """Candidate list from model output, else None (fail closed)."""
    text = (content or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, list):
        return None
    return [c for c in data if isinstance(c, dict)]


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def _verified_candidate(raw: dict, doc_text: str) -> dict | None:
    """A validated candidate, or None when it fails any check."""
    effect = raw.get("effect")
    if effect not in _EXTRACTABLE_EFFECTS:
        return None
    try:
        match = validate_match(raw.get("match"))
    except PolicyError:
        return None
    reason = (raw.get("reason") or "").strip()
    quote = (raw.get("quote") or "").strip()
    if not reason or not quote:
        return None
    if _normalize(quote) not in _normalize(doc_text):
        log.debug("extraction candidate quote not found in source; discarding")
        return None
    return {"effect": effect, "match": match, "reason": reason, "quote": quote}


def draft_candidates(doc_key: str, *, model=None) -> dict:
    """Extract pending rules for one document. Returns counts + rule keys.

    Safe to re-run: identical (effect, match, reason) candidates already
    pending or confirmed for this document are not duplicated.
    """
    from security_agent.brain import get_chat_model, tracked_invoke
    from security_agent.db.models import PolicyRule
    from security_agent.db.session import session_scope
    from security_agent.policy.rules import create_rule
    from security_agent.policy.service import get_document

    doc = get_document(doc_key)
    if doc is None:
        raise PolicyError(f"Unknown policy document {doc_key!r}.")
    if doc.source == "readme":
        raise PolicyError("README documents cannot back guardrails (D3).")
    if doc.status == "disabled":
        raise PolicyError("Enable the document before extracting.")
    try:
        bound = model if model is not None else get_chat_model()
        result = tracked_invoke(
            bound,
            render_prompt("policy_extract", document=doc.text[:_PROMPT_DOC_CHARS]),
            task="policy-extract",
        )
        parsed = _parse_candidates(str(getattr(result, "content", "") or ""))
    except Exception as exc:  # noqa: BLE001 - extraction never breaks ingestion
        log.warning("policy extraction failed for %s: %s", doc_key, exc)
        return {"status": "unavailable", "created": 0, "rule_keys": []}
    if parsed is None:
        log.debug("policy extraction unparseable for %s", doc_key)
        return {"status": "unparseable", "created": 0, "rule_keys": []}
    verified = [c for raw in parsed if (c := _verified_candidate(raw, doc.text)) is not None]
    with session_scope() as db:
        existing = {
            (
                r.effect,
                json.dumps(r.match or {}, sort_keys=True),
                r.reason,
                r.source_document_id,
            )
            for r in db.scalars(
                select(PolicyRule).where(
                    PolicyRule.is_current.is_(True),
                    PolicyRule.status.in_(["pending", "confirmed"]),
                    PolicyRule.source_document_id == doc.id,
                )
            )
        }
    created: list[str] = []
    for cand in verified:
        fingerprint = (
            cand["effect"],
            json.dumps(cand["match"], sort_keys=True),
            cand["reason"],
            doc.id,
        )
        if fingerprint in existing:
            continue
        try:
            rule = create_rule(
                scope=doc.scope,
                effect=cand["effect"],
                match=cand["match"],
                reason=cand["reason"],
                repo_id=doc.repo_id,
                tasks=list(doc.tasks) if doc.tasks else None,
                source_document_id=doc.id,
                source_quote=cand["quote"],
            )
        except PolicyError as exc:
            log.debug("extraction candidate rejected: %s", exc)
            continue
        existing.add(fingerprint)
        created.append(rule.rule_key)
    audit.append(
        action_class="policy",
        decision="extract",
        line=f"doc={doc_key} candidates={len(verified)} created={len(created)}",
    )
    return {"status": "done", "created": len(created), "rule_keys": created}
