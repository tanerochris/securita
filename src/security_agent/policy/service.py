"""Policy document ingestion: upload/editor/README → versioned docs + chunks.

Edits append new versions (D7); deletes are disables. Uploads are
secret-scanned before storage and chunk-capped; embeddings are best
effort — chunks without vectors still serve via keyword fallback.
"""

import hashlib
import logging
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from security_agent.audit import get_shared_log
from security_agent.config import get_settings
from security_agent.db.models import PolicyChunk, PolicyDocument, Repo
from security_agent.db.session import session_scope
from security_agent.policy.chunking import chunk_markdown, chunk_pages, clean_text
from security_agent.policy.constants import POLICY_TASKS, SCOPES, SOURCES

log = logging.getLogger(__name__)
audit = get_shared_log()


class PolicyError(ValueError):
    """Expected policy failure: bad input or unmet precondition."""


class PolicyStoreError(RuntimeError):
    """Policy store unreachable mid-run: enforcement must fail closed (D8)."""


def tables_ok() -> bool:
    """True when the policy tables exist (migration 0016 applied)."""
    from sqlalchemy import inspect

    from security_agent.db.session import get_engine

    try:
        names = set(inspect(get_engine()).get_table_names())
    except Exception:  # noqa: BLE001 - a dead DB reads as no-policy, like news
        return False
    return {"policy_documents", "policy_chunks", "policy_rules"}.issubset(names)


def _check_scope(scope: str, repo_id: int | None) -> None:
    if scope not in SCOPES:
        raise PolicyError(f"Unknown scope {scope!r}; want one of {SCOPES}.")
    if scope == "platform" and repo_id is not None:
        raise PolicyError("Platform policies take no repo.")
    if scope == "repo" and repo_id is None:
        raise PolicyError("Repo policies need a repo_id.")


def _check_tasks(tasks: list[str] | None) -> list[str] | None:
    if not tasks:
        return None
    unknown = [t for t in tasks if t not in POLICY_TASKS]
    if unknown:
        raise PolicyError(f"Unknown policy tasks: {unknown}; want one of {POLICY_TASKS}.")
    return sorted(set(tasks))


def _check_source(source: str) -> None:
    if source not in SOURCES:
        raise PolicyError(f"Unknown source {source!r}; want one of {SOURCES}.")


def _secret_check(text: str) -> None:
    from security_agent.worker.patch import diff_secret_violations

    if violations := diff_secret_violations(text):
        raise PolicyError(
            "Upload rejected: possible secret material detected "
            f"({'; '.join(violations)}). Redact it and retry."
        )


def _chunk_and_store(db, doc_id: int, pieces: list[tuple[str, str | None]], *, embed: bool) -> int:
    """Store chunk rows for one document version; returns the chunk count."""
    from security_agent.brain.embeddings import embed_texts

    cap = max(1, get_settings().policy_max_chunks_per_doc)
    if len(pieces) > cap:
        pieces = pieces[:cap]
        audit.append(
            action_class="policy",
            decision="truncate",
            line=f"doc={doc_id} chunks capped at {cap}",
        )
    vectors: list[list[float]] | None = None
    if embed and pieces:
        vectors = embed_texts([p[0] for p in pieces])
    for i, (text, ref) in enumerate(pieces):
        db.add(
            PolicyChunk(
                document_id=doc_id,
                chunk_index=i,
                text=text,
                source_ref=ref,
                embedding=vectors[i] if vectors else None,
            )
        )
    return len(pieces)


def create_document(
    *,
    scope: str,
    title: str,
    text: str,
    repo_id: int | None = None,
    tasks: list[str] | None = None,
    source: str = "editor",
    file_name: str | None = None,
    created_by: int | None = None,
    pages: list[tuple[str, str]] | None = None,
    embed: bool = True,
    doc_key: str | None = None,
) -> PolicyDocument:
    """Ingest a new policy document as version 1 of a fresh doc_key."""

    _check_scope(scope, repo_id)
    _check_source(source)
    tasks = _check_tasks(tasks)
    title = (title or "").strip()
    if not title:
        raise PolicyError("Policy documents need a title.")
    cleaned = clean_text(text)
    if not cleaned.strip():
        raise PolicyError("Policy documents need non-empty text.")
    if scope == "repo":
        with session_scope() as db:
            if db.get(Repo, repo_id) is None:
                raise PolicyError(f"Unknown repo {repo_id}.")
    _secret_check(cleaned)
    settings = get_settings()
    if pages is not None:
        pieces = chunk_pages(
            pages,
            max_chars=settings.policy_chunk_chars,
            overlap=settings.policy_chunk_overlap_chars,
        )
    else:
        pieces = chunk_markdown(
            cleaned,
            max_chars=settings.policy_chunk_chars,
            overlap=settings.policy_chunk_overlap_chars,
        )
    if not pieces:
        raise PolicyError("Nothing indexable in this document.")
    doc_key = doc_key or uuid.uuid4().hex[:16]
    content_hash = hashlib.sha256(cleaned.encode()).hexdigest()
    with session_scope() as db:
        doc = PolicyDocument(
            doc_key=doc_key,
            version=1,
            is_current=True,
            scope=scope,
            repo_id=repo_id,
            tasks=tasks,
            title=title[:300],
            source=source,
            file_name=(file_name or None),
            content_hash=content_hash,
            text=cleaned,
            status="ready",
            created_by=created_by,
        )
        db.add(doc)
        db.flush()
        count = _chunk_and_store(db, doc.id, pieces, embed=embed)
        db.flush()
        db.expunge(doc)
    audit.append(
        action_class="policy",
        decision="ingest",
        line=f"key={doc_key} scope={scope} chunks={count} source={source}",
    )
    return doc


def update_document(
    doc_key: str,
    *,
    title: str | None = None,
    text: str | None = None,
    tasks: list[str] | None | object = ...,
    pages: list[tuple[str, str]] | None = None,
    created_by: int | None = None,
    embed: bool = True,
) -> PolicyDocument:
    """Append a new current version; prior versions stay for audit (D7)."""

    with session_scope() as db:
        current = db.scalar(
            select(PolicyDocument).where(
                PolicyDocument.doc_key == doc_key, PolicyDocument.is_current.is_(True)
            )
        )
        if current is None:
            raise PolicyError(f"Unknown policy document {doc_key!r}.")
        if current.status == "disabled":
            raise PolicyError("Enable the document before editing it.")
        snapshot: dict[str, Any] = {
            "scope": current.scope,
            "repo_id": current.repo_id,
            "tasks": list(current.tasks or []) if current.tasks else None,
            "title": current.title,
            "source": current.source,
            "file_name": current.file_name,
            "version": current.version,
        }
    new_tasks = snapshot["tasks"] if tasks is ... else _check_tasks(tasks)  # type: ignore[arg-type]
    new_title = (title.strip() if title is not None else snapshot["title"]) or snapshot["title"]
    cleaned = clean_text(text) if text is not None else None
    if cleaned is not None and not cleaned.strip():
        raise PolicyError("Policy documents need non-empty text.")
    if cleaned is not None:
        _secret_check(cleaned)
    settings = get_settings()
    if pages is not None:
        pieces = chunk_pages(
            pages,
            max_chars=settings.policy_chunk_chars,
            overlap=settings.policy_chunk_overlap_chars,
        )
        body = clean_text("\n\n".join(t for _, t in pages))
    elif cleaned is not None:
        pieces = chunk_markdown(
            cleaned,
            max_chars=settings.policy_chunk_chars,
            overlap=settings.policy_chunk_overlap_chars,
        )
        body = cleaned
    else:
        pieces, body = None, None
    with session_scope() as db:
        current = db.scalar(
            select(PolicyDocument).where(
                PolicyDocument.doc_key == doc_key, PolicyDocument.is_current.is_(True)
            )
        )
        if current is None:  # pragma: no cover - raced delete; fail loud
            raise PolicyError(f"Unknown policy document {doc_key!r}.")
        current.is_current = False
        try:
            with db.begin_nested():
                doc = PolicyDocument(
                    doc_key=doc_key,
                    version=snapshot["version"] + 1,
                    is_current=True,
                    scope=snapshot["scope"],
                    repo_id=snapshot["repo_id"],
                    tasks=new_tasks,
                    title=str(new_title)[:300],
                    source=snapshot["source"],
                    file_name=snapshot["file_name"],
                    content_hash=(
                        hashlib.sha256((body or "").encode()).hexdigest()
                        if body is not None
                        else current.content_hash
                    ),
                    text=body if body is not None else current.text,
                    status="ready",
                    created_by=created_by,
                )
                db.add(doc)
                db.flush()
                if pieces is not None:
                    if not pieces:
                        raise PolicyError("Nothing indexable in this document.")
                    _chunk_and_store(db, doc.id, pieces, embed=embed)
                else:
                    prior = list(
                        db.scalars(
                            select(PolicyChunk)
                            .where(PolicyChunk.document_id == current.id)
                            .order_by(PolicyChunk.chunk_index)
                        )
                    )
                    for chunk in prior:
                        db.add(
                            PolicyChunk(
                                document_id=doc.id,
                                chunk_index=chunk.chunk_index,
                                text=chunk.text,
                                source_ref=chunk.source_ref,
                                embedding=list(chunk.embedding) if chunk.embedding else None,
                            )
                        )
                db.flush()
                db.expunge(doc)
        except IntegrityError as exc:
            raise PolicyError("Concurrent policy edit; retry.") from exc
    audit.append(
        action_class="policy",
        decision="edit",
        line=f"key={doc_key} version={snapshot['version'] + 1}",
    )
    return doc


def set_document_status(doc_key: str, *, disabled: bool, user_id: int | None = None) -> None:
    """Disable (or re-enable) a document. Deletes are disables (D7)."""
    with session_scope() as db:
        current = db.scalar(
            select(PolicyDocument).where(
                PolicyDocument.doc_key == doc_key, PolicyDocument.is_current.is_(True)
            )
        )
        if current is None:
            raise PolicyError(f"Unknown policy document {doc_key!r}.")
        current.status = "disabled" if disabled else "ready"
    audit.append(
        action_class="policy",
        decision="disable" if disabled else "enable",
        line=f"key={doc_key} by={user_id}",
    )


def list_documents(*, scope: str | None = None, repo_id: int | None = None) -> list[PolicyDocument]:
    """Current versions only, newest first."""
    with session_scope() as db:
        stmt = (
            select(PolicyDocument)
            .where(PolicyDocument.is_current.is_(True))
            .order_by(PolicyDocument.id.desc())
        )
        if scope is not None:
            stmt = stmt.where(PolicyDocument.scope == scope)
        if repo_id is not None:
            stmt = stmt.where(PolicyDocument.repo_id == repo_id)
        rows = list(db.scalars(stmt))
        for r in rows:
            db.expunge(r)
        return rows


def get_document(doc_key: str, *, version: int | None = None) -> PolicyDocument | None:
    with session_scope() as db:
        stmt = select(PolicyDocument).where(PolicyDocument.doc_key == doc_key)
        stmt = (
            stmt.where(PolicyDocument.version == version)
            if version is not None
            else stmt.where(PolicyDocument.is_current.is_(True))
        )
        doc = db.scalar(stmt)
        if doc is not None:
            db.expunge(doc)
        return doc


def document_history(doc_key: str) -> list[PolicyDocument]:
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(PolicyDocument)
                .where(PolicyDocument.doc_key == doc_key)
                .order_by(PolicyDocument.version.desc())
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


def document_chunks(document_id: int) -> list[PolicyChunk]:
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(PolicyChunk)
                .where(PolicyChunk.document_id == document_id)
                .order_by(PolicyChunk.chunk_index)
            )
        )
        for r in rows:
            db.expunge(r)
        return rows


def upsert_readme_doc(repo_id: int, *, title: str, text: str) -> tuple[PolicyDocument, bool]:
    """Hash-gated README guidance doc (D3/D5). Returns (doc, changed).

    Guidance-only by construction: no extraction ever runs on README
    rows (see policy.extract), so README text cannot become a rule.
    """
    cleaned = clean_text(text)
    if not cleaned.strip():
        raise PolicyError("Nothing indexable in this README.")
    content_hash = hashlib.sha256(cleaned.encode()).hexdigest()
    doc_key = f"readme:{repo_id}"
    with session_scope() as db:
        current = db.scalar(
            select(PolicyDocument).where(
                PolicyDocument.doc_key == doc_key, PolicyDocument.is_current.is_(True)
            )
        )
        if current is not None and current.content_hash == content_hash:
            db.expunge(current)
            return current, False
    with session_scope() as db:
        current = db.scalar(
            select(PolicyDocument).where(
                PolicyDocument.doc_key == doc_key, PolicyDocument.is_current.is_(True)
            )
        )
        exists = current is not None
    if not exists:
        try:
            doc = create_document(
                scope="repo",
                title=title[:300],
                text=cleaned,
                repo_id=repo_id,
                source="readme",
                doc_key=doc_key,
            )
        except IntegrityError:
            # Lost a concurrent first-ingest race; the winner is current.
            existing = get_document(doc_key)
            if existing is None:  # pragma: no cover - defensive
                raise
            return existing, False
        return doc, True
    updated = update_document(doc_key, title=title, text=cleaned)
    return updated, True


def backfill_embeddings(batch: int = 64) -> int:
    """Embed chunks still missing vectors; returns how many were filled.

    For documents ingested while the provider was unreachable (their
    chunks serve by keyword meanwhile). Stops at the first provider
    failure instead of spinning through the whole backlog.
    """
    from security_agent.brain.embeddings import embed_texts

    filled = 0
    while True:
        with session_scope() as db:
            rows = list(
                db.scalars(
                    select(PolicyChunk)
                    .where(PolicyChunk.embedding.is_(None))
                    .order_by(PolicyChunk.id)
                    .limit(max(1, batch))
                )
            )
            if not rows:
                return filled
            vectors = embed_texts([r.text for r in rows], task="policy-embed")
            if not vectors or len(vectors) != len(rows):
                return filled
            for row, vec in zip(rows, vectors, strict=False):
                row.embedding = vec
            filled += len(rows)


def set_repo_readme_policy(repo_id: int, *, enabled: bool) -> None:
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        if repo is None:
            raise PolicyError(f"Unknown repo {repo_id}.")
        repo.readme_policy_enabled = enabled
    audit.append(
        action_class="policy",
        decision="readme-toggle",
        line=f"repo={repo_id} enabled={enabled}",
    )
