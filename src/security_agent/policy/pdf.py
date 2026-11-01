"""PDF text extraction for policy uploads (D6).

Text layer only: scanned-image PDFs raise PdfError visibly instead of
indexing nothing. Pages past the cap are dropped with an audit line —
a policy library should not mint thousands of chunks from one file.
"""

import io
import logging

log = logging.getLogger(__name__)

MAX_PDF_PAGES = 100


class PdfError(ValueError):
    """Expected PDF ingestion failure: surfaced to the uploader."""


def extract_pdf_text(data: bytes) -> list[tuple[str, str]]:
    """Extract [(source_ref, page_text)] for non-empty pages."""
    from pypdf import PdfReader

    try:
        reader = PdfReader(io.BytesIO(data))
    except Exception as exc:
        raise PdfError(f"Unreadable PDF: {exc}") from exc
    if getattr(reader, "is_encrypted", False):
        raise PdfError("Encrypted PDFs are not accepted; upload an unlocked copy.")
    pages = list(getattr(reader, "pages", []) or [])
    if not pages:
        raise PdfError("This PDF has no pages to index.")
    if len(pages) > MAX_PDF_PAGES:
        log.warning("PDF truncated to %d of %d pages", MAX_PDF_PAGES, len(pages))
        from security_agent.audit import get_shared_log

        get_shared_log().append(
            action_class="policy",
            decision="truncate",
            line=f"pdf pages capped at {MAX_PDF_PAGES}",
        )
        pages = pages[:MAX_PDF_PAGES]
    out: list[tuple[str, str]] = []
    for i, page in enumerate(pages, start=1):
        try:
            text = page.extract_text() or ""
        except Exception as exc:  # noqa: BLE001 - one bad page must not kill the file
            log.warning("PDF page %d extraction failed: %s", i, exc)
            continue
        if text.strip():
            out.append((f"page {i}", text))
    if not out:
        raise PdfError(
            "No extractable text found (scanned image?). "
            "Upload a PDF with a text layer, or paste the text."
        )
    return out
