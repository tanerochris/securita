"""Deterministic policy chunking: headings first, then sliding windows.

Markdown splits on ATX headings so each chunk keeps its section as the
source ref; oversized sections (and plain text / PDF pages) fall back to
overlapping char windows snapped to whitespace. NUL bytes are stripped:
Postgres text columns reject them and uploads/PDFs can carry them.
"""

import re

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")


def clean_text(text: str) -> str:
    """Normalize uploads for storage: CRLF + NUL + control chars out."""
    out = (text or "").replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    return re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f]", "", out)


def _windows(text: str, *, max_chars: int, overlap: int) -> list[str]:
    """Overlapping windows, snapped to whitespace; always terminates."""
    text = text.strip()
    if not text or len(text) <= max_chars:
        return [text] if text else []
    out: list[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + max_chars)
        if end < len(text):
            snap = text.rfind(" ", start, end)
            if snap > start + max_chars // 2:
                end = snap
        piece = text[start:end].strip()
        if piece:
            out.append(piece)
        if end >= len(text):
            break
        start = end - min(max(0, overlap), max(0, end - start - 1))
    return out


def split_sections(text: str) -> list[tuple[str | None, str]]:
    """Split markdown into (heading, body) sections; preamble has None."""
    sections: list[tuple[str | None, list[str]]] = [(None, [])]
    for line in clean_text(text).split("\n"):
        m = _HEADING_RE.match(line.strip())
        if m:
            sections.append((m.group(2).strip()[:200], []))
        else:
            sections[-1][1].append(line)
    return [(h, "\n".join(body).strip()) for h, body in sections]


def chunk_markdown(
    text: str, *, max_chars: int = 2000, overlap: int = 200
) -> list[tuple[str, str | None]]:
    """Chunk markdown; returns (chunk_text, source_ref) pairs."""
    out: list[tuple[str, str | None]] = []
    for heading, body in split_sections(text):
        ref = f"## {heading}" if heading else None
        for piece in _windows(body or (heading or ""), max_chars=max_chars, overlap=overlap):
            out.append((piece, ref))
    return out


def chunk_pages(
    pages: list[tuple[str, str]], *, max_chars: int = 2000, overlap: int = 200
) -> list[tuple[str, str | None]]:
    """Chunk (source_ref, page_text) pairs, e.g. from PDF extraction."""
    out: list[tuple[str, str | None]] = []
    for ref, text in pages:
        cleaned = clean_text(text).strip()
        if not cleaned:
            continue
        for piece in _windows(cleaned, max_chars=max_chars, overlap=overlap):
            out.append((piece, ref))
    return out
