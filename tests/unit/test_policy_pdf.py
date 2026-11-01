"""PDF text extraction: text layer in, scanned/encrypted PDFs rejected."""

import pytest

from security_agent.policy.pdf import PdfError, extract_pdf_text


def _tiny_pdf(body_text: str | None) -> bytes:
    """Minimal one-page PDF; body_text None yields an empty content stream."""
    content = f"BT /F1 12 Tf 72 720 Td ({body_text}) Tj ET".encode() if body_text else b""
    parts: list[bytes] = [b"%PDF-1.4\n"]
    offsets = [0]
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    for i, obj in enumerate(objs, start=1):
        offsets.append(sum(len(p) for p in parts))
        parts.append(f"{i} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref_at = sum(len(p) for p in parts)
    parts.append(f"xref\n0 {len(objs) + 1}\n".encode())
    parts.append(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        parts.append(f"{off:010d} 00000 n \n".encode())
    parts.append(
        f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF".encode()
    )
    return b"".join(parts)


def test_extracts_page_text_with_ref():
    pages = extract_pdf_text(_tiny_pdf("Never patch openssl on Fridays"))
    assert len(pages) == 1
    ref, text = pages[0]
    assert ref == "page 1"
    assert "Never patch openssl on Fridays" in text


def test_scanned_pdf_rejected_visibly():
    with pytest.raises(PdfError, match="No extractable text"):
        extract_pdf_text(_tiny_pdf(None))


def test_garbage_rejected():
    with pytest.raises(PdfError, match="Unreadable PDF"):
        extract_pdf_text(b"not a pdf at all")


def test_many_pages_truncated():
    from pypdf import PdfReader

    data = _tiny_pdf("page text here")
    reader = PdfReader(__import__("io").BytesIO(data))
    writer_pages = len(reader.pages)
    assert writer_pages == 1  # fixture sanity: single-page source
    # Build a 120-page PDF by concatenating page objects via pypdf.
    from io import BytesIO

    from pypdf import PdfWriter

    writer = PdfWriter()
    for _ in range(120):
        writer.add_page(reader.pages[0])
    buf = BytesIO()
    writer.write(buf)
    from security_agent.policy import pdf as pdf_mod

    pages = extract_pdf_text(buf.getvalue())
    assert len(pages) == pdf_mod.MAX_PDF_PAGES
