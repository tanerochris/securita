"""Chat attachments: validated uploads consumed as vision/doc context.

Images go to the model as vision parts; documents extract to capped,
untrusted text. Validation is allowlist + magic sniff, never mime trust:
a ".png" that is really a script is rejected, and oversize files never
reach the wire.
"""

import base64
import os

from sqlalchemy import select

from security_agent.db.models import ChatAttachment
from security_agent.db.session import session_scope

MAX_FILE_BYTES = 5_000_000
MAX_FILES_PER_MESSAGE = 3
DOC_CHARS_PER_FILE = 20_000
DOC_CHARS_TOTAL = 30_000

IMAGE_EXTS = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}
IMAGE_EXTS.update({".webp": "image/webp", ".gif": "image/gif"})
DOC_EXTS = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".log": "text/plain",
    ".json": "application/json",
    ".yaml": "text/yaml",
    ".yml": "text/yaml",
    ".csv": "text/csv",
    ".pdf": "application/pdf",
}


def _sniff_image(data: bytes) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(data) > 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def validate_upload(filename: str, data: bytes) -> tuple[str, str]:
    """Return (safe_name, mime). Extension allowlist + magic sniff."""
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"{filename or 'file'} exceeds the 5 MB limit.")
    if not data:
        raise ValueError(f"{filename or 'file'} is empty.")
    safe = os.path.basename(filename or "upload")[:200] or "upload"
    _root, ext = os.path.splitext(safe.lower())
    if ext in IMAGE_EXTS:
        sniffed = _sniff_image(data)
        if sniffed is None:
            raise ValueError(f"{safe} is not a real image; upload rejected.")
        return safe, sniffed
    if ext in DOC_EXTS:
        if ext == ".pdf":
            if not data.startswith(b"%PDF"):
                raise ValueError(f"{safe} is not a real PDF; upload rejected.")
            return safe, "application/pdf"
        try:
            data[:4096].decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError(f"{safe} is not decodable text; upload rejected.") from None
        return safe, DOC_EXTS[ext]
    raise ValueError(f"{safe}: only images and .txt/.md/.log/.json/.yaml/.csv/.pdf.")


def store_attachments(
    conversation_id: int, message_id: int, uploads: list[tuple[str, bytes]]
) -> list[ChatAttachment]:
    if len(uploads) > MAX_FILES_PER_MESSAGE:
        raise ValueError(f"At most {MAX_FILES_PER_MESSAGE} files per message.")
    rows = []
    with session_scope() as db:
        for filename, data in uploads:
            safe, mime = validate_upload(filename, data)
            row = ChatAttachment(
                conversation_id=conversation_id,
                message_id=message_id,
                filename=safe,
                mime=mime,
                size_bytes=len(data),
                blob=data,
            )
            db.add(row)
            db.flush()
            db.expunge(row)
            rows.append(row)
    return rows


def filenames_for_messages(message_ids: list[int]) -> dict[int, list[str]]:
    if not message_ids:
        return {}
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(ChatAttachment)
                .where(ChatAttachment.message_id.in_(message_ids))
                .order_by(ChatAttachment.id)
            )
        )
        out: dict[int, list[str]] = {}
        for row in rows:
            if row.message_id is not None:
                out.setdefault(row.message_id, []).append(row.filename)
        return out


def message_attachments(message_id: int) -> list[ChatAttachment]:
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(ChatAttachment)
                .where(ChatAttachment.message_id == message_id)
                .order_by(ChatAttachment.id)
            )
        )
        for row in rows:
            db.expunge(row)
        return rows


def is_image(mime: str) -> bool:
    return mime in {"image/png", "image/jpeg", "image/webp", "image/gif"}


def image_part(att: ChatAttachment) -> dict:
    b64 = base64.b64encode(att.blob).decode("ascii")
    return {"type": "image_url", "image_url": {"url": f"data:{att.mime};base64,{b64}"}}


def doc_text(att: ChatAttachment) -> str:
    """Extracted doc text, capped. Caller fences it as untrusted."""
    if att.mime == "application/pdf":
        from security_agent.policy.pdf import PdfError, extract_pdf_text

        try:
            pages = extract_pdf_text(att.blob)
        except PdfError as exc:
            return f"[{att.filename}: {exc}]"
        joined = "\n".join(text for _ref, text in pages)
        return joined[:DOC_CHARS_PER_FILE]
    return att.blob.decode("utf-8", errors="replace")[:DOC_CHARS_PER_FILE]
