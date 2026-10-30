"""Scheduled risk digest (FR-12 D2): outstanding-risk summary via FR-13 channels.

One digest per day per install (default 08:00 UTC): counts plus the
top action items, as text with a minimal PDF attachment for email.
The summary builder also feeds JSON/CSV export on the reports screen.
"""

import logging
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError

from security_agent.audit import get_shared_log
from security_agent.db.models import (
    Approval,
    Finding,
    FindingStatus,
    GateStatus,
    NotifyState,
    Repo,
    ScanRun,
    SecretFinding,
    SecretStatus,
)
from security_agent.db.session import session_scope

log = logging.getLogger(__name__)

TOP_N = 20
DIGEST_DEFAULT_HOUR_UTC = 8


def _state(db, key: str, default: str) -> str:
    row = db.get(NotifyState, key)
    return row.value if row else default


def _set_state(db, key: str, value: str) -> None:
    row = db.get(NotifyState, key)
    if row is None:
        db.add(NotifyState(key=key, value=value))
    else:
        row.value = value


def get_digest_schedule() -> dict:
    """{enabled, hour_utc} from notify_state (defaults: on, 08:00 UTC)."""
    with session_scope() as db:
        enabled = _state(db, "digest.enabled", "true").lower() == "true"
        try:
            hour = int(_state(db, "digest.hour_utc", str(DIGEST_DEFAULT_HOUR_UTC)))
        except ValueError:
            hour = DIGEST_DEFAULT_HOUR_UTC
        return {"enabled": enabled, "hour_utc": min(max(hour, 0), 23)}


def set_digest_schedule(*, enabled: bool, hour_utc: int) -> dict:
    if not 0 <= hour_utc <= 23:
        raise ValueError("Digest hour must be 0-23 UTC.")
    with session_scope() as db:
        _set_state(db, "digest.enabled", "true" if enabled else "false")
        _set_state(db, "digest.hour_utc", str(hour_utc))
    get_shared_log().append(
        action_class="notify", decision="digest-schedule", line=f"enabled={enabled} hour={hour_utc}"
    )
    return {"enabled": enabled, "hour_utc": hour_utc}


def build_summary() -> dict:
    """Outstanding-risk snapshot: bounded counts + top action items."""
    with session_scope() as db:
        open_statuses = [FindingStatus.OPEN, FindingStatus.PROPOSED]
        vuln_open = (
            db.scalar(
                select(func.count()).select_from(Finding).where(Finding.status.in_(open_statuses))
            )
            or 0
        )
        kev_open = (
            db.scalar(
                select(func.count())
                .select_from(Finding)
                .where(Finding.status.in_(open_statuses), Finding.kev_exploited.is_(True))
            )
            or 0
        )
        secrets_open = (
            db.scalar(
                select(func.count())
                .select_from(SecretFinding)
                .where(
                    SecretFinding.status.in_(
                        [SecretStatus.OPEN, SecretStatus.PROPOSED, SecretStatus.AWAITING_ROTATION]
                    )
                )
            )
            or 0
        )
        gates_pending = (
            db.scalar(
                select(func.count())
                .select_from(Approval)
                .where(Approval.status == GateStatus.PENDING)
            )
            or 0
        )
        parked = (
            db.scalar(select(func.count()).select_from(ScanRun).where(ScanRun.parked.is_(True)))
            or 0
        )
        repo_names = {r.id: r.name for r in db.scalars(select(Repo)).all()}
        top_findings = list(
            db.scalars(
                select(Finding)
                .where(Finding.status.in_(open_statuses))
                .order_by(
                    Finding.kev_exploited.desc(),
                    Finding.severity_score.desc(),
                    Finding.id.desc(),
                )
                .limit(TOP_N)
            )
        )
        top = [
            {
                "repo": repo_names.get(f.repo_id, f.repo_id),
                "package": f.package,
                "advisory": f.advisory_id,
                "kev": f.kev_exploited,
                "severity": f.severity_score,
                "status": f.status.value,
            }
            for f in top_findings
        ]
        top_secrets = list(
            db.execute(
                select(SecretFinding.rule_id, SecretFinding.path, SecretFinding.repo_id)
                .where(
                    SecretFinding.status.in_(
                        [SecretStatus.OPEN, SecretStatus.PROPOSED, SecretStatus.AWAITING_ROTATION]
                    )
                )
                .order_by(SecretFinding.id.desc())
                .limit(TOP_N)
            ).all()
        )
        top_secret_rows = [
            {"repo": repo_names.get(rid, rid), "rule": rule, "path": path}
            for rule, path, rid in top_secrets
        ]
    return {
        "vuln_open": vuln_open,
        "kev_open": kev_open,
        "secrets_open": secrets_open,
        "gates_pending": gates_pending,
        "parked_runs": parked,
        "top_findings": top,
        "top_secrets": top_secret_rows,
    }


def render_text(summary: dict, date: str) -> str:
    lines = [
        f"security-agent daily digest — {date}",
        "",
        f"Open vuln findings: {summary['vuln_open']} ({summary['kev_open']} KEV exploited)",
        f"Open secrets: {summary['secrets_open']}",
        f"Pending approval gates: {summary['gates_pending']}",
        f"Parked runs (cost cap): {summary['parked_runs']}",
        "",
        "Top findings:",
    ]
    for item in summary["top_findings"]:
        flag = " KEV!" if item["kev"] else ""
        lines.append(
            f"- [{item['repo']}] {item['package']} {item['advisory']}"
            f" (severity {item['severity']}){flag}"
        )
    lines.append("")
    lines.append("Open secrets:")
    for item in summary["top_secrets"]:
        lines.append(f"- [{item['repo']}] {item['rule']} in {item['path']}")
    return "\n".join(lines) + "\n"


def _pdf_escape(text: str) -> str:
    return (
        text.encode("latin-1", "replace")
        .decode("latin-1")
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def render_pdf(title: str, text: str) -> bytes:
    """Minimal multi-page text PDF (Helvetica, no dependencies)."""
    body_lines = [line[:110] for line in text.splitlines()][:500]
    pages: list[list[str]] = []
    for i in range(0, max(len(body_lines), 1), 50):
        pages.append(body_lines[i : i + 50] or ["(empty)"])
    objects: list[bytes] = []
    page_refs: list[int] = []
    content_refs: list[int] = []
    next_id = 4
    for _ in pages:
        page_refs.append(next_id)
        content_refs.append(next_id + 1)
        next_id += 2
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")  # 1
    kids = " ".join(f"{r} 0 R" for r in page_refs)
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode())  # 2
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")  # 3
    for _page_id, content_id, lines in zip(page_refs, content_refs, pages, strict=True):
        objects.append(  # page object
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>".encode()
        )
        ops = ["BT /F1 10 Tf 50 800 Td 12 TL"]
        ops.append(f"({_pdf_escape(title)}) Tj T*")
        ops.append("() Tj T*")
        for line in lines:
            ops.append(f"({_pdf_escape(line)}) Tj T*")
        ops.append("ET")
        stream = "\n".join(ops).encode("latin-1")
        objects.append(
            f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1") + stream + b"\nendstream"
        )
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for obj_id, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{obj_id} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_at = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n"
    ).encode()
    return bytes(out)


def _claim_digest_day(today: str) -> bool:
    """Atomically claim today's digest send; exactly one tick wins per day.

    Guarded UPDATE flips the stamp only when it names another day; on a
    missing row the INSERT wins unless a racing tick got there first
    (IntegrityError means lost). All inside ONE transaction.
    """
    with session_scope() as db:
        stamped = db.execute(
            update(NotifyState)
            .where(NotifyState.key == "digest.last_sent", NotifyState.value != today)
            .values(value=today)
        )
        if cast("CursorResult[Any]", stamped).rowcount == 1:
            return True
        if db.get(NotifyState, "digest.last_sent") is not None:
            return False  # stamp already names today: another tick won
        try:
            with db.begin_nested():
                db.add(NotifyState(key="digest.last_sent", value=today))
                db.flush()
        except IntegrityError:
            return False
        return True


def _reset_digest_claim(today: str) -> None:
    """Release today's claim so the next tick retries (no channel to send to)."""
    with session_scope() as db:
        row = db.get(NotifyState, "digest.last_sent")
        if row is not None and row.value == today:
            row.value = ""


def maybe_send_digest(now: datetime | None = None) -> dict:
    """Send today's digest once past the scheduled hour; skips repeat runs."""
    from security_agent.notify import notify_event

    now = now or datetime.now(UTC)
    schedule = get_digest_schedule()
    if not schedule["enabled"]:
        return {"status": "skipped", "reason": "disabled"}
    today = now.date().isoformat()
    if now.hour < schedule["hour_utc"]:
        return {"status": "skipped", "reason": "before scheduled hour"}
    if not _claim_digest_day(today):
        return {"status": "skipped", "reason": "already sent today"}
    summary = build_summary()
    text = render_text(summary, today)
    pdf = render_pdf(f"security-agent digest {today}", text)
    outcome = notify_event(
        "info",
        f"security-agent digest {today}: "
        f"{summary['vuln_open']} vulns, {summary['secrets_open']} secrets, "
        f"{summary['gates_pending']} gates",
        text,
        kind="digest",
        attachments=[("digest.pdf", pdf, "application/pdf")],
    )
    if not outcome["sent"]:
        log.warning("digest: no info-routed channel; will retry next tick")
        _reset_digest_claim(today)
        return {"status": "skipped", "reason": "no info-routed channel"}
    return {"status": "sent", **outcome}
