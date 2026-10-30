"""H6 Slice A: digest summary, PDF, schedule (FR-12 D2)."""

from datetime import UTC, datetime
from unittest import mock

from sqlalchemy import delete

from security_agent.control import repos as repo_svc
from security_agent.db.models import (
    Finding,
    FindingStatus,
    RepoKind,
)
from security_agent.db.session import session_scope
from security_agent.notify import create_channel, delete_channel, set_routes
from security_agent.notify.digest import (
    build_summary,
    get_digest_schedule,
    maybe_send_digest,
    render_pdf,
    render_text,
    set_digest_schedule,
)


def _seed_vuln(repo_id: int, advisory: str, *, kev: bool = False) -> None:
    with session_scope() as db:
        db.add(
            Finding(
                repo_id=repo_id,
                package="pkg",
                installed_version="1.0.0",
                advisory_id=advisory,
                status=FindingStatus.OPEN,
                kev_exploited=kev,
                severity_score=9.8 if kev else 5.0,
            )
        )


def test_summary_counts_and_top_items():
    from security_agent.db.models import SecretFinding, SecretStatus

    repo = repo_svc.connect_repo("dg-r", RepoKind.GIT, url="https://example.com/dg.git")
    _seed_vuln(repo.id, "CVE-DIGEST-1", kev=True)
    _seed_vuln(repo.id, "CVE-DIGEST-2")
    with session_scope() as db:  # exercise the multi-column secrets select
        db.add(
            SecretFinding(
                repo_id=repo.id,
                rule_id="github-token",
                path="dg-secret.py",
                fingerprint="d" * 64,
                status=SecretStatus.OPEN,
            )
        )
    summary = build_summary()
    assert summary["vuln_open"] >= 2 and summary["kev_open"] >= 1
    assert summary["secrets_open"] >= 1
    assert any(i["rule"] == "github-token" for i in summary["top_secrets"])
    advisories = [i["advisory"] for i in summary["top_findings"]]
    assert "CVE-DIGEST-1" in advisories
    assert advisories.index("CVE-DIGEST-1") < advisories.index("CVE-DIGEST-2")  # KEV first
    text = render_text(summary, "2026-10-30")
    assert "CVE-DIGEST-1" in text and "digest" in text


def test_render_pdf_is_structurally_valid():
    pdf = render_pdf("title (with) \\ escapes", "line one\nline two (x)\n" + "y" * 200)
    assert pdf.startswith(b"%PDF-1.4\n") and pdf.rstrip().endswith(b"%%EOF")
    # Every xref offset must point at its object's header.
    xref_at = int(pdf.split(b"startxref\n")[1].split(b"\n")[0])
    assert pdf[xref_at:].startswith(b"xref\n")
    body = pdf[xref_at:]
    count = int(body.split(b"\n")[1].split()[1])
    entries = body.split(b"\n")[3 : 3 + count - 1]
    assert len(entries) == count - 1
    for obj_id, entry in enumerate(entries, start=1):
        offset = int(entry.split()[0])
        assert pdf[offset:].startswith(f"{obj_id} 0 obj\n".encode())
    assert b"(title \\(with\\) \\\\ escapes)" in pdf  # escaping holds


def test_render_pdf_paginates_long_text():
    pdf = render_pdf("t", "\n".join(f"line {i}" for i in range(120)))
    assert pdf.count(b"/Type /Page ") == 3
    assert b"(line 119)" in pdf


def test_digest_schedule_defaults_and_validation():
    from security_agent.db.models import NotifyState
    from security_agent.db.session import session_scope

    with session_scope() as db:  # order-independent: start from no stored schedule
        db.execute(
            delete(NotifyState).where(NotifyState.key.in_(["digest.enabled", "digest.hour_utc"]))
        )
    try:
        schedule = get_digest_schedule()
        assert schedule["enabled"] is True and schedule["hour_utc"] == 8
        set_digest_schedule(enabled=False, hour_utc=22)
        assert get_digest_schedule() == {"enabled": False, "hour_utc": 22}
        import pytest

        with pytest.raises(ValueError, match="0-23"):
            set_digest_schedule(enabled=True, hour_utc=24)
    finally:
        set_digest_schedule(enabled=True, hour_utc=8)


def test_maybe_send_digest_skips_before_hour_and_repeats():
    set_digest_schedule(enabled=True, hour_utc=12)
    try:
        early = datetime(2026, 10, 30, 6, 0, tzinfo=UTC)
        assert maybe_send_digest(early)["status"] == "skipped"
        set_digest_schedule(enabled=False, hour_utc=12)
        assert maybe_send_digest(datetime(2026, 10, 30, 13, 0, tzinfo=UTC))["status"] == "skipped"
    finally:
        set_digest_schedule(enabled=True, hour_utc=8)


def test_maybe_send_digest_sends_once_with_pdf_attachment():
    ch = create_channel(
        "email",
        "digest-mail",
        config={
            "host": "smtp.example.com",
            "from_addr": "agent@example.com",
            "to": ["ops@example.com"],
        },
        secret={"password": "pw"},
    )
    set_routes("info", [ch.id])
    set_digest_schedule(enabled=True, hour_utc=0)
    try:
        with mock.patch("security_agent.notify.transports.smtplib.SMTP") as fake_smtp:
            server = fake_smtp.return_value.__enter__.return_value
            outcome = maybe_send_digest(datetime(2026, 10, 29, 13, 0, tzinfo=UTC))
            assert outcome["status"] == "sent" and outcome["sent"] == [ch.id]
            msg = server.send_message.call_args[0][0]
            parts = list(msg.iter_attachments())
            assert len(parts) == 1 and parts[0].get_filename() == "digest.pdf"
            assert parts[0].get_content().startswith(b"%PDF-1.4")
            # Same UTC day: no second send.
            assert (
                maybe_send_digest(datetime(2026, 10, 29, 14, 0, tzinfo=UTC))["status"] == "skipped"
            )
    finally:
        delete_channel(ch.id)
        set_digest_schedule(enabled=True, hour_utc=8)
