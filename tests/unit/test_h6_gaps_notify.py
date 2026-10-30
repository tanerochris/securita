"""H6 gaps: export, severity split, channel update, maintainer resume, digest claim."""

import csv
import io
import re
from datetime import UTC, datetime
from unittest import mock

from conftest import mock_notify_http
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from security_agent.app import accounts as accounts_svc
from security_agent.app.main import app
from security_agent.control import repos as repo_svc
from security_agent.db.models import (
    EncryptedToken,
    Finding,
    FindingStatus,
    NotifyState,
    RepoKind,
    Role,
    ScanRun,
    Verdict,
)
from security_agent.db.session import session_scope
from security_agent.notify import create_channel, delete_channel, list_channels, set_routes
from security_agent.notify.digest import set_digest_schedule

client = TestClient(app, raise_server_exceptions=False)

HOSTILE = "<script>alert('xss')</script>"


def _login_as(role: Role) -> None:
    client.cookies.clear()
    email = f"gaps-{role.value}-{datetime.now(UTC).timestamp()}@example.com"
    user = accounts_svc.create_user(email, None, role)
    client.cookies.set("app_session", accounts_svc.create_session(user.id))


def _csrf() -> str:
    resp = client.get("/settings")
    match = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert match, "no csrf token on /settings"
    return match.group(1)


def _cleanup(channels_before: set[int]) -> None:
    for c in list_channels():
        if c["id"] not in channels_before:
            delete_channel(c["id"])


def _repo_with_run(prefix: str):
    repo = repo_svc.connect_repo(
        f"{prefix}-{datetime.now(UTC).timestamp()}", RepoKind.GIT, url="https://example.com/g.git"
    )
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    return repo, run_id


def _seed_finding(repo_id: int, run_id: int, advisory: str, *, kev: bool = False) -> int:
    with session_scope() as db:
        row = Finding(
            repo_id=repo_id,
            package="pkg",
            installed_version="1.0.0",
            advisory_id=advisory,
            status=FindingStatus.OPEN,
            kev_exploited=kev,
            severity_score=9.0 if kev else 5.0,
            first_run_id=run_id,
        )
        db.add(row)
        db.flush()
        return row.id


# G1: JSON/CSV export --------------------------------------------------------


def test_export_json_and_csv_owner_only_with_plain_data():
    _login_as(Role.OWNER)
    before = {c["id"] for c in list_channels()}
    repo, run_id = _repo_with_run("gaps-export")
    _seed_finding(repo.id, run_id, HOSTILE)
    try:
        resp = client.get("/settings/reports/export?format=json")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/json")
        assert "attachment" in resp.headers["content-disposition"]
        assert "reports.json" in resp.headers["content-disposition"]
        payload = resp.json()
        assert payload["top_findings"] and "top_secrets" in payload
        assert HOSTILE in [i["advisory"] for i in payload["top_findings"]]

        resp = client.get("/settings/reports/export?format=csv")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        assert "attachment" in resp.headers["content-disposition"]
        rows = list(csv.reader(io.StringIO(resp.text)))
        assert rows[0] == [
            "section",
            "repo",
            "package_or_rule",
            "advisory_or_path",
            "kev",
            "severity",
            "status",
        ]
        assert any(HOSTILE in row for row in rows[1:])

        assert client.get("/settings/reports/export?format=xml").status_code == 400
        _login_as(Role.MAINTAINER)
        assert client.get("/settings/reports/export?format=json").status_code == 403
    finally:
        _cleanup(before)


# G2: severity split ---------------------------------------------------------


def test_notify_splits_kev_high_reachable_medium_and_quiet():
    from security_agent.worker.graph import _notify

    repo, run_id = _repo_with_run("gaps-split")
    fid = _seed_finding(repo.id, run_id, "CVE-GAPS-REACH")
    try:
        with session_scope() as db:
            db.add(Verdict(finding_id=fid, run_id=run_id, reachable=True))
        with mock.patch("security_agent.notify.notify_event") as fake:
            assert _notify({"repo_id": repo.id, "run_id": run_id}) == {"done": ["notify"]}
            fake.assert_called_once()
            assert fake.call_args[0][0] == "medium"
            assert fake.call_args[1]["kind"] == "new-reachable"
    finally:
        with session_scope() as db:
            db.execute(delete(Verdict).where(Verdict.finding_id == fid))
            db.execute(delete(Finding).where(Finding.id == fid))


def test_notify_quiet_when_unreachable_and_kev_high_without_verdicts():
    from security_agent.worker.graph import _notify

    repo, run_id = _repo_with_run("gaps-quiet")
    fid = _seed_finding(repo.id, run_id, "CVE-GAPS-QUIET")
    try:
        with mock.patch("security_agent.notify.notify_event") as fake:
            _notify({"repo_id": repo.id, "run_id": run_id})
            fake.assert_not_called()  # no verdicts at all: silent
        with session_scope() as db:
            db.add(Verdict(finding_id=fid, run_id=run_id, reachable=False))
        with mock.patch("security_agent.notify.notify_event") as fake:
            _notify({"repo_id": repo.id, "run_id": run_id})
            fake.assert_not_called()  # unreachable verdict: silent
    finally:
        with session_scope() as db:
            db.execute(delete(Verdict).where(Verdict.finding_id == fid))
            db.execute(delete(Finding).where(Finding.id == fid))

    repo2, run2 = _repo_with_run("gaps-kev")
    kev_id = _seed_finding(repo2.id, run2, "CVE-GAPS-KEV", kev=True)
    try:
        with mock.patch("security_agent.notify.notify_event") as fake:
            _notify({"repo_id": repo2.id, "run_id": run2})
            fake.assert_called_once()
            assert fake.call_args[0][0] == "high"
            assert fake.call_args[1]["kind"] == "new-kev"
    finally:
        with session_scope() as db:
            db.execute(delete(Finding).where(Finding.id == kev_id))


# G3: channel update ---------------------------------------------------------


def test_update_channel_success_validation_and_secret_kept():
    import security_agent.notify as notify_mod

    _login_as(Role.OWNER)
    before = {c["id"] for c in list_channels()}
    hook = create_channel("webhook", "upd-hook", secret={"url": "https://hooks.example.com/old"})
    mail = create_channel(
        "email",
        "upd-mail",
        config={
            "host": "smtp.example.com",
            "from_addr": "agent@example.com",
            "to": ["ops@example.com"],
        },
        secret={"password": "original-pw"},
    )
    try:
        resp = client.post(
            f"/settings/channels/{hook.id}",
            data={"csrf": _csrf(), "name": "renamed", "url": "https://hooks.example.com/new"},
            follow_redirects=True,
        )
        assert resp.status_code == 200 and "updated" in resp.text
        listed = {c["id"]: c for c in list_channels()}
        assert listed[hook.id]["name"] == "renamed"
        assert notify_mod._load_secret(hook.id)["url"] == "https://hooks.example.com/new"

        resp = client.post(
            f"/settings/channels/{hook.id}",
            data={"csrf": _csrf(), "name": "renamed", "url": "not-a-url"},
        )
        assert resp.status_code == 400
        resp = client.post("/settings/channels/999999", data={"csrf": _csrf(), "name": "ghost"})
        assert resp.status_code == 404

        # Blank secrets keep the stored ones.
        before_hook = notify_mod._load_secret(hook.id)
        resp = client.post(
            f"/settings/channels/{hook.id}",
            data={"csrf": _csrf(), "name": "renamed-again", "url": ""},
            follow_redirects=True,
        )
        assert "updated" in resp.text
        assert notify_mod._load_secret(hook.id) == before_hook
        resp = client.post(
            f"/settings/channels/{mail.id}",
            data={
                "csrf": _csrf(),
                "name": "upd-mail",
                "host": "smtp.example.com",
                "port": "587",
                "username": "agent",
                "from_addr": "agent@example.com",
                "to": "ops@example.com",
                "password": "",
            },
            follow_redirects=True,
        )
        assert "updated" in resp.text
        with mock.patch("security_agent.notify.transports.smtplib.SMTP") as fake_smtp:
            assert notify_mod.test_send(mail.id)["ok"] is True
            server = fake_smtp.return_value.__enter__.return_value
            server.login.assert_called_once_with("agent", "original-pw")
    finally:
        _cleanup(before)


# G4: maintainer resume ------------------------------------------------------


def test_maintainer_sees_resume_but_not_channel_forms():
    from security_agent.control.cost import effective_cap, set_cap

    _login_as(Role.OWNER)
    before = {c["id"] for c in list_channels()}
    repo, run_id = _repo_with_run("gaps-park")
    owner = accounts_svc.create_user(
        f"gaps-owner-{datetime.now(UTC).timestamp()}@example.com", None, Role.OWNER
    )
    old_cap = effective_cap()
    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        run.parked = True
        run.token_usage = 10
        run.park_reason = "test park"
    try:
        _login_as(Role.MAINTAINER)
        page = client.get("/settings")
        assert page.status_code == 200
        assert "Resume" in page.text and str(run_id) in page.text
        assert 'action="/settings/channels"' not in page.text
        assert "Test-send" not in page.text
        assert 'action="/settings/routes"' not in page.text
        assert 'action="/settings/cost/cap"' not in page.text
        assert 'action="/settings/digest"' not in page.text

        resp = client.post(
            "/settings/channels",
            data={"csrf": _csrf(), "kind": "webhook", "name": "nope", "url": "https://x.example/"},
        )
        assert resp.status_code == 403

        resp = client.post(
            "/settings/cost/cap", data={"csrf": _csrf(), "cap": "5000"}, follow_redirects=True
        )
        assert resp.status_code == 200 and "cap set to 5000" in resp.text
        resp = client.post(
            "/settings/cost/resume",
            data={"csrf": _csrf(), "run_id": str(run_id), "new_cap": "6000"},
            follow_redirects=True,
        )
        assert resp.status_code == 200 and "resumed" in resp.text

        _login_as(Role.REPORTER)
        assert client.get("/settings").status_code == 403
    finally:
        set_cap(old_cap, owner)
        _cleanup(before)


# K5: digest single-send claim ----------------------------------------------


def _clear_digest_stamp() -> None:
    with session_scope() as db:
        db.execute(delete(NotifyState).where(NotifyState.key == "digest.last_sent"))


def test_digest_second_send_same_day_skipped_and_loser_skips():
    from security_agent.notify.digest import maybe_send_digest

    _login_as(Role.OWNER)
    before = {c["id"] for c in list_channels()}
    ch = create_channel(
        "email",
        "gaps-digest",
        config={
            "host": "smtp.example.com",
            "from_addr": "agent@example.com",
            "to": ["ops@example.com"],
        },
        secret={"password": "pw"},
    )
    set_routes("info", [ch.id])
    set_digest_schedule(enabled=True, hour_utc=0)
    _clear_digest_stamp()
    try:
        with mock.patch("security_agent.notify.transports.smtplib.SMTP"):
            assert maybe_send_digest(datetime(2026, 11, 3, 13, 0, tzinfo=UTC))["status"] == "sent"
            assert (
                maybe_send_digest(datetime(2026, 11, 3, 14, 0, tzinfo=UTC))["status"] == "skipped"
            )
        # A racing tick that finds today's stamp already claimed loses quietly.
        with session_scope() as db:
            row = db.get(NotifyState, "digest.last_sent")
            if row is None:
                db.add(NotifyState(key="digest.last_sent", value="2026-11-04"))
            else:
                row.value = "2026-11-04"
        try:
            with mock.patch("security_agent.notify.notify_event") as fake:
                assert (
                    maybe_send_digest(datetime(2026, 11, 4, 13, 0, tzinfo=UTC))["reason"]
                    == "already sent today"
                )
                fake.assert_not_called()
        finally:
            _clear_digest_stamp()
    finally:
        delete_channel(ch.id)
        set_digest_schedule(enabled=True, hour_utc=8)
        _clear_digest_stamp()
        _cleanup(before)


def test_digest_no_channel_releases_claim_for_retry():
    from security_agent.notify.digest import maybe_send_digest

    before = {c["id"] for c in list_channels()}
    ch = create_channel("webhook", "gaps-dh", secret={"url": "https://hooks.example.com/d"})
    set_routes("info", [])
    set_digest_schedule(enabled=True, hour_utc=0)
    _clear_digest_stamp()
    try:
        outcome = maybe_send_digest(datetime(2026, 11, 5, 13, 0, tzinfo=UTC))
        assert outcome["reason"] == "no info-routed channel"
        with session_scope() as db:
            assert db.get(NotifyState, "digest.last_sent").value != "2026-11-05"
        set_routes("info", [ch.id])
        with mock_notify_http() as fake:
            assert maybe_send_digest(datetime(2026, 11, 5, 14, 0, tzinfo=UTC))["status"] == "sent"
            assert fake.call_count == 1
    finally:
        delete_channel(ch.id)
        set_digest_schedule(enabled=True, hour_utc=8)
        _clear_digest_stamp()
        _cleanup(before)


# K6: atomic channel+secret --------------------------------------------------


def test_create_channel_commits_secret_and_routes_together():
    before = {c["id"] for c in list_channels()}
    ch = create_channel("slack", "gaps-atom", secret={"url": "https://hooks.slack.com/gaps"})
    try:
        with session_scope() as db:
            token = db.scalar(
                select(EncryptedToken).where(EncryptedToken.owner == f"notify-channel:{ch.id}")
            )
            assert token is not None
            assert "hooks.slack.com/gaps" not in (token.ciphertext or "")
        listed = {c["id"]: c for c in list_channels()}
        assert listed[ch.id]["has_secret"] is True
        assert sorted(listed[ch.id]["severities"]) == ["critical", "high", "info", "low", "medium"]
    finally:
        _cleanup(before)


# M3: attachment caps --------------------------------------------------------


def test_deliver_caps_email_attachments():
    import security_agent.notify as notify_mod
    from security_agent.db.models import NotifyChannel

    before = {c["id"] for c in list_channels()}
    ch = create_channel(
        "email",
        "gaps-cap",
        config={
            "host": "smtp.example.com",
            "from_addr": "agent@example.com",
            "to": ["ops@example.com"],
        },
        secret={"password": "pw"},
    )
    try:
        many = [(f"f{i}.bin", b"x" * 1_000_000, "application/octet-stream") for i in range(7)]
        capped = notify_mod._cap_attachments(many)
        assert len(capped) == 5  # file-count cap drops the rest
        huge = [(f"g{i}.bin", b"y" * 6_000_000, "application/octet-stream") for i in range(3)]
        capped = notify_mod._cap_attachments(huge)
        assert sum(len(p) for _, p, _ in capped) <= 10_000_000  # byte cap truncates
        with session_scope() as db:
            channel = db.get(NotifyChannel, ch.id)
            db.expunge(channel)
        with mock.patch("security_agent.notify.send_email") as fake_send:
            notify_mod._deliver(channel, "info", "s", "b", "", many)
            sent_atts = fake_send.call_args[1]["attachments"]
            assert len(sent_atts) == 5
            assert sum(len(p) for _, p, _ in sent_atts) <= 10_000_000
    finally:
        _cleanup(before)
