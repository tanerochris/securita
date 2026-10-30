"""H6 validation: fan-out, routing, digest, park/resume end to end (offline).

Mock transports only; every other layer is real (DB, scheduler, graph
node, digest schedule). The injection gate (`tests/security`) and the
restore proof (`tests/unit/test_backup.py`) are companion suites.
"""

from datetime import UTC, datetime, timedelta
from unittest import mock

from conftest import mock_notify_http
from sqlalchemy import delete, select

from security_agent.app import accounts as accounts_svc
from security_agent.control import repos as repo_svc
from security_agent.control.cost import CostCapExceeded, record_usage, resume_run, set_cap
from security_agent.control.gates import request_gate
from security_agent.db.models import GateAction, NotifyState, RepoKind, Role, ScanRun
from security_agent.db.session import session_scope
from security_agent.notify import create_channel, delete_channel, set_routes
from security_agent.notify.digest import set_digest_schedule


def _owner():
    return accounts_svc.create_user(
        f"h6-owner-{datetime.now(UTC).timestamp()}@example.com", None, Role.OWNER
    )


def _channels():
    mail = create_channel(
        "email",
        "h6-mail",
        config={
            "host": "smtp.example.com",
            "from_addr": "agent@example.com",
            "to": ["ops@example.com"],
        },
        secret={"password": "pw"},
    )
    slack = create_channel("slack", "h6-slack", secret={"url": "https://hooks.slack.com/x"})
    hook = create_channel("webhook", "h6-hook", secret={"url": "https://hooks.example.com/x"})
    return mail, slack, hook


def _cleanup(channels):
    for ch in channels:
        delete_channel(ch.id)
    with session_scope() as db:
        db.execute(
            delete(NotifyState).where(
                NotifyState.key.in_(["cost.run_cap", "digest.last_sent", "cost.spend_alert"])
            )
        )
    set_digest_schedule(enabled=True, hour_utc=8)


def test_h6_fanout_routing_and_test_send_per_channel():
    from security_agent.notify import test_send as channel_test_send
    from security_agent.worker.secrets import notify_secret_alert

    channels = _channels()
    try:
        set_routes("critical", [c.id for c in channels])
        set_routes("info", [channels[0].id])
        with (
            mock.patch("security_agent.notify.transports.smtplib.SMTP") as fake_smtp,
            mock_notify_http() as fake_post,
        ):
            notify_secret_alert(1, 1, 1, "github-token", "a.py")  # critical → all
            assert fake_smtp.return_value.__enter__.return_value.send_message.call_count == 1
            assert fake_post.call_count == 2  # slack + webhook
            repo = repo_svc.connect_repo(
                f"h6-{datetime.now(UTC).timestamp()}", RepoKind.GIT, url="https://example.com/h.git"
            )
            request_gate(repo.id, GateAction.MERGE, "https://example.com/pr/h6")  # fan-out all
            assert fake_post.call_count == 4
            for ch in channels:  # test-send per channel
                assert channel_test_send(ch.id)["ok"] is True
    finally:
        _cleanup(channels)


def test_h6_digest_flows_through_tick_on_schedule():
    from security_agent.worker.scheduler import tick

    channels = _channels()
    mail = channels[0]
    try:
        set_routes("info", [mail.id])
        set_digest_schedule(enabled=True, hour_utc=0)
        with (
            mock.patch("security_agent.worker.news.poll_news", return_value={}),
            mock.patch(
                "security_agent.worker.news.run_matcher", return_value={"items": 0, "boosts": 0}
            ),
            mock.patch("security_agent.notify.transports.smtplib.SMTP") as fake_smtp,
            mock_notify_http() as fake_post,
        ):
            tick(datetime.now(UTC))
            msg = fake_smtp.return_value.__enter__.return_value.send_message.call_args[0][0]
            assert "digest" in str(msg["Subject"])
            assert [a.get_filename() for a in msg.iter_attachments()] == ["digest.pdf"]
            fake_post.assert_not_called()  # info routes to mail only
    finally:
        _cleanup(channels)


def test_h6_park_resume_and_reclaim_cycle():
    import pytest

    import security_agent.notify as notify_mod
    from security_agent.worker.scheduler import claim_pending_runs

    owner = _owner()
    channels = _channels()
    repo = repo_svc.connect_repo(
        f"h6park-{datetime.now(UTC).timestamp()}", RepoKind.GIT, url="https://example.com/hp.git"
    )
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        run_id = run.id
    set_cap(100, owner)
    try:
        with (
            mock.patch.object(notify_mod, "notify_event"),
            pytest.raises(CostCapExceeded),
        ):
            record_usage(run_id, "adapt", 60, 60)
        assert run_id not in [r.id for r in claim_pending_runs("w")]  # parked: unclaimable
        with pytest.raises(ValueError, match="raise the cap"):
            resume_run(run_id, owner)
        outcome = resume_run(run_id, owner, new_cap=1000)
        assert outcome["cap"] == 1000
        assert run_id in [r.id for r in claim_pending_runs("w", limit=10000)]  # resumed
    finally:
        _cleanup(channels)


def test_h6_run_summary_node_emits_routed_event():
    from security_agent.db.models import Finding, FindingStatus
    from security_agent.worker.graph import _notify

    channels = _channels()
    repo = repo_svc.connect_repo(
        f"h6sum-{datetime.now(UTC).timestamp()}", RepoKind.GIT, url="https://example.com/hs.git"
    )
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        run_id = run.id
        db.add(
            Finding(
                repo_id=repo.id,
                package="pkg",
                installed_version="1.0.0",
                advisory_id="CVE-H6-SUM",
                kev_exploited=True,
                status=FindingStatus.OPEN,
                first_run_id=run_id,
            )
        )
    set_routes("high", [c.id for c in channels])
    try:
        with (
            mock.patch("security_agent.notify.transports.smtplib.SMTP"),
            mock_notify_http() as fake_post,
        ):
            out = _notify({"repo_id": repo.id, "run_id": run_id})
            assert out == {"done": ["notify"]}
            assert fake_post.call_count == 2
        # Quiet runs stay quiet.
        with session_scope() as db:
            row = db.scalar(select(Finding).where(Finding.advisory_id == "CVE-H6-SUM"))
            row.status = FindingStatus.SILENT
        with (
            mock.patch("security_agent.notify.transports.smtplib.SMTP") as fake_smtp,
            mock_notify_http() as fake_post,
        ):
            _notify({"repo_id": repo.id, "run_id": run_id})
            fake_smtp.return_value.__enter__.return_value.send_message.assert_not_called()
            fake_post.assert_not_called()
    finally:
        _cleanup(channels)


def test_h6_stale_claim_does_not_block_tick_reap():
    """A lease held past the reap horizon still reaps (claims are not wedges)."""
    from security_agent.worker.scheduler import claim_pending_runs, reap_stale_runs

    repo = repo_svc.connect_repo(
        f"h6reap-{datetime.now(UTC).timestamp()}", RepoKind.GIT, url="https://example.com/hr.git"
    )
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        run_id = run.id
    assert run_id in [r.id for r in claim_pending_runs("dead-worker", limit=10000)]
    with session_scope() as db:
        row = db.get(ScanRun, run_id)
        row.started_at = datetime.now(UTC) - timedelta(hours=25)
        # K2: reap spares fresh leases, so expire the dead worker's lease first;
        # the claim itself must never wedge the run.
        row.claimed_at = datetime.now(UTC) - timedelta(minutes=11)
    assert reap_stale_runs() >= 1
    with session_scope() as db:
        assert db.get(ScanRun, run_id).status.value == "failed"
