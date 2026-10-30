"""Slices B+F: webhook receivers enqueue scans; close/merge reconciles PR state."""

import hashlib
import hmac
import json

from fastapi.testclient import TestClient
from sqlalchemy import select

from security_agent.app.main import app
from security_agent.control import repos
from security_agent.db.models import (
    Finding,
    FindingStatus,
    Proposal,
    ProposalStatus,
    RepoKind,
    RunTrigger,
    ScanRun,
)
from security_agent.db.session import session_scope

client = TestClient(app, raise_server_exceptions=False)


def _setup() -> tuple[int, str]:
    from datetime import UTC, datetime

    from security_agent.db.models import RunStatus

    repo = repos.connect_repo("wh-r", RepoKind.GIT, url="https://example.com/w.git")
    with session_scope() as db:  # connect run already executed; webhooks start clean
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        run.status = RunStatus.DONE
        run.finished_at = datetime.now(UTC)
    return repo.id, repos.issue_webhook_secret(repo.id)


def _webhook_runs(repo_id: int) -> int:
    with session_scope() as db:
        return (
            db.scalar(
                select(ScanRun).where(
                    ScanRun.repo_id == repo_id, ScanRun.trigger == RunTrigger.WEBHOOK
                )
            )
            is not None
        )


def test_github_push_queues_scan():
    repo_id, secret = _setup()
    body = b'{"ref":"refs/heads/main"}'
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    r = client.post(
        f"/hooks/github/{repo_id}",
        content=body,
        headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "push"},
    )
    assert r.status_code == 202 and r.json() == {"queued": True}
    assert _webhook_runs(repo_id)


def test_github_push_replay_coalesces():
    repo_id, secret = _setup()
    body = b'{"ref":"refs/heads/main"}'
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    headers = {"X-Hub-Signature-256": sig, "X-GitHub-Event": "push"}
    assert client.post(f"/hooks/github/{repo_id}", content=body, headers=headers).status_code == 202
    assert client.post(f"/hooks/github/{repo_id}", content=body, headers=headers).status_code == 202
    with session_scope() as db:
        runs = list(
            db.scalars(
                select(ScanRun).where(
                    ScanRun.repo_id == repo_id, ScanRun.trigger == RunTrigger.WEBHOOK
                )
            )
        )
        assert len(runs) == 1


def test_github_bad_signature_rejected():
    repo_id, _secret = _setup()
    r = client.post(
        f"/hooks/github/{repo_id}",
        content=b"{}",
        headers={"X-Hub-Signature-256": "sha256=dead", "X-GitHub-Event": "push"},
    )
    assert r.status_code == 401
    assert not _webhook_runs(repo_id)


def test_github_unknown_event_acked_without_queue():
    repo_id, secret = _setup()
    body = b"{}"
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    r = client.post(
        f"/hooks/github/{repo_id}",
        content=body,
        headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "star"},
    )
    assert r.status_code == 202 and r.json() == {"queued": False}


def test_gitlab_push_queues_scan():
    repo_id, secret = _setup()
    r = client.post(
        f"/hooks/gitlab/{repo_id}",
        content=b'{"object_kind":"push"}',
        headers={"X-Gitlab-Token": secret, "X-Gitlab-Event": "Push Hook"},
    )
    assert r.status_code == 202 and r.json() == {"queued": True}


def test_gitlab_bad_token_rejected():
    repo_id, _secret = _setup()
    r = client.post(
        f"/hooks/gitlab/{repo_id}",
        content=b"{}",
        headers={"X-Gitlab-Token": "wrong", "X-Gitlab-Event": "Push Hook"},
    )
    assert r.status_code == 401


def test_unknown_repo_and_local_rejected():
    r = client.post(
        "/hooks/github/999999",
        content=b"{}",
        headers={"X-Hub-Signature-256": "sha256=x", "X-GitHub-Event": "push"},
    )
    assert r.status_code == 404
    local = repos.connect_repo("wh-local", RepoKind.LOCAL, local_path="/tmp/wh-local")
    r = client.post(
        f"/hooks/github/{local.id}",
        content=b"{}",
        headers={"X-Hub-Signature-256": "sha256=x", "X-GitHub-Event": "push"},
    )
    assert r.status_code == 400


def _seed_open_proposal(repo_id: int, pr_url: str) -> tuple[int, int]:
    with session_scope() as db:
        finding = Finding(
            repo_id=repo_id,
            package="left-pad",
            installed_version="1.0.0",
            advisory_id="CVE-1",
            status=FindingStatus.PROPOSED,
        )
        db.add(finding)
        db.flush()
        proposal = Proposal(
            repo_id=repo_id,
            finding_ids=[finding.id],
            package_from="1.0.0",
            package_to="1.0.1",
            verification_result="tests passed",
            pr_url=pr_url,
            pr_state="open",
            branch="security/left-pad-CVE-1",
        )
        db.add(proposal)
        db.flush()
        return proposal.id, finding.id


def test_github_merge_reconciles_proposal():
    repo_id, secret = _setup()
    pid, fid = _seed_open_proposal(repo_id, "https://github.com/o/r/pull/71")
    body = json.dumps(
        {
            "action": "closed",
            "pull_request": {"html_url": "https://github.com/o/r/pull/71", "merged": True},
        }
    ).encode()
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    r = client.post(
        f"/hooks/github/{repo_id}",
        content=body,
        headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "pull_request"},
    )
    assert r.status_code == 202
    with session_scope() as db:
        assert db.get(Proposal, pid).status == ProposalStatus.MERGED
        assert db.get(Finding, fid).status == FindingStatus.RESOLVED


def test_gitlab_close_requeues_finding():
    repo_id, secret = _setup()
    pid, fid = _seed_open_proposal(repo_id, "https://git.example/g/-/merge_requests/41")
    body = json.dumps(
        {
            "object_attributes": {
                "action": "close",
                "url": "https://git.example/g/-/merge_requests/41",
            }
        }
    ).encode()
    r = client.post(
        f"/hooks/gitlab/{repo_id}",
        content=body,
        headers={"X-Gitlab-Token": secret, "X-Gitlab-Event": "Merge Request Hook"},
    )
    assert r.status_code == 202
    with session_scope() as db:
        assert db.get(Proposal, pid).status == ProposalStatus.CLOSED
        assert db.get(Finding, fid).status == FindingStatus.OPEN
