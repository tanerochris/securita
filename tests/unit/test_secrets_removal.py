"""H5 Slice D: removal redaction, proposals, secret delivery."""

from pathlib import Path

from sqlalchemy import select

from security_agent.control import repos as repo_svc
from security_agent.db.models import (
    Proposal,
    ProposalStatus,
    RepoKind,
    ScanRun,
    SecretFinding,
    SecretStatus,
)
from security_agent.db.session import session_scope
from security_agent.sandbox import tools
from security_agent.worker import deliver as deliver_mod
from security_agent.worker import secrets as secrets_mod
from security_agent.worker.secrets import apply_removal, plan_removal, redact_line

_GIT_IDENTITY = ["-c", "user.email=t@t", "-c", "user.name=t"]
_FP = "ff" * 32
_VALUE = "ghp_FAKEVALUE0000000000000000000000"


def _git(args: list[str], cwd: Path) -> str:
    return tools.run_allowlisted("git", args, cwd=str(cwd))


def _repo_with(path: Path, files: dict[str, str]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        target = path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    _git(["init", "-b", "main", str(path)], path)
    _git(["-C", str(path), "add", "."], path)
    _git(["-C", str(path), *_GIT_IDENTITY, "commit", "-m", "x"], path)
    return path


def _report(path: str, line: int, value: str = _VALUE, fp: str = _FP) -> dict:
    return {
        "findings": [
            {
                "rule_id": "github-pat",
                "match": {"value": value, "fingerprint": fp},
                "location": {"path": path, "start_line": line},
                "analysis": {"status": "valid"},
            }
        ],
        "scan": {"state": "complete", "config_hash": "cfg-1"},
    }


def _open_secret(repo_id: int, run_id: int, path: str = ".env", fp: str = _FP) -> int:
    with session_scope() as db:
        row = SecretFinding(
            repo_id=repo_id,
            rule_id="github-pat",
            path=path,
            start_line=1,
            fingerprint=fp,
            liveness="live",
            status=SecretStatus.OPEN,
            guidance="rotate",
            first_run_id=run_id,
        )
        db.add(row)
        db.flush()
        return row.id


def _connect(path: Path, tag: str):
    repo = repo_svc.connect_repo(tag, RepoKind.LOCAL, local_path=str(path))
    with session_scope() as db:
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        assert run is not None
        return repo.id, run.id


def test_redact_line_shapes():
    assert redact_line(f"GITHUB_TOKEN={_VALUE}", _VALUE) == "GITHUB_TOKEN=${GITHUB_TOKEN}"
    assert redact_line(f"export KEY={_VALUE}  # keep", _VALUE) == ("export KEY=${KEY}  # keep")
    assert redact_line(f'token: "{_VALUE}"', _VALUE) == 'token: "${token}"'
    assert redact_line(f"prefix {_VALUE} suffix", _VALUE) == "prefix ***REMOVED*** suffix"
    assert redact_line("nothing here", _VALUE) is None
    assert redact_line(f"KEY={_VALUE}", "") is None


def test_plan_apply_roundtrip_redacts_and_tracks(tmp_path):
    workdir = _repo_with(tmp_path / "r", {".env": f"GITHUB_TOKEN={_VALUE}\n"})
    plan = plan_removal(_report(".env", 1), {_FP})
    assert set(plan) == {".env"}
    touched, skipped, fps = apply_removal(workdir, plan)
    assert skipped == {} and fps == {_FP} and touched == {".env": [1]}
    assert (workdir / ".env").read_text() == "GITHUB_TOKEN=${GITHUB_TOKEN}\n"
    # Plan entries without values (path-only rules) plan nothing.
    assert plan_removal({"findings": [{"match": {"fingerprint": _FP}}]}, {_FP}) == {}


def test_apply_preserves_crlf_endings(tmp_path):
    workdir = tmp_path / "r"
    workdir.mkdir()
    (workdir / ".env").write_bytes(f"GITHUB_TOKEN={_VALUE}\r\nOTHER=1\r\n".encode())
    _git(["init", "-b", "main", str(workdir)], workdir)
    _git(["-C", str(workdir), "add", "."], workdir)
    _git(["-C", str(workdir), *_GIT_IDENTITY, "commit", "-m", "x"], workdir)
    plan = plan_removal(_report(".env", 1), {_FP})
    touched, skipped, _ = apply_removal(workdir, plan)
    assert skipped == {} and touched == {".env": [1]}
    assert (workdir / ".env").read_bytes() == b"GITHUB_TOKEN=${GITHUB_TOKEN}\r\nOTHER=1\r\n"


def test_apply_refuses_untracked_stale_and_escapes(tmp_path):
    workdir = _repo_with(tmp_path / "r", {".env": f"GITHUB_TOKEN={_VALUE}\n"})
    (workdir / "loose.txt").write_text(_VALUE)  # untracked
    plan = plan_removal(_report("loose.txt", 1), {_FP})
    _, skipped, _ = apply_removal(workdir, plan)
    assert skipped == {"loose.txt": "file not tracked in git"}
    plan = plan_removal(_report(".env", 99), {_FP})  # line past EOF
    _, skipped, _ = apply_removal(workdir, plan)
    assert skipped == {".env": "stale scanner location"}
    plan = plan_removal(_report("../escape.txt", 1), {_FP})
    _, skipped, _ = apply_removal(workdir, plan)
    assert skipped == {"../escape.txt": "file not tracked in git"}


def test_removal_proposes_verified_proposal(tmp_path, monkeypatch):
    workdir = _repo_with(tmp_path / "r", {".env": f"GITHUB_TOKEN={_VALUE}\n"})
    repo_id, run_id = _connect(workdir, "sec-rem-a")
    sid = _open_secret(repo_id, run_id)
    clean = {"findings": [], "scan": {"state": "complete"}}
    monkeypatch.setattr(secrets_mod, "scan_worktree", lambda _w: clean)
    result = secrets_mod.run_secrets_removal(repo_id, run_id, workdir, _report(".env", 1))
    assert result["skipped"] == {}
    assert len(result["proposal_ids"]) == 1
    with session_scope() as db:
        proposal = db.get(Proposal, result["proposal_ids"][0])
        assert proposal is not None
        assert proposal.secret_finding_id == sid
        assert proposal.finding_ids == []
        assert proposal.patch is None  # re-derived at delivery; values never rest
        assert _VALUE not in repr(
            (proposal.verification_result, proposal.package_from, proposal.package_to)
        )
        row = db.get(SecretFinding, sid)
        assert row is not None and row.status == SecretStatus.PROPOSED
        assert row.proposal_id == proposal.id
    # The scan workdir is proof-only: redaction is verified, then restored,
    # because delivery re-derives the removal from HEAD (H5 R1).
    assert (workdir / ".env").read_text() == f"GITHUB_TOKEN={_VALUE}\n"


def test_removal_skips_when_proposal_already_exists(tmp_path, monkeypatch):
    """A concurrent run's proposal wins; the loser skips with a reason (H5 #31)."""
    workdir = _repo_with(tmp_path / "r", {".env": f"GITHUB_TOKEN={_VALUE}\n"})
    repo_id, run_id = _connect(workdir, "sec-rem-f")
    sid = _open_secret(repo_id, run_id)
    with session_scope() as db:
        db.add(
            Proposal(
                repo_id=repo_id,
                finding_ids=[],
                package_from="github-pat",
                package_to="redacted",
                verification_result="removal verified",
                patch=None,
                secret_finding_id=sid,
            )
        )
    clean = {"findings": [], "scan": {"state": "complete"}}
    monkeypatch.setattr(secrets_mod, "scan_worktree", lambda _w: clean)
    result = secrets_mod.run_secrets_removal(repo_id, run_id, workdir, _report(".env", 1))
    assert result["proposal_ids"] == []
    assert "already exists" in result["skipped"][sid]


def test_removal_refuses_when_rescan_still_flags(tmp_path, monkeypatch):
    workdir = _repo_with(tmp_path / "r", {".env": f"GITHUB_TOKEN={_VALUE}\n"})
    repo_id, run_id = _connect(workdir, "sec-rem-b")
    sid = _open_secret(repo_id, run_id)
    still_dirty = _report(".env", 1)  # verify rescan still flags the fingerprint
    monkeypatch.setattr(secrets_mod, "scan_worktree", lambda _w: still_dirty)
    result = secrets_mod.run_secrets_removal(repo_id, run_id, workdir, _report(".env", 1))
    assert result["proposal_ids"] == []
    assert "rescan still flags" in result["skipped"][sid]
    with session_scope() as db:
        row = db.get(SecretFinding, sid)
        assert row is not None and row.status == SecretStatus.OPEN  # retry next run


def test_secret_delivery_opens_branch_and_never_groups(tmp_path, monkeypatch):
    workdir = _repo_with(
        tmp_path / "r",
        {".env": f"GITHUB_TOKEN={_VALUE}\n", "other.env": f"GITHUB_TOKEN={_VALUE}\n"},
    )
    repo_id, run_id = _connect(workdir, "sec-rem-c")
    sid = _open_secret(repo_id, run_id)
    other = _open_secret(repo_id, run_id, path="other.env", fp="ee" * 32)
    with session_scope() as db:
        for target in (sid, other):
            db.add(
                Proposal(
                    repo_id=repo_id,
                    finding_ids=[],
                    package_from="github-pat",
                    package_to="redacted",
                    verification_result="removal verified",
                    patch=None,
                    secret_finding_id=target,
                )
            )
            row = db.get(SecretFinding, target)
            assert row is not None
            row.status = SecretStatus.PROPOSED
    with session_scope() as db:
        pending = list(
            db.scalars(
                select(Proposal).where(Proposal.repo_id == repo_id, Proposal.branch.is_(None))
            )
        )
        for p in pending:
            db.expunge(p)
        assert len(deliver_mod.group_by_package(pending)) == 2  # never grouped

    def stateful_scan(scan_dir):
        hits = []
        for rel, fp in ((".env", _FP), ("other.env", "ee" * 32)):
            try:
                text = (Path(scan_dir) / rel).read_text()
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if _VALUE in line:
                    hits.append(
                        {
                            "rule_id": "github-pat",
                            "match": {"value": _VALUE, "fingerprint": fp},
                            "location": {"path": rel, "start_line": lineno},
                            "analysis": {"status": "valid"},
                        }
                    )
        return {"findings": hits, "scan": {"state": "complete"}}

    monkeypatch.setattr(secrets_mod, "scan_worktree", stateful_scan)
    result = deliver_mod.run_deliver(repo_id, run_id, delivery_root=tmp_path / "out")
    assert result["errors"] == []
    assert len(result["proposal_ids"]) == 2
    with session_scope() as db:
        rows = list(db.scalars(select(Proposal).where(Proposal.repo_id == repo_id)))
        assert all(r.branch and r.branch.startswith("security/secret-") for r in rows)
        assert all(r.pr_state == "branch-only" for r in rows)
    # No format-patch artifacts: a unified diff would persist the secret
    # bytes via its `-` lines (H5 G2). Nothing under the delivery root may
    # carry secret bytes at all.
    out = tmp_path / "out"
    files = [p for p in out.rglob("*") if p.is_file()] if out.exists() else []
    assert [p for p in files if p.suffix == ".patch"] == []
    assert _VALUE not in "".join(p.read_text(errors="replace") for p in files)
    title, body = deliver_mod.render_secret_pr("github-pat", ".env", "v", "rotate now", "d")
    assert "github-pat" in title and "rotate now" in body
    assert deliver_mod.secret_branch_name("github-pat", 7) == "security/secret-github-pat-7"


def test_pr_closed_unmerged_reopens_secret_but_merge_does_not(tmp_path):
    """A dead removal PR re-proposes; a merged one moves no state (H5 G3)."""
    workdir = _repo_with(tmp_path / "r", {".env": f"GITHUB_TOKEN={_VALUE}\n"})
    repo_id, run_id = _connect(workdir, "sec-rem-e")
    sid = _open_secret(repo_id, run_id)
    with session_scope() as db:
        db.add(
            Proposal(
                repo_id=repo_id,
                finding_ids=[],
                package_from="github-pat",
                package_to="redacted",
                verification_result="removal verified",
                patch=None,
                secret_finding_id=sid,
            )
        )
        db.flush()
        row = db.get(SecretFinding, sid)
        assert row is not None
        row.status = SecretStatus.PROPOSED
        pid = db.scalar(select(Proposal).where(Proposal.secret_finding_id == sid)).id
    assert deliver_mod._apply_provider_state(pid, "closed", False) is True
    with session_scope() as db:
        assert db.get(Proposal, pid).status.value == "closed"
        assert db.get(SecretFinding, sid).status == SecretStatus.OPEN
    with session_scope() as db:
        db.get(SecretFinding, sid).status = SecretStatus.PROPOSED
        db.get(Proposal, pid).status = ProposalStatus.OPEN
    assert deliver_mod._apply_provider_state(pid, "merged", True) is True
    with session_scope() as db:
        assert db.get(Proposal, pid).status.value == "merged"
        assert db.get(SecretFinding, sid).status == SecretStatus.PROPOSED


def test_apply_redacts_space_path_files(tmp_path):
    """`ls-files -z` keeps quoted names matchable (H5 R3)."""
    workdir = _repo_with(tmp_path / "r", {"my secrets.env": f"GITHUB_TOKEN={_VALUE}\n"})
    plan = plan_removal(_report("my secrets.env", 1), {_FP})
    touched, skipped, fps = apply_removal(workdir, plan)
    assert skipped == {} and fps == {_FP} and touched == {"my secrets.env": [1]}
    assert (workdir / "my secrets.env").read_text() == "GITHUB_TOKEN=${GITHUB_TOKEN}\n"


def test_secret_delivery_supersedes_when_already_gone(tmp_path, monkeypatch):
    workdir = _repo_with(tmp_path / "r", {".env": "GITHUB_TOKEN=${GITHUB_TOKEN}\n"})
    repo_id, run_id = _connect(workdir, "sec-rem-d")
    sid = _open_secret(repo_id, run_id)
    with session_scope() as db:
        db.add(
            Proposal(
                repo_id=repo_id,
                finding_ids=[],
                package_from="github-pat",
                package_to="redacted",
                verification_result="removal verified",
                patch=None,
                secret_finding_id=sid,
            )
        )
        row = db.get(SecretFinding, sid)
        assert row is not None
        row.status = SecretStatus.PROPOSED
    monkeypatch.setattr(
        secrets_mod, "scan_worktree", lambda _w: {"findings": [], "scan": {"state": "complete"}}
    )
    result = deliver_mod.run_deliver(repo_id, run_id, delivery_root=tmp_path / "out")
    assert len(result["proposal_ids"]) == 0
    assert any("superseded" in e for e in result["errors"])
    with session_scope() as db:
        proposal = db.scalar(select(Proposal).where(Proposal.secret_finding_id == sid))
        assert proposal is not None and proposal.status.value == "superseded"
    again = deliver_mod.run_deliver(repo_id, run_id, delivery_root=tmp_path / "out")
    assert again["errors"] == []  # superseded once: delivery stops retrying
