"""Slice F: delivery mechanics, provider sync, issue filing."""

import json
from pathlib import Path
from unittest import mock

import pytest
from sqlalchemy import select

from security_agent.control import repos
from security_agent.db.models import (
    Finding,
    FindingStatus,
    Proposal,
    ProposalStatus,
    RepoKind,
    ScanRun,
)
from security_agent.db.session import session_scope
from security_agent.sandbox import tools
from security_agent.worker import build_graph
from security_agent.worker import deliver as deliver_mod
from security_agent.worker.deliver import (
    DeliverError,
    branch_name,
    detect_provider,
    open_issue,
    open_pr,
    query_pr_state,
    reconcile_pr,
    render_issue,
    render_pr,
    run_deliver,
    sync_proposal_states,
)

_GIT_IDENTITY = ["-c", "user.email=t@t", "-c", "user.name=t"]


def _git_run(args: list[str], cwd: Path) -> str:
    return tools.run_allowlisted("git", args, cwd=str(cwd))


def _remote(path: Path, files: dict[str, str]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        target = path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    _git_run(["init", "-b", "main", str(path)], path)
    _git_run(["-C", str(path), "add", "."], path)
    _git_run(["-C", str(path), *_GIT_IDENTITY, "commit", "-m", "x"], path)
    return path


def _capture_patch(repo: Path, rel: str, new_content: str) -> str:
    (repo / rel).write_text(new_content)
    patch = _git_run(["-C", str(repo), "diff", "--", rel], repo)
    _git_run(["-C", str(repo), "checkout", "--", rel], repo)
    assert patch
    return patch


def _connect_local(tag: str, local_path: str):
    return repos.connect_repo(tag, RepoKind.LOCAL, local_path=local_path)


def _seed_proposal(repo_id: int, package: str, advisory: str, patch: str, kev: bool = False) -> int:
    with session_scope() as db:
        finding = Finding(
            repo_id=repo_id,
            package=package,
            installed_version="1.0.0",
            advisory_id=advisory,
            fixed_versions=["1.0.1"],
            kev_exploited=kev,
            status=FindingStatus.PROPOSED,
        )
        db.add(finding)
        db.flush()
        proposal = Proposal(
            repo_id=repo_id,
            finding_ids=[finding.id],
            package_from="1.0.0",
            package_to="1.0.1",
            verification_result="repo tests passed",
            ignored_tests=[],
            patch=patch,
        )
        db.add(proposal)
        db.flush()
        return proposal.id


def test_branch_name_shapes():
    assert branch_name("left-pad", ["CVE-2026-0001"]) == "security/left-pad-CVE-2026-0001"
    multi = branch_name("left-pad", ["CVE-2", "CVE-1"])
    assert multi == "security/left-pad-CVE-1-plus-1-more"
    assert branch_name("@scope/pkg", ["GHSA-x"]) == "security/scope-pkg-GHSA-x"


def test_detect_provider():
    assert detect_provider("https://github.com/o/r.git") == ("github", "o/r")
    assert detect_provider("git@github.com:o/r.git") == ("github", "o/r")
    assert detect_provider("https://gitlab.example.com/a/b/c") == ("gitlab", "a/b/c")
    assert detect_provider("git@gitlab.com:o/r.git") == ("gitlab", "o/r")
    assert detect_provider("https://git.example.com/r.git") is None


def test_render_pr_and_issue_templates():
    title, body = render_pr(
        "left-pad",
        "1.0.0",
        "1.0.1",
        ["CVE-1"],
        ["CVE-1"],
        ["repo tests passed"],
        "single package",
        [],
        "http://dash/repos/1/findings",
    )
    assert title.startswith("[security] left-pad 1.0.0→1.0.1")
    assert "WARNING: CVE-1 is CISA KEV exploited." in body
    assert "Dashboard: http://dash/repos/1/findings" in body
    ititle, ibody = render_issue("p", "ADV", "do X", "http://dash")
    assert "manual upgrade needed" in ititle and "do X" in ibody


def test_local_delivery_end_to_end(tmp_path):
    remote = _remote(tmp_path / "remote", {"a.js": "a1\n"})
    main_tip = _git_run(["-C", str(remote), "rev-parse", "main"], remote).strip()
    patch = _capture_patch(remote, "a.js", "a1\na2\n")
    repo = _connect_local("deliv-r", str(remote))
    pid = _seed_proposal(repo.id, "left-pad", "CVE-2026-0001", patch, kev=True)
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    result = run_deliver(repo.id, run_id, delivery_root=tmp_path / "out")
    assert result["proposal_ids"] == [pid] and result["errors"] == []
    assert _git_run(["-C", str(remote), "rev-parse", "main"], remote).strip() == main_tip
    branches = _git_run(["-C", str(remote), "branch", "--list", "security/*"], remote)
    assert "security/left-pad-CVE-2026-0001" in branches
    author = _git_run(
        ["-C", str(remote), "log", "-1", "--format=%an/%ae", "security/left-pad-CVE-2026-0001"],
        remote,
    )
    assert author.strip() == "security-agent-bot/security-agent@localhost"
    patches = list((tmp_path / "out" / f"run-{run_id}").glob("*.patch"))
    assert len(patches) == 1
    with session_scope() as db:
        row = db.get(Proposal, pid)
        assert row is not None and row.pr_state == "branch-only"
        assert row.branch == "security/left-pad-CVE-2026-0001"


def test_grouped_proposals_share_one_branch(tmp_path):
    remote = _remote(tmp_path / "remote", {"a.js": "a1\n", "b.js": "b1\n"})
    patch_a = _capture_patch(remote, "a.js", "a1\na2\n")
    patch_b = _capture_patch(remote, "b.js", "b1\nb2\n")
    repo = _connect_local("group-r", str(remote))
    p1 = _seed_proposal(repo.id, "left-pad", "CVE-1", patch_a)
    p2 = _seed_proposal(repo.id, "left-pad", "CVE-2", patch_b)
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    result = run_deliver(repo.id, run_id, delivery_root=tmp_path / "out")
    assert sorted(result["proposal_ids"]) == sorted([p1, p2])
    with session_scope() as db:
        assert db.get(Proposal, p1).branch == db.get(Proposal, p2).branch
        assert "plus-1-more" in (db.get(Proposal, p1).branch or "")


def test_base_branch_override_and_unknown_base(tmp_path):
    remote = _remote(tmp_path / "remote", {"a.js": "a1\n"})
    _git_run(["-C", str(remote), "checkout", "-b", "dev"], remote)
    _git_run(["-C", str(remote), "checkout", "main"], remote)
    patch = _capture_patch(remote, "a.js", "a1\na2\n")
    repo = _connect_local("base-r", str(remote))
    with session_scope() as db:
        db.get(type(repo), repo.id).default_branch = "dev"
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    pid = _seed_proposal(repo.id, "left-pad", "CVE-1", patch)
    result = run_deliver(repo.id, run_id, delivery_root=tmp_path / "out")
    assert result["proposal_ids"] == [pid]
    dev_tip = _git_run(["-C", str(remote), "rev-parse", "dev"], remote).strip()
    parent = _git_run(["-C", str(remote), "rev-parse", "security/left-pad-CVE-1^"], remote).strip()
    assert parent == dev_tip
    with session_scope() as db:
        db.get(type(repo), repo.id).default_branch = "nope"
    pid2 = _seed_proposal(repo.id, "left-pad", "CVE-2", patch)
    result2 = run_deliver(repo.id, run_id, delivery_root=tmp_path / "out")
    assert result2["proposal_ids"] == [] and len(result2["errors"]) == 1
    with session_scope() as db:
        assert db.get(Proposal, pid2).branch is None


def test_unsafe_base_branch_rejected(tmp_path):
    from security_agent.worker.deliver import DeliverError, _checkout_base

    repo = _remote(tmp_path / "remote", {"a.js": "a1\n"})
    for unsafe in ("--upload-pack=evil", "../escape", "main@{1}", "a b", "x~1"):
        with pytest.raises(DeliverError, match="unsafe base branch"):
            _checkout_base(repo, unsafe)
    assert _checkout_base(repo, "main") == "main"


def test_patch_conflict_records_error(tmp_path):
    remote = _remote(tmp_path / "remote", {"a.js": "a1\n"})
    repo = _connect_local("conflict-r", str(remote))
    pid = _seed_proposal(repo.id, "left-pad", "CVE-1", "not a patch\n")
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    result = run_deliver(repo.id, run_id, delivery_root=tmp_path / "out")
    assert result["proposal_ids"] == [] and result["errors"]
    with session_scope() as db:
        assert db.get(Proposal, pid).branch is None


def test_open_pr_and_issue_apis_mocked():
    post_resp = mock.Mock()
    post_resp.json.return_value = {"html_url": "https://github.com/o/r/pull/1"}
    with mock.patch.object(deliver_mod.httpx, "post", return_value=post_resp) as fake:
        url = open_pr("github", "o/r", "github.com", "tok", "t", "b", "head", "main")
    assert url.endswith("/pull/1")
    _args, kwargs = fake.call_args
    assert kwargs["json"]["draft"] is False and kwargs["json"]["head"] == "head"
    get_resp = mock.Mock()
    get_resp.json.return_value = {"id": 42}
    mr_resp = mock.Mock()
    mr_resp.json.return_value = {"web_url": "https://git.example/o/r/-/merge_requests/2"}
    with (
        mock.patch.object(deliver_mod.httpx, "get", return_value=get_resp),
        mock.patch.object(deliver_mod.httpx, "post", return_value=mr_resp) as fake_post,
    ):
        url = open_pr("gitlab", "o/r", "git.example", "tok", "t", "b", "h", "main")
    assert url.endswith("/merge_requests/2")
    assert "/projects/42/merge_requests" in fake_post.call_args[0][0]
    issue_resp = mock.Mock()
    issue_resp.json.return_value = {"html_url": "https://github.com/o/r/issues/3"}
    with mock.patch.object(deliver_mod.httpx, "post", return_value=issue_resp):
        assert open_issue("github", "o/r", "github.com", "tok", "t", "b").endswith("/issues/3")
    bad = mock.Mock()
    bad.raise_for_status.side_effect = RuntimeError("403")
    with (
        mock.patch.object(deliver_mod.httpx, "post", return_value=bad),
        pytest.raises(DeliverError, match="PR open failed"),
    ):
        open_pr("github", "o/r", "github.com", "tok", "t", "b", "h", "main")


def test_git_delivery_needs_token(tmp_path):
    repo = repos.connect_repo("notok-r", RepoKind.GIT, url="https://example.com/r.git")
    template = _remote(tmp_path / "template", {"a.js": "a1\n"})
    patch = _capture_patch(template, "a.js", "a1\na2\n")
    pid = _seed_proposal(repo.id, "left-pad", "CVE-1", patch)
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    result = run_deliver(repo.id, run_id, source_dir=template, delivery_root=tmp_path / "out")
    assert result["proposal_ids"] == [] and any("token" in e for e in result["errors"])
    with session_scope() as db:
        assert db.get(Proposal, pid).branch is None


def test_issue_filing_local_and_provider(tmp_path):
    remote = _remote(tmp_path / "remote", {"a.js": "a1\n"})
    repo = _connect_local("issue-r", str(remote))
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
        finding = Finding(
            repo_id=repo.id,
            package="left-pad",
            installed_version="1.0.0",
            advisory_id="CVE-9",
            status=FindingStatus.UNPATCHABLE,
            guidance="upgrade manually",
        )
        db.add(finding)
        db.flush()
        fid = finding.id
    result = run_deliver(repo.id, run_id, delivery_root=tmp_path / "out")
    assert result["issues"] == [fid]
    files = list((tmp_path / "out" / f"run-{run_id}").glob("issue-*.md"))
    assert len(files) == 1 and "upgrade manually" in files[0].read_text()


def test_sync_and_reconcile_lifecycle(tmp_path):
    repo = repos.connect_repo("sync-r", RepoKind.GIT, url="https://github.com/o/r.git")
    repos.store_repo_token(repo.id, "tok")
    patch = "x\n"
    pid = _seed_proposal(repo.id, "left-pad", "CVE-1", patch)
    with session_scope() as db:
        row = db.get(Proposal, pid)
        assert row is not None
        row.pr_url = "https://github.com/o/r/pull/7"
        fid = row.finding_ids[0]
    with mock.patch.object(deliver_mod, "query_pr_state", return_value=("closed", True)):
        assert sync_proposal_states(repo.id) == {"synced": 1}
    with session_scope() as db:
        assert db.get(Proposal, pid).status == ProposalStatus.MERGED
        assert db.get(Finding, fid).status == FindingStatus.RESOLVED
    assert reconcile_pr("https://github.com/o/r/pull/unknown", True, True) is False
    assert reconcile_pr("", True, True) is False


def test_query_pr_state_url_shapes():
    gh = mock.Mock()
    gh.json.return_value = {"state": "closed", "merged": True}
    with mock.patch.object(deliver_mod.httpx, "get", return_value=gh) as fake:
        assert query_pr_state("https://github.com/o/r/pull/7", "tok") == ("closed", True)
        assert "/repos/o/r/pulls/7" in fake.call_args[0][0]
    proj = mock.Mock()
    proj.json.return_value = {"id": 9}
    mr = mock.Mock()
    mr.json.return_value = {"state": "merged"}
    with mock.patch.object(deliver_mod.httpx, "get", side_effect=[proj, mr]):
        state, merged = query_pr_state("https://git.example/g/sub/-/merge_requests/4", "tok")
        assert (state, merged) == ("merged", True)
    with pytest.raises(DeliverError, match="unrecognized"):
        query_pr_state("https://example.com/x", "tok")


def test_max_version_prefers_semver(tmp_path):
    assert deliver_mod._max_version(["4.17.21", "4.9.0"]) == "4.17.21"
    assert deliver_mod._max_version(["1.0.0", "not-a-version"]) == "1.0.0"
    assert deliver_mod._max_version(["bbb", "aaa"]) == "bbb"


def _push_fake(origin: str, *, fail_push: str = ""):
    def _fake(name, args, **kwargs):
        if args[:2] == ["remote", "get-url"]:
            return origin + "\n"
        if args[0] == "push" and fail_push:
            raise RuntimeError(fail_push)
        return ""

    return mock.patch.object(deliver_mod, "run_allowlisted", side_effect=_fake)


def test_push_branch_authenticates_momentarily(tmp_path):
    with _push_fake("https://example.com/r.git") as fake:
        deliver_mod._push_branch(tmp_path, "security/x", "tok-SECRET")
    calls = [c[0][1] for c in fake.call_args_list]
    assert calls[0] == ["remote", "get-url", "origin"]
    assert calls[1][:3] == ["remote", "set-url", "origin"]
    assert "tok-SECRET" in calls[1][3]
    assert fake.call_args_list[1][1]["redact"] == ("tok-SECRET",)
    assert calls[2] == ["push", "--force-with-lease", "origin", "security/x"]
    assert calls[3] == ["remote", "set-url", "origin", "https://example.com/r.git"]


def test_push_branch_failure_redacts_and_restores(tmp_path):
    with _push_fake(
        "https://example.com/r.git", fail_push="remote: Invalid credentials tok-SECRET"
    ) as fake:
        with pytest.raises(DeliverError) as exc_info:
            deliver_mod._push_branch(tmp_path, "security/x", "tok-SECRET")
    assert "tok-SECRET" not in str(exc_info.value)
    assert fake.call_args_list[-1][0][1] == [
        "remote",
        "set-url",
        "origin",
        "https://example.com/r.git",
    ]


def test_push_branch_file_origin_needs_no_token(tmp_path):
    with _push_fake("file:///tmp/remote.git") as fake:
        deliver_mod._push_branch(tmp_path, "security/x", "tok-SECRET")
    assert [c[0][1][0] for c in fake.call_args_list] == ["remote", "push"]


def test_piggyback_sync_on_every_scan(tmp_path):
    from security_agent.worker import scan as scan_mod

    repo = repos.connect_repo("pig-r", RepoKind.GIT, url="https://example.com/p.git")
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {}}))
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    with (
        mock.patch.object(scan_mod, "scan_lockfile", return_value={"results": []}),
        mock.patch.object(scan_mod, "kev_exploited_ids", return_value=set()),
        mock.patch(
            "security_agent.worker.deliver.sync_proposal_states", return_value={"synced": 0}
        ) as fake_sync,
    ):
        scan_mod.run_scan(repo.id, run_id, source_dir=tmp_path)
        fake_sync.assert_called_once_with(repo.id)  # every trigger resyncs (FR-5 D5)


def test_ancestry_sync_observes_local_merge(tmp_path):
    bare = tmp_path / "remote.git"
    tools.run_allowlisted("git", ["init", "--bare", "-b", "main", str(bare)])
    work = tmp_path / "work"
    tools.run_allowlisted("git", ["clone", f"file://{bare}", str(work)])
    (work / "a.js").write_text("a1\n")
    tools.run_allowlisted("git", ["-C", str(work), "add", "."])
    tools.run_allowlisted(
        "git", ["-C", str(work), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "x"]
    )
    tools.run_allowlisted("git", ["-C", str(work), "push", "origin", "main"])
    branch = "security/left-pad-CVE-1"
    tools.run_allowlisted("git", ["-C", str(work), "checkout", "-b", branch])
    (work / "a.js").write_text("a1\na2\n")
    tools.run_allowlisted("git", ["-C", str(work), "commit", "-am", "fix"])
    tools.run_allowlisted("git", ["-C", str(work), "push", "origin", branch])
    tools.run_allowlisted("git", ["-C", str(work), "checkout", "main"])
    tools.run_allowlisted("git", ["-C", str(work), "merge", "--no-ff", branch, "-m", "merge"])
    tools.run_allowlisted("git", ["-C", str(work), "push", "origin", "main"])
    repo = repos.connect_repo("ancestry-r", RepoKind.LOCAL, local_path=str(bare))
    with session_scope() as db:
        finding = Finding(
            repo_id=repo.id,
            package="left-pad",
            installed_version="1.0.0",
            advisory_id="CVE-ANC",
            status=FindingStatus.PROPOSED,
        )
        db.add(finding)
        db.flush()
        proposal = Proposal(
            repo_id=repo.id,
            finding_ids=[finding.id],
            package_from="1.0.0",
            package_to="1.0.1",
            verification_result="v",
            branch=branch,
            base_branch="main",
            pr_state="branch-only",
        )
        db.add(proposal)
        db.flush()
        pid, fid = proposal.id, finding.id
    assert sync_proposal_states(repo.id) == {"synced": 1}
    with session_scope() as db:
        assert db.get(Proposal, pid).status == ProposalStatus.MERGED
        assert db.get(Finding, fid).status == FindingStatus.RESOLVED


def test_delivered_pr_requests_merge_gate(tmp_path):
    bare = tmp_path / "remote.git"
    tools.run_allowlisted("git", ["init", "--bare", "-b", "main", str(bare)])
    template = tmp_path / "template"
    tools.run_allowlisted("git", ["clone", f"file://{bare}", str(template)])
    (template / "a.js").write_text("a1\n")
    tools.run_allowlisted("git", ["-C", str(template), "add", "."])
    tools.run_allowlisted(
        "git",
        ["-C", str(template), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "x"],
    )
    tools.run_allowlisted("git", ["-C", str(template), "push", "origin", "main"])
    (template / "a.js").write_text("a1\na2\n")
    patch = tools.run_allowlisted("git", ["-C", str(template), "diff", "--", "a.js"])
    tools.run_allowlisted("git", ["-C", str(template), "checkout", "--", "a.js"])
    repo = repos.connect_repo("gate-r", RepoKind.GIT, url="https://github.com/o/gate.git")
    repos.store_repo_token(repo.id, "tok")
    pid = _seed_proposal(repo.id, "left-pad", "CVE-GATE", patch)
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    with mock.patch.object(deliver_mod, "open_pr", return_value="https://github.com/o/gate/pull/1"):
        result = run_deliver(repo.id, run_id, source_dir=template, delivery_root=tmp_path / "out")
    assert result["proposal_ids"] == [pid]
    with session_scope() as db:
        from security_agent.db.models import Approval, GateAction, GateStatus

        gate = db.scalar(
            select(Approval).where(Approval.repo_id == repo.id, Approval.action == GateAction.MERGE)
        )
        assert gate is not None and gate.status == GateStatus.PENDING
        assert gate.proposal_id == pid


def test_run_deliver_unknown_ids_and_prod_refuses(tmp_path):
    with pytest.raises(ValueError, match="Unknown repo"):
        run_deliver(999999, 1, delivery_root=tmp_path)
    settings = mock.Mock(is_prod=True, sandbox_backend="docker")
    with (
        mock.patch("security_agent.config.get_settings", return_value=settings),
        mock.patch("security_agent.sandbox.shutil.which", return_value=None),
    ):
        with pytest.raises(PermissionError, match="Docker sandbox"):
            run_deliver(1, 1)


def test_commit_signing_argv(tmp_path):
    key = tmp_path / "bot_key"
    key.write_text("fake-key-material")
    settings = mock.Mock(bot_name="b", bot_email="e@x", bot_signing_key=str(key))
    with (
        mock.patch("security_agent.config.get_settings", return_value=settings),
        mock.patch.object(deliver_mod, "run_allowlisted") as fake,
    ):
        assert deliver_mod._commit(tmp_path, "t", "b") is True
    argv = fake.call_args[0][1]
    assert "-S" in argv and "gpg.format=ssh" in " ".join(argv)
    settings_nokey = mock.Mock(bot_name="b", bot_email="e@x", bot_signing_key="")
    with (
        mock.patch("security_agent.config.get_settings", return_value=settings_nokey),
        mock.patch.object(deliver_mod, "run_allowlisted") as fake,
    ):
        assert deliver_mod._commit(tmp_path, "t", "b") is False
    assert "-S" not in fake.call_args[0][1]


def _signing_key_or_skip(tmp_path: Path) -> Path:
    """Throwaway ed25519 key, or skip when this environment cannot ssh-sign."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    key = tmp_path / "bot_key"
    key.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
        )
    )
    key.chmod(0o600)
    probe = tmp_path / "probe"
    try:
        _remote(probe, {"a.js": "a1\n"})
        _git_run(
            [
                "-C",
                str(probe),
                "-c",
                "user.name=b",
                "-c",
                "user.email=e@x",
                "-c",
                "gpg.format=ssh",
                "-c",
                f"user.signingkey={key}",
                "commit",
                "--amend",
                "--no-edit",
                "-S",
            ],
            probe,
        )
    except RuntimeError:
        pytest.skip("ssh signing unavailable in this environment")
    return key


def test_signed_commit_when_key_configured(tmp_path):
    key = _signing_key_or_skip(tmp_path)
    remote = _remote(tmp_path / "remote", {"a.js": "a1\n"})
    patch = _capture_patch(remote, "a.js", "a1\na2\n")
    repo = _connect_local("sign-r", str(remote))
    pid = _seed_proposal(repo.id, "left-pad", "CVE-1", patch)
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
    settings = mock.Mock(
        public_url="http://t",
        bot_name="b",
        bot_email="e@x",
        bot_signing_key=str(key),
        is_prod=False,
    )
    with mock.patch("security_agent.config.get_settings", return_value=settings):
        result = run_deliver(repo.id, run_id, delivery_root=tmp_path / "out")
    assert result["proposal_ids"] == [pid]
    raw = _git_run(["-C", str(remote), "cat-file", "commit", "security/left-pad-CVE-1"], remote)
    assert "gpgsig" in raw


def test_graph_deliver_node_runs_real_delivery():
    with (
        mock.patch("security_agent.worker.news.poll_news", return_value={}),
        mock.patch(
            "security_agent.worker.news.run_matcher", return_value={"items": 0, "boosts": 0}
        ),
        mock.patch("security_agent.worker.scan.run_scan", return_value={"finding_ids": []}),
        mock.patch(
            "security_agent.worker.reachability.run_reachability",
            return_value={"verdict_ids": []},
        ),
        mock.patch(
            "security_agent.worker.patch.run_patch",
            return_value={"proposal_ids": []},
        ),
        mock.patch.object(
            deliver_mod, "run_deliver", return_value={"status": "done", "proposal_ids": [5]}
        ) as fake,
        mock.patch(
            "security_agent.control.gates.run_merge",
            return_value={"status": "done", "merged": [], "skipped": [5]},
        ),
    ):
        result = build_graph().invoke({"repo_id": 1, "run_id": 2})
    fake.assert_called_once_with(1, 2)
    assert result["proposals"] == [{"id": 5}]


def test_purge_old_deliveries_prunes_stale_run_dirs(tmp_path):
    """Per-run delivery dirs past retention are removed (H5 #21)."""
    import os
    import time

    from security_agent.worker.deliver import purge_old_deliveries

    root = tmp_path / "deliveries"
    old, new = root / "run-1", root / "run-2"
    old.mkdir(parents=True)
    (old / "0001.patch").write_text("old")
    new.mkdir(parents=True)
    (new / "0001.patch").write_text("new")
    aged = time.time() - 31 * 86400
    os.utime(old, (aged, aged))
    assert purge_old_deliveries(root) == 1
    assert not old.exists() and (new / "0001.patch").read_text() == "new"
    assert purge_old_deliveries(root / "missing") == 0
