"""Worker wiring: guidance in prompts, parked runs short-circuit."""

import subprocess
from types import SimpleNamespace
from unittest import mock

import pytest

from security_agent.brain.adapt import make_model_adapt
from security_agent.db.models import Finding, Repo, RepoKind, RunTrigger, ScanRun
from security_agent.db.session import session_scope
from security_agent.policy.service import create_document
from security_agent.worker.patch import _mark_unpatchable, run_patch


@pytest.fixture(autouse=True)
def _no_embeddings():
    with mock.patch("security_agent.brain.embeddings.embed_texts", return_value=None):
        yield


def _repo(name: str) -> int:
    # Direct insert: connect_repo enqueues a RUNNING scan that would trip
    # the single-flight invariant when a test adds its own run.
    with session_scope() as db:
        repo = Repo(name=name, kind=RepoKind.GIT, url=f"https://example.com/{name}.git")
        db.add(repo)
        db.flush()
        return repo.id


def _finding(repo_id: int, package: str) -> int:
    with session_scope() as db:
        row = Finding(
            repo_id=repo_id,
            package=package,
            installed_version="1.0.0",
            advisory_id="CVE-WIRE-1",
        )
        db.add(row)
        db.flush()
        return row.id


def test_adapt_prompt_carries_policy_guidance(tmp_path):
    repo_id = _repo("wire-adapt")
    create_document(
        scope="platform",
        title="Adapt policy",
        text="When adapting pkgwire, keep the diff minimal and note why.",
        embed=False,
    )
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)  # noqa: S603, S607
    (tmp_path / "index.js").write_text("require('pkgwire');\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)  # noqa: S603, S607

    prompts: list[str] = []

    class _Model:
        def bind_tools(self, tools):
            return self

        def invoke(self, prompt):
            prompts.append(prompt)
            return SimpleNamespace(tool_calls=[], usage_metadata={}, content="")

    finding = SimpleNamespace(
        package="pkgwire",
        installed_version="1.0.0",
        advisory_id="CVE-WIRE-1",
        repo_id=repo_id,
    )
    adapt = make_model_adapt(model=_Model(), probe_ok=True)
    adapt(tmp_path, finding, "2.0.0", [])
    assert prompts and "keep the diff minimal" in prompts[0]


def test_unpatchable_guidance_appends_policy_notes():
    repo_id = _repo("wire-unpatch")
    create_document(
        scope="platform",
        title="Unpatch policy",
        text="Manual upgrades of legacywire need a changelog entry.",
        embed=False,
    )
    finding_id = _finding(repo_id, "legacywire")
    _mark_unpatchable(finding_id, "No verified fix.")
    with session_scope() as db:
        row = db.get(Finding, finding_id)
        assert row is not None and "Policy notes" in (row.guidance or "")
        assert "changelog entry" in (row.guidance or "")


def test_run_patch_short_circuits_parked_runs():
    repo_id = _repo("wire-park")
    with session_scope() as db:
        run = ScanRun(repo_id=repo_id, trigger=RunTrigger.MANUAL, parked=True)
        db.add(run)
        db.flush()
        run_id = run.id
    out = run_patch(repo_id, run_id)
    assert out["status"] == "parked" and out["proposal_ids"] == []


def test_run_patch_blocks_matching_group_end_to_end():
    from sqlalchemy import select

    from security_agent.control import repos as repo_svc
    from security_agent.db.models import FindingStatus, RepoKind, Verdict
    from security_agent.policy.rules import confirm_rule, create_rule

    repo = repo_svc.connect_repo(
        "wire-block", RepoKind.GIT, url="https://example.com/wire-block.git"
    )
    with session_scope() as db:
        run_id = db.scalar(select(ScanRun.id).where(ScanRun.repo_id == repo.id))
        row = Finding(
            repo_id=repo.id,
            package="stop-lib",
            installed_version="1.0.0",
            advisory_id="CVE-WIRE-2",
            fixed_versions=["1.0.1"],
        )
        db.add(row)
        db.flush()
        db.add(Verdict(finding_id=row.id, run_id=run_id, reachable=True))
        db.flush()
        finding_id = row.id
    rule = create_rule(
        scope="platform",
        effect="block",
        match={"package": "stop-lib"},
        reason="do not touch",
    )
    confirm_rule(rule.rule_key)
    out = run_patch(repo.id, run_id)
    assert out["proposal_ids"] == []
    assert [r["outcome"] for r in out["results"]] == ["blocked"]
    with session_scope() as db:
        row = db.get(Finding, finding_id)
        assert row is not None and row.status == FindingStatus.OPEN
        assert (row.policy_block or {}).get("rule_key") == rule.rule_key


def test_run_patch_parks_when_policy_store_fails():
    from security_agent.policy.service import PolicyStoreError

    repo_id = _repo("wire-pppark")
    with session_scope() as db:
        run = ScanRun(repo_id=repo_id, trigger=RunTrigger.MANUAL)
        db.add(run)
        db.flush()
        run_id = run.id
    with mock.patch(
        "security_agent.policy.enforce.pre_patch_check",
        side_effect=PolicyStoreError("db gone"),
    ):
        out = run_patch(repo_id, run_id)
    assert out["status"] == "parked"
    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        assert run is not None and run.parked
