"""Sandbox-mediated chat investigation (settled #6).

Live repo-content questions (grep, file reads) run against a fresh clone in
a temp dir: the clone itself reuses the worker's allowlisted git path, the
agent-driven pattern goes only to the allowlisted ripgrep tool, and reads
are capped + confined to the clone. Temp dirs are always removed. Output is
flagged untrusted — the agent fences it as data before it enters context.
"""

import shutil
import tempfile
from pathlib import Path

from security_agent.db.models import Repo, RepoKind, User
from security_agent.db.session import session_scope


def _repo_or_raise(repo_id: int) -> Repo:
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        if repo is None:
            raise ValueError(f"Unknown repo #{repo_id}.")
        db.expunge(repo)
        return repo


def _fresh_clone(repo: Repo) -> Path:
    from security_agent.worker.scan import clone_repo

    parent = Path(tempfile.mkdtemp(prefix="chat-inv-"))
    dest = parent / "repo"
    try:
        clone_repo(repo, dest)
    except Exception:
        shutil.rmtree(parent, ignore_errors=True)
        raise
    return dest


def _inside(workdir: Path, rel: str) -> Path:
    target = (workdir / rel).resolve()
    if target != workdir.resolve() and workdir.resolve() not in target.parents:
        raise ValueError("Path escapes the repo; refusing.")
    return target


def investigate_search(user: User, repo_id: int, pattern: str) -> dict:
    """Grep first-party code in a fresh clone. Any signed-in role may read."""
    from security_agent.sandbox.tools import code_search

    _ = user
    repo = _repo_or_raise(repo_id)
    if repo.kind == RepoKind.LOCAL and repo.local_path:
        workdir = Path(repo.local_path)
        cleanup = None
    else:
        workdir = _fresh_clone(repo)
        cleanup = workdir.parent
    try:
        out = str(code_search.invoke({"pattern": pattern, "repo_dir": str(workdir)}))
    finally:
        if cleanup is not None:
            shutil.rmtree(cleanup, ignore_errors=True)
    return {"text": out or "(no matches)", "untrusted": True, "source": f"repo #{repo_id} code"}


def investigate_read(user: User, repo_id: int, path: str, max_chars: int = 8000) -> dict:
    """Read one file from a fresh clone (capped, confined)."""
    from security_agent.worker.scan import read_text_capped

    _ = user
    repo = _repo_or_raise(repo_id)
    if repo.kind == RepoKind.LOCAL and repo.local_path:
        workdir = Path(repo.local_path)
        cleanup = None
    else:
        workdir = _fresh_clone(repo)
        cleanup = workdir.parent
    try:
        target = _inside(workdir, path)
        if not target.is_file():
            raise ValueError(f"No such file: {path}.")
        text = read_text_capped(target, limit=max_chars)
        if text is None:
            raise ValueError(f"Cannot read {path} (oversize or unreadable).")
    finally:
        if cleanup is not None:
            shutil.rmtree(cleanup, ignore_errors=True)
    return {"text": text, "untrusted": True, "source": f"repo #{repo_id} file {path}"}


def investigate_import_chain(user: User, repo_id: int, package: str) -> dict:
    """Why is this package reachable? Import-chain evidence, live or stored.

    Prefers stored verdict evidence (no clone); falls back to a fresh-clone
    analysis when the package has no verdict yet.
    """
    from security_agent.worker.reachability import (
        analyze,
        analyze_python,
        verdict_for_package,
        verdict_for_package_python,
    )

    _ = user
    with session_scope() as db:
        from sqlalchemy import select

        from security_agent.db.models import Finding, Verdict

        finding = db.scalar(
            select(Finding)
            .where(Finding.repo_id == repo_id, Finding.package == package)
            .order_by(Finding.id.desc())
        )
        verdict = None
        if finding is not None:
            verdict = db.scalar(
                select(Verdict).where(Verdict.finding_id == finding.id).order_by(Verdict.id.desc())
            )
            evidence = verdict.evidence if verdict is not None else None
            reachable = verdict.reachable if verdict is not None else None
    if verdict is not None:
        state = "reachable" if reachable else "unreachable"
        return {
            "text": f"{package} is {state} (stored verdict):\n{evidence or 'no evidence recorded'}"
        }
    repo = _repo_or_raise(repo_id)
    if repo.kind == RepoKind.LOCAL and repo.local_path:
        workdir = Path(repo.local_path)
        cleanup = None
    else:
        workdir = _fresh_clone(repo)
        cleanup = workdir.parent
    try:
        node = analyze(workdir)
        py = analyze_python(workdir)
        ok_n, ev_n, _ = verdict_for_package(node, package)
        ok_p, ev_p, _ = verdict_for_package_python(py, package)
    finally:
        if cleanup is not None:
            shutil.rmtree(cleanup, ignore_errors=True)
    if ok_n:
        return {"text": f"{package} is reachable (JS/TS):\n{ev_n}"}
    if ok_p:
        return {"text": f"{package} is reachable (Python):\n{ev_p}"}
    return {"text": f"{package}: no import chain found (treated as unreachable)."}
