"""README guidance sync (D3/D5): repo docs become guidance on every scan.

Root-level README plus SECURITY/CONTRIBUTING files are hashed and
upserted as the repo's guidance document; unchanged content is a no-op.
Guidance-only by construction — extraction never runs on README rows,
so repo-controllable text can never become a guardrail.
"""

import logging
from pathlib import Path

from security_agent.config import get_settings
from security_agent.db.models import Repo
from security_agent.db.session import session_scope

log = logging.getLogger(__name__)

README_FILES = (
    "README.md",
    "README.rst",
    "README.txt",
    "README",
    "SECURITY.md",
    "SECURITY.rst",
    "CONTRIBUTING.md",
    "CONTRIBUTING.rst",
)
_MAX_SINGLE_FILE = 100_000


def collect_readme_text(workdir: Path) -> tuple[str, str] | None:
    """(title, combined_text) from repo doc files, or None when absent."""

    budget = max(10_000, get_settings().policy_readme_max_bytes)
    parts: list[str] = []
    total = 0
    for name in README_FILES:
        candidate = workdir / name
        try:
            if not candidate.is_file() or candidate.stat().st_size > _MAX_SINGLE_FILE:
                continue
            text = candidate.read_text(errors="replace").strip()
        except OSError:
            continue
        if not text:
            continue
        chunk = f"# {name}\n\n{text}"
        if total + len(chunk) > budget:
            break
        parts.append(chunk)
        total += len(chunk)
    if not parts:
        return None
    return ("Repository docs (README)", "\n\n".join(parts))


def sync_repo_readme(repo_id: int, workdir: Path) -> str | None:
    """Upsert the repo's README guidance doc. Returns a run note or None.

    Never raises: README sync must not fail a scan (secrets-stage
    precedent). Returns None when disabled, absent, or unchanged.
    """
    from security_agent.policy.service import tables_ok, upsert_readme_doc

    try:
        if not tables_ok():
            return None
        with session_scope() as db:
            repo = db.get(Repo, repo_id)
            if repo is None or repo.readme_policy_enabled is False:
                return None
            name = repo.name
        collected = collect_readme_text(workdir)
        if collected is None:
            return None
        _, text = collected
        _, changed = upsert_readme_doc(repo_id, title=f"{name} repo docs", text=text)
        if changed:
            return "policy: repo docs ingested as guidance"
        return None
    except Exception as exc:  # noqa: BLE001 - sync never breaks the scan
        log.warning("README policy sync failed for repo %d: %s", repo_id, exc)
        return None
