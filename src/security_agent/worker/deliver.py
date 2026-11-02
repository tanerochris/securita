"""Patch delivery: PR/MR/branch, bot-signed commits, state sync (FR-5).

Ready-for-review proposals only, one PR per package (grouped when related),
bot identity with SSH signatures when a key is configured, default-branch
targets, minimal template, local branch + format-patch files, provider
state sync via webhooks + per-scan resync. Unpatchable findings get
provider issues, never PRs.
"""

import json
import re
import shutil
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote, urlparse

import httpx
from packaging.version import InvalidVersion, Version
from sqlalchemy import select

from security_agent.control.lifecycle import (
    append_run_note,
    reopen_run,
    transition_finding,
    transition_secret_finding,
)
from security_agent.control.repos import get_repo_token
from security_agent.db.models import (
    Finding,
    FindingStatus,
    Proposal,
    ProposalStatus,
    Repo,
    RepoKind,
    ScanRun,
    SecretStatus,
)
from security_agent.db.session import session_scope
from security_agent.sandbox import assert_host_execution_allowed, make_workdir
from security_agent.sandbox.tools import run_allowlisted
from security_agent.worker.scan import clone_repo

_API_TIMEOUT = 15


class DeliverError(RuntimeError):
    """Expected delivery failure for one group: recorded, proposals stay open."""


def sanitize_branch_part(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-/.")
    return re.sub(r"-{2,}", "-", cleaned) or "x"


def branch_name(package: str, advisories: list[str]) -> str:
    """security/<package>-<advisory> (FR-5 D6)."""
    pkg = sanitize_branch_part(package.replace("/", "-"))
    advs = sorted(set(advisories))
    if len(advs) <= 1:
        return f"security/{pkg}-{sanitize_branch_part(advs[0] if advs else 'x')}"
    first = sanitize_branch_part(advs[0])
    return f"security/{pkg}-{first}-plus-{len(advs) - 1}-more"


def detect_provider(url: str) -> tuple[str, str] | None:
    """(provider, slug) for github/gitlab https + scp-like URLs; else None."""
    if "@" in url and ":" in url and "://" not in url:
        host, _, path = url.partition("@")[2].partition(":")
        slug = path.removesuffix(".git")
    else:
        try:
            parsed = urlparse(url)
        except ValueError:
            return None
        host, slug = parsed.netloc.split("@")[-1], parsed.path.strip("/").removesuffix(".git")
    if not host or not slug:
        return None
    if "github" in host:
        return ("github", slug)
    if "gitlab" in host:
        return ("gitlab", slug)
    return None


def _api_base(provider: str, host: str) -> str:
    if provider == "github":
        return "https://api.github.com" if host == "github.com" else f"https://{host}/api/v3"
    return f"https://{host}/api/v4"


def _provider_host(url: str) -> str:
    if "://" not in url:
        return url.partition("@")[2].partition(":")[0]
    return urlparse(url).netloc.split("@")[-1]


def render_pr(
    package: str,
    from_version: str,
    to_version: str,
    advisories: list[str],
    kev: list[str],
    verifications: list[str],
    grouping: str,
    ignored: list[str],
    dashboard: str,
) -> tuple[str, str]:
    """Deterministic PR copy; also the fallback when the model misses."""
    advs = sorted(set(advisories))
    if len(advs) <= 3:
        adv_summary = ", ".join(advs) if advs else "security fixes"
    else:
        adv_summary = f"{len(advs)} advisories incl. {advs[0]}"
    title = f"[security] {package} {from_version}→{to_version} ({adv_summary})"
    if len(advs) <= 3:
        first = (
            f"{package} {from_version} → {to_version} "
            f"fixes {', '.join(advs) if advs else 'security issues'}."
        )
    else:
        first = f"{package} {from_version} → {to_version} fixes {len(advs)} advisories."
    lines = [first]
    if len(advs) > 3:
        shown = advs[:20]
        rest = f", and {len(advs) - len(shown)} more" if len(advs) > len(shown) else ""
        lines.append(f"Advisories: {', '.join(shown)}{rest}.")
    lines.extend(
        [
            *[f"WARNING: {adv} is CISA KEV exploited." for adv in sorted(set(kev))],
            *[f"Verification: {v}" for v in verifications],
            f"Grouping: {grouping}.",
            *(["Ignored tests: " + "; ".join(ignored)] if ignored else []),
            f"Dashboard: {dashboard}",
        ]
    )
    return title, "\n".join(lines)


_TEMPLATE_MAX_CHARS = 4000
_TEMPLATE_FILES = (
    ".github/pull_request_template.md",
    "docs/pull_request_template.md",
)
_TEMPLATE_DIRS = (
    ".github/PULL_REQUEST_TEMPLATE",
    ".gitlab/merge_request_templates",
)
_TEMPLATE_KEYWORDS = ("security", "fix", "bug", "deps", "default")


def _find_pr_template(workdir: Path) -> str | None:
    """Repo PR/MR template text (capped), or None when the repo has none.

    Single-file templates win; a template directory yields the first
    keyword match (security/fix/bug/deps/default), else the first file.
    Read from the delivery checkout, so it is always fresh per delivery.
    """
    for rel in _TEMPLATE_FILES:
        target = workdir / rel
        if target.is_file():
            text = _safe_template_read(target)
            if text:
                return text
    for rel in _TEMPLATE_DIRS:
        directory = workdir / rel
        if not directory.is_dir():
            continue
        try:
            candidates = sorted(p for p in directory.iterdir() if p.is_file())
        except OSError:
            continue
        picked = None
        for keyword in _TEMPLATE_KEYWORDS:
            picked = next((p for p in candidates if keyword in p.name.lower()), None)
            if picked is not None:
                break
        if picked is None and candidates:
            picked = candidates[0]
        if picked is not None:
            text = _safe_template_read(picked)
            if text:
                return text
    return None


def _safe_template_read(path: Path) -> str:
    try:
        return path.read_text(errors="replace")[:_TEMPLATE_MAX_CHARS].strip()
    except OSError:
        return ""


def _render_pr_text(
    package: str,
    from_version: str,
    to_version: str,
    advisories: list[str],
    kev: list[str],
    verifications: list[str],
    grouping: str,
    ignored: list[str],
    dashboard: str,
    *,
    template: str | None = None,
    repo_id: int | None = None,
) -> tuple[str, str]:
    """Model-written PR copy with the deterministic template as fallback."""
    from security_agent.brain.pr_text import generate_pr_text
    from security_agent.control.cost import CostCapExceeded

    try:
        generated = generate_pr_text(
            package,
            from_version,
            to_version,
            advisories,
            kev,
            verifications,
            grouping,
            ignored,
            dashboard,
            template=template,
            repo_id=repo_id,
        )
    except CostCapExceeded:
        raise
    except Exception:  # noqa: BLE001 - PR copy never breaks delivery
        generated = None
    if generated is not None:
        return generated
    return render_pr(
        package,
        from_version,
        to_version,
        advisories,
        kev,
        verifications,
        grouping,
        ignored,
        dashboard,
    )


def render_issue(package: str, advisory: str, guidance: str, dashboard: str) -> tuple[str, str]:
    return (
        f"[security] {package} {advisory}: manual upgrade needed",
        f"{guidance}\n\nDashboard: {dashboard}",
    )


def _headers(provider: str, token: str) -> dict[str, str]:
    # Bearer is accepted for PATs on both providers.
    if provider == "gitlab":
        return {"Authorization": f"Bearer {token}"}
    return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}


def _gitlab_project_id(base: str, headers: dict[str, str], slug: str) -> int:
    r = httpx.get(f"{base}/projects/{quote(slug, safe='')}", headers=headers, timeout=_API_TIMEOUT)
    r.raise_for_status()
    project_id = r.json().get("id")
    if not project_id:
        raise DeliverError(f"GitLab project not found for {slug}")
    return int(project_id)


def open_pr(
    provider: str,
    slug: str,
    host: str,
    token: str,
    title: str,
    body: str,
    head: str,
    base: str,
) -> str:
    """Open a ready-for-review PR/MR; returns its URL."""
    api = _api_base(provider, host)
    headers = _headers(provider, token)
    try:
        if provider == "github":
            r = httpx.post(
                f"{api}/repos/{slug}/pulls",
                headers=headers,
                json={"title": title, "head": head, "base": base, "body": body, "draft": False},
                timeout=_API_TIMEOUT,
            )
            r.raise_for_status()
            url = r.json().get("html_url", "")
        else:
            project_id = _gitlab_project_id(api, headers, slug)
            r = httpx.post(
                f"{api}/projects/{project_id}/merge_requests",
                headers=headers,
                json={
                    "title": title,
                    "source_branch": head,
                    "target_branch": base,
                    "description": body,
                },
                timeout=_API_TIMEOUT,
            )
            r.raise_for_status()
            url = r.json().get("web_url", "")
    except Exception as exc:
        raise DeliverError(f"PR open failed: {exc}") from exc
    if not url:
        raise DeliverError("PR open returned no URL")
    url = str(url)
    if not url.startswith(("http://", "https://")):
        raise DeliverError(f"PR open returned a non-http URL: {url[:100]}")
    return url


def open_issue(provider: str, slug: str, host: str, token: str, title: str, body: str) -> str:
    api = _api_base(provider, host)
    headers = _headers(provider, token)
    try:
        if provider == "github":
            r = httpx.post(
                f"{api}/repos/{slug}/issues",
                headers=headers,
                json={"title": title, "body": body},
                timeout=_API_TIMEOUT,
            )
            r.raise_for_status()
            url = r.json().get("html_url", "")
        else:
            project_id = _gitlab_project_id(api, headers, slug)
            r = httpx.post(
                f"{api}/projects/{project_id}/issues",
                headers=headers,
                json={"title": title, "description": body},
                timeout=_API_TIMEOUT,
            )
            r.raise_for_status()
            url = r.json().get("web_url", "")
    except Exception as exc:
        raise DeliverError(f"issue open failed: {exc}") from exc
    if not url:
        raise DeliverError("issue open returned no URL")
    url = str(url)
    if not url.startswith(("http://", "https://")):
        raise DeliverError(f"issue open returned a non-http URL: {url[:100]}")
    return url


def _github_pull_api(pr_url: str) -> str:
    """API base for a github.com PR URL; raises DeliverError when unparseable."""
    try:
        number = pr_url.rstrip("/").rsplit("/pull/", 1)[1]
        slug = "/".join(pr_url.split("github.com/")[-1].split("/")[:2])
        if not number or len(slug.split("/")) != 2:
            raise ValueError("not a github PR URL")
    except (ValueError, IndexError) as exc:
        raise DeliverError(f"unrecognized PR URL: {pr_url}") from exc
    return f"https://api.github.com/repos/{slug}/pulls/{number}"


def _gitlab_mr_api(pr_url: str, token: str) -> tuple[str, dict[str, str]]:
    """(API URL, headers) for a GitLab MR URL; raises DeliverError when unparseable."""
    if "/-/merge_requests/" not in pr_url:
        raise DeliverError(f"unrecognized PR URL: {pr_url}")
    host = _provider_host(pr_url)
    slug = pr_url.split(f"{host}/")[-1].split("/-/merge_requests/")[0]
    iid = pr_url.rstrip("/").rsplit("/merge_requests/", 1)[1]
    if not host or not slug or not iid:
        raise DeliverError(f"unrecognized PR URL: {pr_url}")
    headers = _headers("gitlab", token)
    base = _api_base("gitlab", host)
    project_id = _gitlab_project_id(base, headers, slug)
    return f"{base}/projects/{project_id}/merge_requests/{iid}", headers


def query_pr_state(pr_url: str, token: str) -> tuple[str, bool]:
    """(state, merged) for a proposal PR URL. Raises DeliverError when unknown."""
    try:
        if "/pull/" in pr_url:
            # github.com only in v1; GHES URLs degrade to a DeliverError skip.
            api, headers = _github_pull_api(pr_url), _headers("github", token)
        elif "/merge_requests/" in pr_url:
            api, headers = _gitlab_mr_api(pr_url, token)
        else:
            raise DeliverError(f"unrecognized PR URL: {pr_url}")
        r = httpx.get(api, headers=headers, timeout=_API_TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except DeliverError:
        raise
    except Exception as exc:
        raise DeliverError(f"PR state query failed: {exc}") from exc
    if "/pull/" in pr_url:
        return str(data.get("state", "open")), bool(data.get("merged", False))
    state = str(data.get("state", "opened"))
    return ("open" if state == "opened" else state), state == "merged"


def merge_pr(pr_url: str, token: str) -> None:
    """Backend merge of an approved PR/MR. Callers must hold an APPROVED gate."""
    try:
        if "/pull/" in pr_url:
            api, headers = _github_pull_api(pr_url), _headers("github", token)
            r = httpx.put(
                f"{api}/merge",
                headers=headers,
                json={"merge_method": "merge"},
                timeout=_API_TIMEOUT,
            )
            r.raise_for_status()
            if not r.json().get("merged", False):
                raise DeliverError(f"merge rejected: {r.json().get('message', 'unknown')}")
        elif "/merge_requests/" in pr_url:
            api, headers = _gitlab_mr_api(pr_url, token)
            r = httpx.put(api + "/merge", headers=headers, timeout=_API_TIMEOUT)
            r.raise_for_status()
        else:
            raise DeliverError(f"unrecognized PR URL: {pr_url}")
    except DeliverError:
        raise
    except Exception as exc:
        raise DeliverError(f"merge failed: {exc}") from exc


def _commit(workdir: Path, title: str, body: str) -> bool:
    """Commit with the bot identity; SSH-signed when a key is configured."""
    from security_agent.config import get_settings

    settings = get_settings()
    base = [
        "-c",
        f"user.name={settings.bot_name}",
        "-c",
        f"user.email={settings.bot_email}",
    ]
    key = settings.bot_signing_key
    if key and Path(key).exists():
        run_allowlisted(
            "git",
            [
                *base,
                "-c",
                "gpg.format=ssh",
                "-c",
                f"user.signingkey={key}",
                "commit",
                "-S",
                "-m",
                title,
                "-m",
                body,
            ],
            cwd=str(workdir),
        )
        return True
    run_allowlisted("git", [*base, "commit", "-m", title, "-m", body], cwd=str(workdir))
    return False


def _apply_proposal_patches(workdir: Path, patches: list[str]) -> None:
    patch_file = workdir / ".agent-patch"
    try:
        for patch in patches:
            patch_file.write_text(patch or "")
            run_allowlisted("git", ["apply", "--3way", ".agent-patch"], cwd=str(workdir))
    finally:
        patch_file.unlink(missing_ok=True)


def group_by_package(proposals: list[Proposal]) -> list[list[Proposal]]:
    """Same-package proposals ride one PR (overlap/edge judgment is a follow-up).

    Secret removals are never grouped: one finding per PR, so each merge
    maps to exactly one rotated credential.
    """
    with session_scope() as db:
        packages: dict[int, str] = {}
        for proposal in proposals:
            first_id = (proposal.finding_ids or [None])[0]
            row = db.get(Finding, first_id) if first_id else None
            packages[proposal.id] = row.package if row else "unknown"
    groups: dict[str, list[Proposal]] = {}
    for proposal in proposals:
        if proposal.secret_finding_id is not None:
            groups[f"secret:{proposal.id}"] = [proposal]
        else:
            groups.setdefault(packages[proposal.id], []).append(proposal)
    return list(groups.values())


def secret_branch_name(rule_id: str, secret_id: int) -> str:
    """security/secret-<rule>-<id> (FR-8 D1 removal PRs)."""
    return f"security/secret-{sanitize_branch_part(rule_id)}-{secret_id}"


def render_secret_pr(
    rule_id: str,
    path: str,
    verification: str,
    guidance: str,
    dashboard: str,
) -> tuple[str, str]:
    title = f"[security] remove leaked {rule_id} secret from {path}"
    body = "\n".join(
        [
            f"Removes a {rule_id} secret committed in {path} (value redacted, "
            "replaced with an environment reference).",
            f"Verification: {verification}.",
            "",
            "Rotation (do this by hand, then confirm in the dashboard):",
            guidance,
            f"Dashboard: {dashboard}",
        ]
    )
    return title, body


def _proposal_findings(proposal_ids: list[int]) -> list[Finding]:
    with session_scope() as db:
        rows = list(db.scalars(select(Finding).where(Finding.id.in_(proposal_ids))))
        for r in rows:
            db.expunge(r)
        return rows


def _max_version(versions: list[str]) -> str:
    """Highest version by semver; unparseable entries fall back to lexical max."""

    def key(v: str) -> tuple[int, object]:
        try:
            return (1, Version(v))
        except InvalidVersion:
            return (0, v)

    return max(versions, key=key)


def _push_branch(workdir: Path, branch: str, token: str) -> None:
    """Push, authenticating via a momentary credential URL on https origins.

    Clones strip credentials from origin, so the token is re-attached only
    for the push and removed again after (file/SSH remotes never need it).
    Auth is keyed off the workdir's actual origin, which can differ from
    the repo URL when delivering from a template workdir.
    """
    from security_agent.worker.scan import clone_url

    try:
        clean = run_allowlisted("git", ["remote", "get-url", "origin"], cwd=str(workdir)).strip()
    except (RuntimeError, TimeoutError):
        clean = ""
    needs_auth = bool(token) and clean.startswith("https://")
    if needs_auth:
        run_allowlisted(
            "git",
            ["remote", "set-url", "origin", clone_url(clean, token)],
            cwd=str(workdir),
            redact=(token,),
        )
    try:
        run_allowlisted(
            "git",
            ["push", "--force-with-lease", "origin", branch],
            allow_network=True,
            cwd=str(workdir),
            redact=(token,) if token else (),
        )
    except (RuntimeError, TimeoutError) as exc:
        # Push stderr echoes the remote URL; never persist the credential.
        detail = str(exc).replace(token, "***") if token else exc
        raise DeliverError(f"push failed: {detail}") from exc
    finally:
        if needs_auth:
            try:
                run_allowlisted("git", ["remote", "set-url", "origin", clean], cwd=str(workdir))
            except (RuntimeError, TimeoutError):
                pass  # workdir is temp and always wiped


_BRANCH_FORBIDDEN_RE = re.compile(r"\.\.|@\{|[~^:?*\[\\\s\x00-\x1f]")


def _valid_branch_name(configured: str) -> bool:
    """True when a stored branch name is safe to pass to git checkout.

    `git checkout -- <branch>` would switch semantics to path-restore, so
    the stored value is validated instead: no option prefix, no traversal
    or revision syntax, no whitespace or control bytes.
    """
    return (
        bool(configured)
        and not configured.startswith(("-", ".", "/"))
        and not configured.endswith(("/", ".", ".lock"))
        and _BRANCH_FORBIDDEN_RE.search(configured) is None
    )


def _checkout_base(workdir: Path, configured: str | None) -> str:
    current = run_allowlisted(
        "git", ["rev-parse", "--abbrev-ref", "HEAD"], cwd=str(workdir)
    ).strip()
    if configured and not _valid_branch_name(configured):
        raise DeliverError(f"refusing unsafe base branch {configured!r}")
    if configured and configured != current:
        try:
            run_allowlisted("git", ["checkout", configured], cwd=str(workdir))
        except RuntimeError as exc:
            raise DeliverError(f"unknown base branch {configured}: {exc}") from exc
        return configured
    return current


def _deliver_secret_group(
    repo: Repo,
    token: str,
    proposal: Proposal,
    workdir: Path,
    dest_dir: Path,
    dashboard: str,
) -> dict:
    """Deliver one secret removal PR; the merge sync moves no secret state."""
    from security_agent.db.models import SecretFinding
    from security_agent.worker.secrets import SecretError, apply_secret_removal

    with session_scope() as db:
        secret = db.get(SecretFinding, proposal.secret_finding_id or -1)
        if secret is None:
            raise DeliverError("secret finding is gone; refusing to deliver")
        rule_id, path, guidance = secret.rule_id, secret.path, secret.guidance or ""
        secret_id = secret.id
    base = _checkout_base(workdir, repo.default_branch)
    branch = secret_branch_name(rule_id, secret_id)
    run_allowlisted("git", ["checkout", "-b", branch], cwd=str(workdir))
    try:
        touched = apply_secret_removal(workdir, secret_id)
    except SecretError as exc:
        if exc.reason == "gone":
            # Nothing to remove: supersede once so delivery stops retrying.
            with session_scope() as db:
                row = db.get(Proposal, proposal.id)
                if row is not None:
                    row.status = ProposalStatus.SUPERSEDED
                    row.pr_state = "superseded"
            raise DeliverError(f"superseded: {exc}") from exc
        raise DeliverError(f"removal not applicable: {exc}") from exc
    # Stage exactly the redacted files (`git apply --3way` stages for vulns;
    # the secrets path edits the worktree, so it stages explicitly).
    run_allowlisted("git", ["add", "--", *sorted(touched)], cwd=str(workdir))
    title, body = render_secret_pr(rule_id, path, proposal.verification_result, guidance, dashboard)
    signed = _commit(workdir, title, body)
    if repo.kind == RepoKind.GIT and not token and (repo.url or "").startswith("https://"):
        raise DeliverError("no provider token for push")
    _push_branch(workdir, branch, token)
    pr_url = ""
    provided = detect_provider(repo.url or "") if repo.kind == RepoKind.GIT else None
    if provided and token:
        provider, slug = provided
        pr_url = open_pr(
            provider, slug, _provider_host(repo.url or ""), token, title, body, branch, base
        )
    # No format-patch artifact: a unified diff would persist the secret
    # bytes via its `-` lines (the branch + PR are the artifact).
    with session_scope() as db:
        row = db.get(Proposal, proposal.id)
        if row is not None:
            row.branch = branch
            row.base_branch = base
            row.pr_url = pr_url or None
            row.pr_state = "open" if pr_url else "branch-only"
            row.grouping_reason = "secret removal: one finding per PR"
    if pr_url:
        from security_agent.control.gates import request_gate
        from security_agent.db.models import GateAction

        request_gate(
            repo.id, GateAction.MERGE, pr_url, proposal_id=proposal.id, reason="secret removal PR"
        )
    return {
        "proposal_ids": [proposal.id],
        "branch": branch,
        "pr_url": pr_url,
        "signed": signed,
    }


def _deliver_group(
    repo: Repo,
    token: str,
    group: list[Proposal],
    workdir: Path,
    dest_dir: Path,
    dashboard: str,
) -> dict:
    if group and group[0].secret_finding_id is not None:
        return _deliver_secret_group(repo, token, group[0], workdir, dest_dir, dashboard)
    findings = _proposal_findings([fid for p in group for fid in (p.finding_ids or [])])
    package = findings[0].package if findings else "unknown"
    advisories = sorted({f.advisory_id for f in findings})
    kev = sorted({f.advisory_id for f in findings if f.kev_exploited})
    base = _checkout_base(workdir, repo.default_branch)
    branch = branch_name(package, advisories)
    run_allowlisted("git", ["checkout", "-b", branch], cwd=str(workdir))
    patches = [p.patch or "" for p in group]
    if not all(patches):
        raise DeliverError("proposal is missing its stored patch")
    try:
        _apply_proposal_patches(workdir, patches)
    except RuntimeError as exc:
        raise DeliverError(f"patch no longer applies cleanly: {exc}") from exc
    from_v = group[0].package_from
    to_v = _max_version([p.package_to for p in group])
    grouping = (
        "single package" if len(group) == 1 else f"{len(group)} proposals, same package {package}"
    )
    ignored = sorted({i for p in group for i in (p.ignored_tests or [])})
    template = _find_pr_template(workdir)
    title, body = _render_pr_text(
        package,
        from_v,
        to_v,
        advisories,
        kev,
        [p.verification_result for p in group],
        grouping,
        ignored,
        dashboard,
        template=template,
        repo_id=repo.id,
    )
    if template:
        # A filled template is the PR body; the commit keeps the concise
        # summary so `git log` stays readable.
        _, commit_body = render_pr(
            package,
            from_v,
            to_v,
            advisories,
            kev,
            [p.verification_result for p in group],
            grouping,
            ignored,
            dashboard,
        )
    else:
        commit_body = body
    signed = _commit(workdir, title, commit_body)
    if repo.kind == RepoKind.GIT and not token and (repo.url or "").startswith("https://"):
        raise DeliverError("no provider token for push")
    _push_branch(workdir, branch, token)
    pr_url = ""
    provided = detect_provider(repo.url or "") if repo.kind == RepoKind.GIT else None
    if provided and token:
        provider, slug = provided
        pr_url = open_pr(
            provider, slug, _provider_host(repo.url or ""), token, title, body, branch, base
        )
    dest_dir.mkdir(parents=True, exist_ok=True)
    run_allowlisted("git", ["format-patch", "-1", "HEAD", "-o", str(dest_dir)], cwd=str(workdir))
    with session_scope() as db:
        for proposal in group:
            row = db.get(Proposal, proposal.id)
            if row is None:
                continue
            row.branch = branch
            row.base_branch = base
            row.pr_url = pr_url or None
            row.pr_state = "open" if pr_url else "branch-only"
            row.grouping_reason = grouping
    if pr_url:
        from security_agent.control.gates import request_gate
        from security_agent.db.models import GateAction

        request_gate(
            repo.id, GateAction.MERGE, pr_url, proposal_id=group[0].id, reason="delivered PR"
        )
    return {
        "proposal_ids": [p.id for p in group],
        "branch": branch,
        "pr_url": pr_url,
        "signed": signed,
    }


def _deliver_issue(repo: Repo, token: str, finding: Finding, dest_dir: Path, dashboard: str) -> str:
    title, body = render_issue(
        finding.package, finding.advisory_id, finding.guidance or "", dashboard
    )
    provided = detect_provider(repo.url or "") if repo.kind == RepoKind.GIT else None
    if provided is None or not token:
        dest_dir.mkdir(parents=True, exist_ok=True)
        path = dest_dir / f"issue-{sanitize_branch_part(finding.advisory_id)}.md"
        path.write_text(f"# {title}\n\n{body}\n")
        url = str(path)
    else:
        provider, slug = provided
        url = open_issue(provider, slug, _provider_host(repo.url or ""), token, title, body)
    with session_scope() as db:
        row = db.get(Finding, finding.id)
        if row is not None:
            row.issue_url = url
    return url


@contextmanager
def _fresh_workdir(repo: Repo, source_template: Path | None, *, depth: int | None = 1):
    workdir = make_workdir("deliver-")
    try:
        if source_template is not None:
            shutil.rmtree(workdir)
            shutil.copytree(source_template, workdir)
            # Copies preserve index stat info that `git apply --3way`
            # distrusts ("does not match index"); refresh it. Clones are immune.
            run_allowlisted("git", ["update-index", "--refresh"], cwd=str(workdir))
        else:
            clone_repo(repo, workdir, depth=depth)
        yield workdir
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def run_deliver(
    repo_id: int,
    run_id: int,
    *,
    source_dir: Path | None = None,
    delivery_root: Path | None = None,
) -> dict:
    """Deliver open proposals + file issues for report-only findings (FR-5)."""
    from security_agent.config import get_settings
    from security_agent.policy.enforce import park_for_policy, pre_deliver_check
    from security_agent.policy.service import PolicyStoreError

    assert_host_execution_allowed()
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        run = db.get(ScanRun, run_id)
        if repo is None or run is None:
            raise ValueError(f"Unknown repo {repo_id} or run {run_id}.")
        if run.parked:
            return {"status": "parked", "proposal_ids": [], "issues": [], "errors": []}
        db.expunge(repo)
    root = Path(delivery_root) if delivery_root else Path("deliveries")
    dashboard = f"{get_settings().public_url}/repos/{repo_id}/findings"
    token = get_repo_token(repo_id) if repo.kind == RepoKind.GIT else ""
    with session_scope() as db:
        pending = list(
            db.scalars(
                select(Proposal).where(
                    Proposal.repo_id == repo_id,
                    Proposal.status == ProposalStatus.OPEN,
                    Proposal.branch.is_(None),
                )
            )
        )
        for p in pending:
            db.expunge(p)
        unpatched = list(
            db.scalars(
                select(Finding).where(
                    Finding.repo_id == repo_id,
                    Finding.status == FindingStatus.UNPATCHABLE,
                    Finding.issue_url.is_(None),
                )
            )
        )
        for f in unpatched:
            db.expunge(f)
    try:
        gate = pre_deliver_check(repo_id, run_id, pending)
    except PolicyStoreError as exc:
        park_for_policy(run_id, str(exc))
        return {"status": "parked", "proposal_ids": [], "issues": [], "errors": []}
    shippable = set(gate["deliver"])
    pending = [p for p in pending if p.id in shippable]
    reopen_run(run_id)
    delivered: list[int] = []
    issues: list[int] = []
    errors: list[str] = []
    if gate["held"]:
        append_run_note(run_id, f"policy held {len(gate['held'])} proposals for review")
    append_run_note(
        run_id,
        f"deliver: {len(pending)} proposal(s) to ship, {len(unpatched)} issue(s) to file",
    )
    for group in group_by_package(pending):
        group_findings = _proposal_findings(
            [fid for p in group for fid in (p.finding_ids or [])]
        )
        package = group_findings[0].package if group_findings else "unknown"
        ids = [p.id for p in group]
        append_run_note(run_id, f"deliver: shipping {package} (proposal {ids})...")
        try:
            with _fresh_workdir(repo, source_dir) as workdir:
                outcome = _deliver_group(
                    repo, token or "", group, workdir, root / f"run-{run_id}", dashboard
                )
            delivered.extend(outcome["proposal_ids"])
            append_run_note(
                run_id, f"deliver: {package}: shipped ({outcome.get('branch')})"
            )
            if not outcome["signed"]:
                append_run_note(
                    run_id,
                    f"proposals {outcome['proposal_ids']} committed unsigned (no key)",
                )
        except (DeliverError, RuntimeError, TimeoutError) as exc:
            errors.append(f"group {ids}: {exc}")
            append_run_note(run_id, f"deliver: {package}: failed ({exc})")
    for finding in unpatched:
        append_run_note(
            run_id, f"deliver: filing issue for {finding.package} ({finding.advisory_id})..."
        )
        try:
            url = _deliver_issue(
                repo, token or "", finding, root / f"run-{run_id}", dashboard
            )
            issues.append(finding.id)
            append_run_note(run_id, f"deliver: {finding.package}: issue {url}")
        except (DeliverError, RuntimeError, TimeoutError) as exc:
            errors.append(f"issue {finding.id}: {exc}")
            append_run_note(run_id, f"deliver: {finding.package}: issue failed ({exc})")
    append_run_note(
        run_id,
        f"delivered {len(delivered)} proposals, {len(issues)} issues, {len(errors)} errors",
    )
    return {
        "status": "done",
        "proposal_ids": delivered,
        "issues": issues,
        "errors": errors,
    }


def _apply_provider_state(
    proposal_id: int, state: str, merged: bool, *, observed_source: str = "provider"
) -> bool:
    """Sync one proposal + findings from provider truth. Returns found."""
    with session_scope() as db:
        proposal = db.get(Proposal, proposal_id)
        if proposal is None:
            return False
        proposal.pr_state = "merged" if merged else state
        finding_ids = list(proposal.finding_ids or [])
        secret_id = proposal.secret_finding_id
        if merged:
            proposal.status = ProposalStatus.MERGED
        elif state == "closed":
            proposal.status = ProposalStatus.CLOSED
    for fid in finding_ids:
        with session_scope() as db:
            row = db.get(Finding, fid)
            current = row.status if row else None
        if merged and current == FindingStatus.PROPOSED:
            transition_finding(fid, FindingStatus.RESOLVED)
        elif state == "closed" and not merged and current == FindingStatus.PROPOSED:
            transition_finding(fid, FindingStatus.OPEN)
    if secret_id is not None and state == "closed" and not merged:
        # The removal PR died unmerged: reopen so the next run re-proposes
        # while the secret is still at HEAD. A merged PR moves no secret
        # state (closure needs HEAD-clean + rotation confirmed).
        try:
            transition_secret_finding(secret_id, SecretStatus.OPEN)
        except ValueError:
            pass  # already open/awaiting/closed: nothing to reopen
    if merged:
        from security_agent.control.gates import resolve_gates_for_proposal

        resolve_gates_for_proposal(proposal_id, observed_source)
    return True


def reconcile_pr(pr_url: str, merged: bool, closed: bool) -> bool:
    """Webhook-instant reconcile from a verified close/merge event (FR-5 D5)."""
    if not pr_url:
        return False
    with session_scope() as db:
        proposal = db.scalar(select(Proposal).where(Proposal.pr_url == pr_url))
        proposal_id = proposal.id if proposal else None
    if proposal_id is None:
        return False
    state = "merged" if merged else ("closed" if closed else "open")
    return _apply_provider_state(proposal_id, state, merged)


def _branch_merged(workdir: Path, branch: str, base: str) -> bool:
    """True when base contains the branch tip (merge observed in git)."""
    try:
        run_allowlisted("git", ["merge-base", "--is-ancestor", branch, base], cwd=str(workdir))
        return True
    except RuntimeError:
        return False


def sync_proposal_states(repo_id: int) -> dict:
    """Resync open proposals: provider APIs for PRs, ancestry for branch-only."""
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        if repo is None:
            return {"synced": 0}
        db.expunge(repo)
        rows = list(
            db.scalars(
                select(Proposal).where(
                    Proposal.repo_id == repo_id,
                    Proposal.status == ProposalStatus.OPEN,
                )
            )
        )
        api_targets = [(r.id, r.pr_url or "") for r in rows if r.pr_url]
        ancestry_targets = [
            (r.id, r.branch or "", r.base_branch or "")
            for r in rows
            if not r.pr_url and r.branch and r.base_branch
        ]
    synced = 0
    if api_targets and repo.kind == RepoKind.GIT and detect_provider(repo.url or ""):
        token = get_repo_token(repo_id) or ""
        if token:
            for proposal_id, pr_url in api_targets:
                try:
                    state, merged = query_pr_state(pr_url, token)
                except DeliverError:
                    continue
                if merged or state in ("closed", "merged"):
                    _apply_provider_state(proposal_id, state, merged)
                    synced += 1
                else:
                    with session_scope() as db:
                        row = db.get(Proposal, proposal_id)
                        if row is not None:
                            row.pr_state = state
    if ancestry_targets:
        from security_agent.sandbox import assert_host_execution_allowed

        assert_host_execution_allowed()
        with _fresh_workdir(repo, None, depth=None) as workdir:
            for proposal_id, branch, base in ancestry_targets:
                try:
                    merged = _branch_merged(workdir, f"origin/{branch}", f"origin/{base}")
                except (RuntimeError, TimeoutError):
                    continue
                if merged:
                    source = "operator" if repo.kind == RepoKind.LOCAL else "provider"
                    _apply_provider_state(proposal_id, "merged", True, observed_source=source)
                    synced += 1
    return {"synced": synced}


DELIVERY_RETENTION_DAYS = 30


def purge_old_deliveries(
    root: Path | str = "deliveries", *, older_than_days: int = DELIVERY_RETENTION_DAYS
) -> int:
    """Delete per-run delivery dirs past retention; returns dirs removed."""
    import time

    base = Path(root)
    if not base.is_dir():
        return 0
    cutoff = time.time() - older_than_days * 86400
    removed = 0
    for entry in list(base.iterdir()):  # snapshot: rmtree during iteration is unsafe
        if not entry.is_dir():
            continue
        try:
            if entry.stat().st_mtime >= cutoff:
                continue
            shutil.rmtree(entry)
        except OSError:
            continue
        removed += 1
    return removed


def json_loads_maybe(body: bytes) -> dict:
    try:
        parsed = json.loads(body.decode() or "{}")
    except (ValueError, UnicodeDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}
