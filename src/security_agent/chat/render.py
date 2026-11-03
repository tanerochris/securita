"""Chat rendering: safe markdown subset + @/# mention links.

Escape-first by construction: raw HTML never passes through, links only
allow http/https, and every href is a server-built internal path. User
messages stay plain text; only assistant output renders markdown.
"""

import html
import re

from markupsafe import Markup

_FENCE = re.compile(r"```(\w*)\n?(.*?)```", re.S)
_LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")
_URL = re.compile(r"(?<![\"'=(\[])https?://[^\s<]+")
_BOLD = re.compile(r"\*\*(.+?)\*\*")
_ITALIC = re.compile(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)")
_AT = re.compile(r"@([A-Za-z0-9][\w.\-/@]*)")
_HASH = re.compile(r"#(finding|run|gate|repo|proposal)-(\d+)")

_FENCE_MARK = "\x00"
_MENTION_MARK = "\x01"


def _split_code_spans(text: str) -> list[tuple[bool, str]]:
    """Split on `code` spans: (is_code, segment) pairs, code unprocessed."""
    parts: list[tuple[bool, str]] = []
    buf = ""
    in_code = False
    for char in text:
        if char == "`":
            parts.append((in_code, buf))
            buf = ""
            in_code = not in_code
        else:
            buf += char
    parts.append((in_code, buf))
    return parts


def _inline(text: str) -> str:
    """Inline markup on already-escaped text (code spans skipped)."""
    out = []
    for is_code, seg in _split_code_spans(text):
        if is_code:
            out.append(f"<code>{seg}</code>")
            continue
        seg = _LINK.sub(lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>', seg)
        seg = _URL.sub(lambda m: f'<a href="{m.group(0)}">{m.group(0)}</a>', seg)
        seg = _BOLD.sub(r"<strong>\1</strong>", seg)
        seg = _ITALIC.sub(r"<em>\1</em>", seg)
        out.append(seg)
    return "".join(out)


def render_markdown(text: str) -> str:
    """Escape-first markdown subset: fences, headers, quotes, lists, inline."""
    fences: list[str] = []

    def _take_fence(match: re.Match) -> str:
        fences.append(html.escape(match.group(2)))
        return f"{_FENCE_MARK}{len(fences) - 1}{_FENCE_MARK}"

    body = _FENCE.sub(_take_fence, text.replace(_FENCE_MARK, ""))
    body = html.escape(body)
    blocks: list[str] = []
    para: list[str] = []
    in_ul = in_ol = False

    def _flush_para() -> None:
        if para:
            blocks.append(f"<p>{'<br>'.join(_inline(line) for line in para)}</p>")
            para.clear()

    def _close_lists() -> None:
        nonlocal in_ul, in_ol
        if in_ul:
            blocks.append("</ul>")
            in_ul = False
        if in_ol:
            blocks.append("</ol>")
            in_ol = False

    for line in body.split("\n"):
        stripped = line.strip()
        if not stripped:
            _flush_para()
            _close_lists()
            continue
        header = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if header:
            _flush_para()
            _close_lists()
            level = min(6, 3 + len(header.group(1)))
            blocks.append(f"<h{level}>{_inline(header.group(2))}</h{level}>")
            continue
        if stripped.startswith("&gt; "):
            _flush_para()
            _close_lists()
            blocks.append(f"<blockquote>{_inline(stripped[5:])}</blockquote>")
            continue
        bullet = re.match(r"^[-*]\s+(.*)$", stripped)
        if bullet:
            _flush_para()
            if in_ol:
                blocks.append("</ol>")
                in_ol = False
            if not in_ul:
                blocks.append("<ul>")
                in_ul = True
            blocks.append(f"<li>{_inline(bullet.group(1))}</li>")
            continue
        ordered = re.match(r"^\d+\.\s+(.*)$", stripped)
        if ordered:
            _flush_para()
            if in_ul:
                blocks.append("</ul>")
                in_ul = False
            if not in_ol:
                blocks.append("<ol>")
                in_ol = True
            blocks.append(f"<li>{_inline(ordered.group(1))}</li>")
            continue
        _close_lists()
        para.append(line.strip())
    _flush_para()
    _close_lists()
    out = "\n".join(blocks)
    for i, code in enumerate(fences):
        out = out.replace(f"{_FENCE_MARK}{i}{_FENCE_MARK}", f"<pre><code>{code}</code></pre>")
    return out


def resolve_mention(token: str, *, viewer_is_owner: bool):
    """Resolve @name / #type-id to (label, url); None stays literal text."""
    from sqlalchemy import select

    from security_agent.db.models import (
        Approval,
        Finding,
        Proposal,
        Repo,
        ScanRun,
        User,
    )
    from security_agent.db.session import session_scope

    hashed = re.fullmatch(r"#(finding|run|gate|repo|proposal)-(\d+)", token)
    with session_scope() as db:
        if hashed:
            kind, raw_id = hashed.group(1), int(hashed.group(2))
            if kind == "repo":
                repo_row = db.get(Repo, raw_id)
                if repo_row is None:
                    return None
                return (f"#{token[1:]} {repo_row.name}", f"/repos/{repo_row.id}")
            if kind == "gate":
                gate_row = db.get(Approval, raw_id)
                if gate_row is None:
                    return None
                return (f"gate #{gate_row.id} ({gate_row.action.value})", "/approvals")
            if kind == "finding":
                finding_row = db.get(Finding, raw_id)
                if finding_row is None:
                    return None
                return (
                    f"finding #{finding_row.id} {finding_row.package}",
                    f"/repos/{finding_row.repo_id}/findings",
                )
            if kind == "run":
                run_row = db.get(ScanRun, raw_id)
                if run_row is None:
                    return None
                return (
                    f"run #{run_row.id}",
                    f"/repos/{run_row.repo_id}/runs/{run_row.id}",
                )
            proposal_row = db.get(Proposal, raw_id)
            if proposal_row is None:
                return None
            return (
                f"patch #{proposal_row.id} {proposal_row.package_from}",
                f"/repos/{proposal_row.repo_id}/patches",
            )
        if token.startswith("@"):
            name = token[1:]
            repo = db.scalar(select(Repo).where(Repo.name == name))
            if repo is not None:
                return (f"@{repo.name}", f"/repos/{repo.id}")
            if viewer_is_owner:
                user = db.scalar(select(User).where(User.email == name))
                if user is not None:
                    return (f"@{user.email}", "/accounts")
            return None
    return None


def search_mentions(
    query: str, kind: str, repo_id: int | None, *, viewer_is_owner: bool
) -> list[dict]:
    """Picker candidates: @repos/@users and #findings/#runs/#gates."""
    from sqlalchemy import select

    from security_agent.db.models import Approval, Finding, Repo, ScanRun, User
    from security_agent.db.session import session_scope

    query = query.strip().lower()
    out: list[dict] = []
    with session_scope() as db:
        if kind in ("all", "@"):
            repos = db.scalars(select(Repo).order_by(Repo.id.desc()).limit(50)).all()
            got = 0
            for repo in repos:
                if query and query not in repo.name.lower():
                    continue
                out.append({"token": f"@{repo.name}", "label": f"repo {repo.name}", "kind": "@"})
                got += 1
                if got >= 5:
                    break
            if viewer_is_owner:
                users = db.scalars(select(User).order_by(User.id.desc()).limit(50)).all()
                got = 0
                for user in users:
                    if query and query not in user.email.lower():
                        continue
                    out.append(
                        {"token": f"@{user.email}", "label": f"user {user.email}", "kind": "@"}
                    )
                    got += 1
                    if got >= 5:
                        break
        if kind in ("all", "#"):
            if query.isdigit():
                num = int(query)
                for model, label in (
                    (Finding, "finding"),
                    (ScanRun, "run"),
                    (Approval, "gate"),
                    (Repo, "repo"),
                ):
                    if db.get(model, num) is not None:
                        out.append(
                            {
                                "token": f"#{label}-{num}",
                                "label": f"{label} #{num}",
                                "kind": "#",
                            }
                        )
            else:
                findings = db.scalars(select(Finding).order_by(Finding.id.desc()).limit(50)).all()
                for finding in findings:
                    if repo_id is not None and finding.repo_id != repo_id:
                        continue
                    hay = f"{finding.package} {finding.advisory_id}".lower()
                    if query and query not in hay:
                        continue
                    out.append(
                        {
                            "token": f"#finding-{finding.id}",
                            "label": f"finding #{finding.id} {finding.package}",
                            "kind": "#",
                        }
                    )
                    if len(out) >= 10:
                        break
    return out[:10]


def render_assistant(text: str, *, viewer_is_owner: bool) -> Markup:
    """Assistant message: mention links inside fenced-safe markdown."""
    mentions: list[str] = []

    def _take(match: re.Match) -> str:
        mentions.append(match.group(0))
        return f"{_MENTION_MARK}{len(mentions) - 1}{_MENTION_MARK}"

    # Mentions never resolve inside code spans or fences.
    text = text.replace(_FENCE_MARK, "").replace(_MENTION_MARK, "")
    segments = []
    for is_code, seg in _split_code_spans(text):
        if is_code:
            segments.append(f"`{seg}`")
        else:
            seg = _AT.sub(_take, seg)
            seg = _HASH.sub(_take, seg)
            segments.append(seg)
    out = render_markdown("".join(segments))
    for i, token in enumerate(mentions):
        resolved = resolve_mention(token, viewer_is_owner=viewer_is_owner)
        mark = f"{_MENTION_MARK}{i}{_MENTION_MARK}"
        if resolved is None:
            out = out.replace(mark, html.escape(token))
        else:
            label, url = resolved
            out = out.replace(mark, f'<a href="{url}">{html.escape(label)}</a>')
    return Markup(out)  # noqa: S704 escape-first builder, same as timefmt
