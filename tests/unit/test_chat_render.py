"""Chat rendering + attachments: markdown safety, mentions, upload validation."""

from datetime import UTC, datetime
from unittest import mock

import pytest

from security_agent.app import accounts as accounts_svc
from security_agent.chat import render as render_mod
from security_agent.chat.attachments import MAX_FILE_BYTES, validate_upload
from security_agent.control import repos as repo_svc
from security_agent.db.models import RepoKind, Role


def _email(tag: str) -> str:
    return f"render-{tag}-{datetime.now(UTC).timestamp()}@example.com"


def test_markdown_subset_renders():
    html = render_mod.render_markdown(
        "# Title\n\nHello **bold** and *italic* with `code`.\n\n"
        "- one\n- two\n\n1. first\n\n> quote\n\n```py\nprint(1)\n```\n"
    )
    assert "<h4>Title</h4>" in html
    assert "<strong>bold</strong>" in html and "<em>italic</em>" in html
    assert "<code>code</code>" in html
    assert "<ul>" in html and "<li>one</li>" in html
    assert "<ol>" in html and "<blockquote>quote</blockquote>" in html
    assert "<pre><code>print(1)\n</code></pre>" in html


def test_markdown_links_http_only_and_raw_html_inert():
    html = render_mod.render_markdown(
        "[ok](https://example.com/x) [evil](javascript:alert(1))\n"
        "<script>alert(1)</script> <img src=x onerror=alert(1)>"
    )
    assert '<a href="https://example.com/x">ok</a>' in html
    assert "<script>" not in html and "<img" not in html
    assert "&lt;script&gt;" in html
    assert "javascript:alert(1)" in html  # literal text, never a link target
    assert 'href="javascript' not in html


def test_markdown_autolinks_bare_urls():
    html = render_mod.render_markdown("see https://example.com/a?b=1&c=2 now")
    assert '<a href="https://example.com/a?b=1&amp;c=2">' in html


def test_mentions_resolve_and_stay_literal_when_unknown():
    repo = repo_svc.connect_repo("mention-r", RepoKind.LOCAL, local_path="/tmp/mention-r")
    try:
        html = render_mod.render_assistant(
            f"Check @{repo.name} and #repo-{repo.id} plus @nobody-here.",
            viewer_is_owner=True,
        )
        assert f'<a href="/repos/{repo.id}">@{repo.name}</a>' in html
        assert f"/repos/{repo.id}" in html
        assert "@nobody-here" in html  # unresolved stays literal
        assert "`" not in html
    finally:
        repo_svc.disconnect_repo(repo.id)


def test_mentions_ignored_inside_code():
    repo = repo_svc.connect_repo("mention-c", RepoKind.LOCAL, local_path="/tmp/mention-c")
    try:
        html = render_mod.render_assistant(
            f"`@{repo.name}` and ```\n#repo-{repo.id}\n```", viewer_is_owner=True
        )
        assert "<a href=" not in html
    finally:
        repo_svc.disconnect_repo(repo.id)


def test_user_mentions_owner_only():
    owner = accounts_svc.create_user(_email("o"), None, Role.OWNER)
    as_owner = render_mod.render_assistant(f"hi @{owner.email}", viewer_is_owner=True)
    assert '<a href="/accounts">' in as_owner
    as_dev = render_mod.render_assistant(f"hi @{owner.email}", viewer_is_owner=False)
    assert "<a href=" not in as_dev


def test_search_mentions_scopes():
    repo = repo_svc.connect_repo("search-m", RepoKind.LOCAL, local_path="/tmp/search-m")
    try:
        hits = render_mod.search_mentions("search-m", "@", None, viewer_is_owner=False)
        assert any(h["token"] == f"@{repo.name}" for h in hits)
        users_hidden = render_mod.search_mentions("", "@", None, viewer_is_owner=False)
        assert all("@" not in h["token"][1:] or "@" not in h["token"] for h in users_hidden)
        users_shown = render_mod.search_mentions("", "@", None, viewer_is_owner=True)
        assert any("@" in h["token"][1:] for h in users_shown)
        by_id = render_mod.search_mentions(str(repo.id), "#", None, viewer_is_owner=False)
        assert any(h["token"] == f"#repo-{repo.id}" for h in by_id)
    finally:
        repo_svc.disconnect_repo(repo.id)


# --- upload validation ---

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 100
PDF = b"%PDF-1.4 fake body"


def test_validate_upload_images_and_docs():
    assert validate_upload("shot.png", PNG) == ("shot.png", "image/png")
    assert validate_upload("photo.JPG", JPG)[1] == "image/jpeg"
    assert validate_upload("notes.md", b"# hi\ntext") == ("notes.md", "text/markdown")
    assert validate_upload("a.pdf", PDF)[1] == "application/pdf"
    assert validate_upload("../evil.png", PNG)[0] == "evil.png"


def test_validate_upload_rejects():
    with pytest.raises(ValueError, match="not a real image"):
        validate_upload("x.png", b"#!/bin/sh\necho pwned")
    with pytest.raises(ValueError, match="not a real PDF"):
        validate_upload("x.pdf", b"nope")
    with pytest.raises(ValueError, match="only images"):
        validate_upload("x.exe", b"MZ" + b"\x00" * 10)
    with pytest.raises(ValueError, match="exceeds"):
        validate_upload("big.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * MAX_FILE_BYTES)
    with pytest.raises(ValueError, match="empty"):
        validate_upload("e.txt", b"")
    with pytest.raises(ValueError, match="not decodable"):
        validate_upload("b.txt", b"\xff\xfe\x00binary")


# --- agent consumes uploads ---


class _CaptureChat:
    def __init__(self, script):
        self.script = list(script)
        self.seen = []

    def bind_tools(self, _tools):
        return self

    def invoke(self, messages):
        self.seen.append(messages)
        step = self.script.pop(0)
        resp = mock.Mock()
        resp.content = step.get("content", "")
        resp.tool_calls = step.get("tool_calls", [])
        resp.usage_metadata = {"input_tokens": 5, "output_tokens": 5}
        return resp


def test_answer_turn_feeds_doc_context_as_untrusted():
    from security_agent.chat import get_conversation
    from security_agent.chat.agent import answer_turn

    owner = accounts_svc.create_user(_email("doc"), None, Role.OWNER)
    conv = get_conversation(owner.id)
    model = _CaptureChat([{"content": "noted", "tool_calls": []}])
    reply = answer_turn(
        owner, conv, "review this", model=model, uploads=[("log.txt", b"ERROR boom")]
    )
    assert reply.content == "noted"
    last_human = model.seen[0][-1]
    assert "UNTRUSTED DATA" in last_human.content
    assert "ERROR boom" in last_human.content


def test_answer_turn_sends_image_parts_and_falls_back():
    from security_agent.chat import get_conversation
    from security_agent.chat.agent import answer_turn

    owner = accounts_svc.create_user(_email("img"), None, Role.OWNER)
    conv = get_conversation(owner.id)

    class Flaky(_CaptureChat):
        def invoke(self, messages):
            self.seen.append(list(messages))
            if not getattr(self, "_failed", False):
                self._failed = True
                raise RuntimeError("vision unsupported")
            step = self.script.pop(0)
            resp = mock.Mock()
            resp.content = step.get("content", "")
            resp.tool_calls = step.get("tool_calls", [])
            resp.usage_metadata = {"input_tokens": 5, "output_tokens": 5}
            return resp

    model = Flaky([{"content": "described", "tool_calls": []}])
    reply = answer_turn(owner, conv, "what is this", model=model, uploads=[("s.png", PNG)])
    assert "can't see images" in reply.content
    first_try = model.seen[0][-1]
    assert isinstance(first_try.content, list)
    assert any(isinstance(p, dict) and p.get("type") == "image_url" for p in first_try.content)
