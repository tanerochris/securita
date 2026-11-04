"""Policy dashboard: docs, rules queue, preview, RBAC."""

import re
from datetime import UTC, datetime
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from security_agent.app import accounts as accounts_svc
from security_agent.app.main import app
from security_agent.control import repos as repo_svc
from security_agent.db.models import RepoKind, Role
from security_agent.policy.rules import list_rules
from security_agent.policy.service import list_documents

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _no_embeddings():
    with mock.patch("security_agent.brain.embeddings.embed_texts", return_value=None):
        yield


def _login_as(role: Role) -> None:
    client.cookies.clear()
    email = f"pol-{role.value}-{datetime.now(UTC).timestamp()}@example.com"
    user = accounts_svc.create_user(email, None, role)
    sid = accounts_svc.create_session(user.id)
    client.cookies.set("app_session", sid)


def _csrf(page: str = "/policies") -> str:
    resp = client.get(page)
    match = re.search(r'name="csrf" value="([^"]+)"', resp.text)
    assert match, f"no csrf token on {page}"
    return match.group(1)


def _repo(name: str) -> int:
    return repo_svc.connect_repo(name, RepoKind.GIT, url=f"https://example.com/{name}.git").id


def test_policies_read_open_write_gated():
    from security_agent.app.dependencies import make_csrf

    _login_as(Role.REPORTER)
    assert client.get("/policies").status_code == 200
    # Reporters see no forms (no CSRF on the page), so mint one directly:
    # the 403 below must come from the role gate, not CSRF.
    resp = client.post(
        "/policies/editor",
        data={"csrf": make_csrf(), "scope": "platform", "title": "x", "text": "y"},
    )
    assert resp.status_code == 403
    _login_as(Role.OWNER)
    resp = client.post(
        "/policies/editor",
        data={
            "csrf": _csrf(),
            "scope": "platform",
            "title": "Owner doc",
            "text": "Guidance words.",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200 and "Owner doc" in resp.text


def test_upload_editor_rule_lifecycle():
    _login_as(Role.OWNER)
    stamp = datetime.now(UTC).timestamp()
    resp = client.post(
        "/policies/upload",
        data={"csrf": _csrf(), "scope": "platform", "title": f"Upload {stamp}"},
        files={"file": ("policy.md", b"# Rules\n\nNever auto-patch openssl.\n", "text/markdown")},
        follow_redirects=True,
    )
    assert resp.status_code == 200 and "ingested" in resp.text
    docs = [d for d in list_documents(scope="platform") if d.file_name == "policy.md"]
    assert docs
    doc = docs[-1]
    with mock.patch(
        "security_agent.policy.extract.draft_candidates",
        return_value={"status": "done", "created": 0, "rule_keys": []},
    ) as drafted:
        resp = client.post(
            f"/policies/docs/{doc.doc_key}/extract",
            data={"csrf": _csrf()},
            follow_redirects=True,
        )
    assert resp.status_code == 200
    drafted.assert_called_once_with(doc.doc_key)
    # Hand-written rule → pending → confirm → disable.
    resp = client.post(
        "/policies/rules",
        data={
            "csrf": _csrf(),
            "scope": "platform",
            "effect": "block",
            "package": "dash-lib",
            "reason": "dashboard rule",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200 and "drafted" in resp.text
    rule = [r for r in list_rules() if r.reason == "dashboard rule"][-1]
    assert rule.status == "pending"
    resp = client.post(
        f"/policies/rules/{rule.rule_key}/confirm",
        data={"csrf": _csrf()},
        follow_redirects=True,
    )
    assert resp.status_code == 200 and "confirmed" in resp.text
    resp = client.post(
        f"/policies/rules/{rule.rule_key}/disable",
        data={"csrf": _csrf()},
        follow_redirects=True,
    )
    assert resp.status_code == 200 and "disabled" in resp.text


def test_edit_doc_and_rule_endpoints():
    _login_as(Role.OWNER)
    client.post(
        "/policies/editor",
        data={
            "csrf": _csrf(),
            "scope": "platform",
            "title": "Editable doc",
            "text": "Original guidance words here.",
        },
    )
    doc = [d for d in list_documents(scope="platform") if d.title == "Editable doc"][-1]
    resp = client.post(
        f"/policies/docs/{doc.doc_key}/edit",
        data={"csrf": _csrf(), "title": "Renamed doc", "text": ""},
        follow_redirects=True,
    )
    assert resp.status_code == 200 and "new version" in resp.text
    client.post(
        "/policies/rules",
        data={
            "csrf": _csrf(),
            "scope": "platform",
            "effect": "silence",
            "package": "edit-lib",
            "reason": "first reason",
        },
    )
    rule = [r for r in list_rules() if r.reason == "first reason"][-1]
    resp = client.post(
        f"/policies/rules/{rule.rule_key}/edit",
        data={
            "csrf": _csrf(),
            "full_match": "on",
            "effect": "silence",
            "package": "edit-lib",
            "advisory": "",
            "ecosystem": "",
            "max_severity": "",
            "reason": "second reason",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200 and "updated" in resp.text


def test_upload_rejects_bad_suffix_and_secrets():
    _login_as(Role.OWNER)
    resp = client.post(
        "/policies/upload",
        data={"csrf": _csrf(), "scope": "platform"},
        files={"file": ("evil.exe", b"binary", "application/octet-stream")},
    )
    assert resp.status_code == 400
    resp = client.post(
        "/policies/upload",
        data={"csrf": _csrf(), "scope": "platform"},
        files={"file": ("leak.md", b"key AKIAIOSFODNN7EXAMPLE here", "text/markdown")},
    )
    assert resp.status_code == 400


def test_repo_policies_page_and_readme_toggle():
    _login_as(Role.OWNER)
    repo_id = _repo(f"dash-repo-{datetime.now(UTC).timestamp()}")
    resp = client.get(f"/repos/{repo_id}/policies")
    assert resp.status_code == 200 and "README guidance" in resp.text
    resp = client.post(
        f"/repos/{repo_id}/policies/readme-toggle",
        data={"csrf": _csrf(f"/repos/{repo_id}/policies"), "enabled": ""},
        follow_redirects=True,
    )
    assert resp.status_code == 200 and "disabled" in resp.text
    resp = client.post(
        "/policies/editor",
        data={
            "csrf": _csrf(),
            "scope": "repo",
            "repo_id": str(repo_id),
            "title": "Repo doc",
            "text": "Repo-specific guidance words.",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200 and "Repo doc" in resp.text


def test_edit_panels_render_below_tables():
    _login_as(Role.OWNER)
    stamp = datetime.now(UTC).timestamp()
    client.post(
        "/policies/editor",
        data={
            "csrf": _csrf(),
            "scope": "platform",
            "title": f"Panel doc {stamp}",
            "text": "Panel guidance words.",
        },
    )
    client.post(
        "/policies/rules",
        data={
            "csrf": _csrf(),
            "scope": "platform",
            "effect": "block",
            "package": "panel-lib",
            "reason": f"panel rule {stamp}",
        },
    )
    doc = [d for d in list_documents(scope="platform") if d.title == f"Panel doc {stamp}"][-1]
    rule = [r for r in list_rules() if r.reason == f"panel rule {stamp}"][-1]
    resp = client.get("/policies")
    assert resp.status_code == 200
    for anchor in (
        f'href="#edit-rule-{rule.rule_key}"',
        f'id="edit-rule-{rule.rule_key}"',
        f'data-edit-panel="edit-rule-{rule.rule_key}"',
        f'href="#edit-doc-{doc.doc_key}"',
        f'id="edit-doc-{doc.doc_key}"',
        f'data-edit-panel="edit-doc-{doc.doc_key}"',
        "data-edit-close",
    ):
        assert anchor in resp.text
    assert "<details" not in resp.text
    repo_id = _repo(f"panel-repo-{stamp}")
    client.post(
        "/policies/editor",
        data={
            "csrf": _csrf(),
            "scope": "repo",
            "repo_id": str(repo_id),
            "title": f"Repo panel {stamp}",
            "text": "Repo panel words.",
        },
    )
    client.post(
        "/policies/rules",
        data={
            "csrf": _csrf(),
            "scope": "repo",
            "repo_id": str(repo_id),
            "effect": "silence",
            "package": "panel-repo-lib",
            "reason": f"repo panel rule {stamp}",
        },
    )
    rdoc = [
        d
        for d in list_documents(scope="repo", repo_id=repo_id)
        if d.title == f"Repo panel {stamp}"
    ][-1]
    rrule = [r for r in list_rules() if r.reason == f"repo panel rule {stamp}"][-1]
    resp = client.get(f"/repos/{repo_id}/policies")
    assert resp.status_code == 200
    for anchor in (
        f'href="#edit-rule-{rrule.rule_key}"',
        f'id="edit-rule-{rrule.rule_key}"',
        f'data-edit-panel="edit-rule-{rrule.rule_key}"',
        f'href="#edit-doc-{rdoc.doc_key}"',
        f'id="edit-doc-{rdoc.doc_key}"',
        f'data-edit-panel="edit-doc-{rdoc.doc_key}"',
        "data-edit-close",
    ):
        assert anchor in resp.text
    assert "<details" not in resp.text


def _form_tag(html: str, action: str) -> str:
    match = re.search(rf'<form [^>]*action="{re.escape(action)}"[^>]*>', html)
    assert match, f"no form posts to {action}"
    return match.group(0)


def test_inline_actions_marked_and_redirect_to_fresh_sections():
    _login_as(Role.OWNER)
    stamp = datetime.now(UTC).timestamp()
    client.post(
        "/policies/editor",
        data={
            "csrf": _csrf(),
            "scope": "platform",
            "title": f"Inline doc {stamp}",
            "text": "Inline guidance words.",
        },
    )
    client.post(
        "/policies/rules",
        data={
            "csrf": _csrf(),
            "scope": "platform",
            "effect": "block",
            "package": "inline-lib",
            "reason": f"inline rule {stamp}",
        },
    )
    doc = [d for d in list_documents(scope="platform") if d.title == f"Inline doc {stamp}"][-1]
    rule = [r for r in list_rules() if r.reason == f"inline rule {stamp}"][-1]
    page = client.get("/policies").text
    for action in (
        f"/policies/rules/{rule.rule_key}/confirm",
        f"/policies/rules/{rule.rule_key}/disable",
        f"/policies/docs/{doc.doc_key}/disable",
    ):
        assert "data-inline" in _form_tag(page, action), action
    for action in (
        f"/policies/rules/{rule.rule_key}/edit",
        f"/policies/docs/{doc.doc_key}/edit",
        f"/policies/docs/{doc.doc_key}/extract",
        "/policies/upload",
        "/policies/editor",
        "/policies/rules",
    ):
        assert "data-inline" not in _form_tag(page, action), action
    # The fetch flow follows the redirect and swaps its sections in.
    resp = client.post(
        f"/policies/rules/{rule.rule_key}/confirm",
        data={"csrf": _csrf()},
        follow_redirects=False,
    )
    assert resp.status_code == 303 and "notice=" in resp.headers["location"]
    fresh = client.get(resp.headers["location"])
    assert fresh.status_code == 200 and "confirmed" in fresh.text
    assert rule.rule_key in fresh.text.split("Enforced rules")[1]


def test_preview_shows_matching_chunks():
    _login_as(Role.OWNER)
    client.post(
        "/policies/editor",
        data={
            "csrf": _csrf(),
            "scope": "platform",
            "title": "Preview doc",
            "text": "Unicorn libraries must never auto-patch without review.",
        },
    )
    resp = client.get("/policies/preview", params={"q": "unicorn libraries"})
    assert resp.status_code == 200 and "Unicorn" in resp.text
    resp = client.get("/policies/preview", params={"q": "zzz-no-such-term-zzz"})
    assert resp.status_code == 200 and "no policy" in resp.text
