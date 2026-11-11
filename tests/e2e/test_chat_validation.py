"""Chat validation end to end (offline): widget, scan + gate flows.

No live brain: turns that need the model run through the service layer with
a fake model in tests/unit/test_chat.py. Here HTTP covers page, widget,
scope, gate requests, and confirm execution; the scan-confirm path proves
the chat-started run matches a dashboard scan-now run.
"""

from datetime import UTC, datetime
from unittest import mock

from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from security_agent.app import accounts as accounts_svc
from security_agent.app.dependencies import make_csrf
from security_agent.app.main import app
from security_agent.control import gates
from security_agent.control import repos as repo_svc
from security_agent.db.models import (
    Approval,
    ChatRole,
    EncryptedToken,
    GateAction,
    GateStatus,
    NotifyState,
    RepoKind,
    Role,
    RunTrigger,
    ScanRun,
)
from security_agent.db.session import session_scope

client = TestClient(app, raise_server_exceptions=False)


def _email(tag: str) -> str:
    return f"chate2e-{tag}-{datetime.now(UTC).timestamp()}@example.com"


def _login(role: Role):
    user = accounts_svc.create_user(_email(role.value), None, role)
    sid = accounts_svc.create_session(user.id)
    client.cookies.clear()
    client.cookies.set("app_session", sid)
    return user


def test_chat_page_gone_widget_and_scope():
    from security_agent.chat import get_conversation

    user = _login(Role.OWNER)
    repo = repo_svc.connect_repo("e2e-r", RepoKind.LOCAL, local_path="/tmp/e2e-r")
    try:
        assert client.get("/chat").status_code == 404
        widget = client.get("/chat/widget")
        assert widget.status_code == 200
        assert f"#{repo.id} {repo.name}" in widget.text
        dash = client.get("/dashboard")
        assert dash.status_code == 200
        assert 'href="/chat"' not in dash.text
        assert 'hx-get="/chat/widget"' in dash.text
        assert "#chat-widget { position: fixed; right: 1.25rem; bottom: 1.25rem;" in dash.text
        assert "#chat-widget [hidden] { display: none !important; }" in dash.text
        resp = client.post(
            "/chat/scope",
            data={"csrf": make_csrf(), "repo_id": str(repo.id)},
            headers={"HX-Request": "true"},
        )
        assert resp.status_code == 200
        assert get_conversation(user.id).repo_id == repo.id
    finally:
        repo_svc.disconnect_repo(repo.id)


def test_scan_confirm_creates_manual_run_with_watch_card():
    from security_agent.chat import append_message, get_conversation, history
    from security_agent.chat.tools import want_scan

    user = _login(Role.OWNER)
    repo = repo_svc.connect_repo("e2e-s", RepoKind.LOCAL, local_path="/tmp/e2e-s")
    try:
        with session_scope() as db:
            # Drop the scan-on-connect run: the trigger dedups in-flight runs.
            db.execute(delete(ScanRun).where(ScanRun.repo_id == repo.id))
        conv = get_conversation(user.id)
        out = want_scan(user, repo.id)
        msg = append_message(conv.id, ChatRole.ASSISTANT, "confirm?", out["card"])
        resp = client.post(f"/chat/confirm/{msg.id}", data={"csrf": make_csrf()})
        assert resp.status_code == 200, resp.text[:300]
        assert "data-run-watch" in resp.text
        with session_scope() as db:
            run = db.scalar(
                select(ScanRun).where(ScanRun.repo_id == repo.id).order_by(ScanRun.id.desc())
            )
            assert run is not None and run.trigger == RunTrigger.MANUAL
        reply = history(conv.id)[-1]
        assert reply.card["kind"] == "run"
        assert reply.card["events_url"].endswith(f"/runs/{run.id}/events")
    finally:
        with session_scope() as db:
            db.execute(delete(ScanRun).where(ScanRun.repo_id == repo.id))
        repo_svc.disconnect_repo(repo.id)


def test_developer_scans_but_cannot_decide_gates_over_http():
    from security_agent.chat import append_message, get_conversation
    from security_agent.chat.tools import want_scan

    dev = _login(Role.DEVELOPER)
    repo = repo_svc.connect_repo("e2e-d", RepoKind.LOCAL, local_path="/tmp/e2e-d")
    gate = gates.request_gate(repo.id, GateAction.MERGE, "e2e-d-target")
    try:
        conv = get_conversation(dev.id)
        msg = append_message(
            conv.id, ChatRole.ASSISTANT, "confirm?", want_scan(dev, repo.id)["card"]
        )
        resp = client.post(f"/chat/confirm/{msg.id}", data={"csrf": make_csrf()})
        assert resp.status_code == 200
        resp = client.post(
            f"/chat/gates/{gate.id}/request",
            data={"csrf": make_csrf(), "approved": "yes"},
        )
        assert resp.status_code == 403
    finally:
        with session_scope() as db:
            db.execute(delete(Approval).where(Approval.id == gate.id))
            db.execute(delete(ScanRun).where(ScanRun.repo_id == repo.id))
        repo_svc.disconnect_repo(repo.id)


def test_chat_gate_decision_matches_dashboard_path():
    """Same decide_gate core: status, decider, reason identical either way."""
    owner = _login(Role.OWNER)
    repo = repo_svc.connect_repo("e2e-p", RepoKind.LOCAL, local_path="/tmp/e2e-p")
    via_chat = gates.request_gate(repo.id, GateAction.MERGE, "e2e-p-chat")
    via_dash = gates.request_gate(repo.id, GateAction.MERGE, "e2e-p-dash")
    try:
        csrf = make_csrf()
        resp = client.post(
            f"/chat/gates/{via_chat.id}/request",
            data={"csrf": csrf, "approved": "yes", "reason": "ship"},
        )
        assert resp.status_code == 200
        from security_agent.chat import get_conversation, history

        conv = get_conversation(owner.id)
        pending = [m for m in history(conv.id) if (m.card or {}).get("state") == "pending"]
        assert len(pending) == 1
        resp = client.post(f"/chat/confirm/{pending[0].id}", data={"csrf": csrf})
        assert resp.status_code == 200
        resp = client.post(
            f"/approvals/{via_dash.id}/approve", data={"csrf": csrf, "reason": "ship"}
        )
        assert resp.status_code in (303, 200), resp.text[:300]
        with session_scope() as db:
            chat_row = db.get(Approval, via_chat.id)
            dash_row = db.get(Approval, via_dash.id)
            assert chat_row is not None and dash_row is not None
            assert (chat_row.status, chat_row.decider_id, chat_row.reason) == (
                GateStatus.APPROVED,
                owner.id,
                "ship",
            )
            assert (dash_row.status, dash_row.decider_id, dash_row.reason) == (
                GateStatus.APPROVED,
                owner.id,
                "ship",
            )
    finally:
        with session_scope() as db:
            db.execute(delete(Approval).where(Approval.id.in_([via_chat.id, via_dash.id])))
        repo_svc.disconnect_repo(repo.id)


def test_fake_model_turn_over_http_shape():
    """answer_turn output renders through the shared message partial."""
    from security_agent.chat import get_conversation
    from security_agent.chat.agent import answer_turn

    owner = _login(Role.OWNER)
    conv = get_conversation(owner.id)

    class FakeChat:
        def bind_tools(self, _tools):
            return self

        def invoke(self, _messages):
            resp = mock.Mock()
            resp.content = "2 open findings."
            resp.tool_calls = []
            resp.usage_metadata = {"input_tokens": 3, "output_tokens": 3}
            return resp

    reply = answer_turn(owner, conv, "findings?", model=FakeChat())
    assert reply.content == "2 open findings."
    widget = client.get("/chat/widget")
    assert widget.status_code == 200
    assert "2 open findings." in widget.text


def test_widget_has_upload_composer_and_min_height():
    _login(Role.OWNER)
    widget = client.get("/chat/widget")
    assert widget.status_code == 200
    assert 'name="files"' in widget.text
    assert "data-chat-input" in widget.text
    assert "data-mic" not in widget.text  # voice removed for now
    dash = client.get("/dashboard")
    assert "#widget-thread { display: flex" in dash.text
    assert "min-height: 20rem" in dash.text


def test_widget_has_launcher_and_header_controls():
    _login(Role.OWNER)
    widget = client.get("/chat/widget")
    assert widget.status_code == 200
    assert 'id="chat-launcher"' in widget.text
    assert 'id="chat-panel"' in widget.text
    assert "data-chat-new" in widget.text
    assert 'id="chat-history-btn"' in widget.text
    assert 'id="chat-history-view"' in widget.text
    assert 'id="chat-thread-view"' in widget.text
    assert 'class="chat-composer"' in widget.text
    assert "Open full chat" not in widget.text
    # New chat submits with CSRF (bare hx-post buttons 403).
    assert 'hx-post="/chat/new"' in widget.text
    new_form = widget.text.split('hx-post="/chat/new"')[1].split("</form>")[0]
    assert 'name="csrf"' in new_form


def test_new_chat_over_http_clears_thread():
    from security_agent.chat import append_message, get_conversation

    user = _login(Role.OWNER)
    conv = get_conversation(user.id)
    append_message(conv.id, ChatRole.USER, "old thread")
    hx = {"HX-Request": "true", "Accept": "text/html"}
    resp = client.post("/chat/new", data={"csrf": make_csrf()}, headers=hx)
    assert resp.status_code == 200
    assert "old thread" not in resp.text
    assert get_conversation(user.id).id != conv.id


def test_new_switch_and_threads_endpoints():
    from security_agent.chat import append_message, get_conversation

    user = _login(Role.OWNER)
    conv = get_conversation(user.id)
    append_message(conv.id, ChatRole.USER, "thread one")
    csrf = make_csrf()
    resp = client.post("/chat/new", data={"csrf": csrf})
    assert resp.status_code in (303, 200)
    hx = {"HX-Request": "true", "Accept": "text/html"}
    threads = client.get("/chat/threads")
    assert threads.status_code == 200
    assert "thread one" in threads.text
    resp = client.post(f"/chat/switch/{conv.id}", data={"csrf": csrf}, headers=hx)
    assert resp.status_code == 200
    assert "thread one" in resp.text
    _login(Role.OWNER)
    resp = client.post(f"/chat/switch/{conv.id}", data={"csrf": make_csrf()})
    assert resp.status_code == 404


def test_mentions_endpoint_scopes_users_to_owner():
    _login(Role.DEVELOPER)
    resp = client.get("/chat/mentions", params={"q": "", "kind": "@"})
    assert resp.status_code == 200
    assert all("@" not in item["token"][1:] for item in resp.json())
    _login(Role.OWNER)
    resp = client.get("/chat/mentions", params={"q": "", "kind": "@"})
    assert resp.status_code == 200


def test_message_with_upload_shows_chips_and_rejects_bad_file():
    _login(Role.OWNER)
    with session_scope() as db:  # unconfigured brain posts a notice
        db.execute(delete(NotifyState).where(NotifyState.key.like("brain.%")))
        db.execute(delete(EncryptedToken).where(EncryptedToken.owner.like("brain:%")))
    csrf = make_csrf()
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
    resp = client.post(
        "/chat/message",
        data={"csrf": csrf, "text": "look", "thread": "thread"},
        files={"files": ("shot.png", png, "image/png")},
    )
    # Unconfigured brain posts a notice, but validate/store/chips run first.
    assert resp.status_code == 200, resp.text[:300]
    assert "shot.png" in resp.text
    assert "Settings → Brain" in resp.text
    resp = client.post(
        "/chat/message",
        data={"csrf": csrf, "text": "x", "thread": "thread"},
        files={"files": ("x.exe", b"MZ" + b"\x00" * 10, "application/octet-stream")},
    )
    assert resp.status_code == 400
