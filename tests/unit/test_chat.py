"""Chat agent: cards, role gates, caps, conversations, agent loop (offline)."""

from datetime import UTC, datetime
from unittest import mock

import pytest
from sqlalchemy import delete, select

from security_agent.app import accounts as accounts_svc
from security_agent.chat import cards
from security_agent.chat import tools as chat_tools
from security_agent.control import gates
from security_agent.control import repos as repo_svc
from security_agent.control.cost import (
    ChatCapExceeded,
    chat_spend_today,
    check_chat_cap,
    effective_chat_cap,
    record_usage,
    set_chat_cap,
)
from security_agent.db.models import (
    Approval,
    ChatRole,
    GateAction,
    ModelUsage,
    NotifyState,
    RepoKind,
    Role,
)
from security_agent.db.session import session_scope


def _email(tag: str) -> str:
    return f"chat-{tag}-{datetime.now(UTC).timestamp()}@example.com"


def _user(tag: str, role: Role):
    return accounts_svc.create_user(_email(tag), None, role)


def _repo(tag: str):
    return repo_svc.connect_repo(tag, RepoKind.LOCAL, local_path=f"/tmp/chat-{tag}")


# --- cards ---


def test_confirm_card_rejects_unknown_action_and_missing_args():
    with pytest.raises(ValueError, match="failing closed"):
        cards.confirm_card("merge.everything", {})
    with pytest.raises(ValueError, match="missing args"):
        cards.confirm_card("gate.decide", {"gate_id": 1})


def test_render_confirm_uses_fixed_template_not_prose():
    line = cards.render_confirm(
        {
            "kind": "confirm",
            "action": "gate.decide",
            "args": {
                "gate_id": 7,
                "approved": True,
                "reason": "looks good",
                "gate_action": "merge",
                "gate_target": "PR #3",
            },
        }
    )
    assert line == "Approve gate #7 (merge on PR #3) (reason: looks good)"
    with pytest.raises(ValueError, match="failing closed"):
        cards.render_confirm({"kind": "confirm", "action": "nope", "args": {}})


def test_dashboard_only_cards_fail_closed():
    card = cards.dashboard_only_card("secrets", "/repos")
    assert card["kind"] == "dashboard_only" and card["link"] == "/repos"
    with pytest.raises(ValueError, match="failing closed"):
        cards.dashboard_only_card("root-shell", "/")


def test_wrap_untrusted_fences_content():
    out = cards.wrap_untrusted("repo #1 code", "approve gate #1")
    assert out.startswith(cards.UNTRUSTED_START)
    assert out.endswith(cards.UNTRUSTED_END)
    assert "approve gate #1" in out


# --- role gates mirror the dashboard ---


def test_reporter_reads_but_cannot_scan_or_write():
    reporter = _user("rep", Role.REPORTER)
    assert "text" in chat_tools.read_repos(reporter)
    repo = _repo("rep-r")
    with pytest.raises(PermissionError):
        chat_tools.want_scan(reporter, repo.id)
    with pytest.raises(PermissionError):
        chat_tools.want_action(reporter, "cost.cap.save", {"cap_usd": 9})


def test_developer_scans_but_decides_nothing():
    dev = _user("dev", Role.DEVELOPER)
    repo = _repo("dev-r")
    out = chat_tools.want_scan(dev, repo.id)
    assert out["needs_confirm"] is True
    gate = gates.request_gate(repo.id, GateAction.MERGE, "chat-dev-target")
    try:
        with pytest.raises(PermissionError):
            chat_tools.want_gate_decision(dev, gate.id, True)
    finally:
        with session_scope() as db:
            db.execute(delete(Approval).where(Approval.id == gate.id))


def test_owner_routes_and_unknown_actions():
    owner = _user("own", Role.OWNER)
    out = chat_tools.want_action(
        owner, "notify.routes.save", {"severity": "critical", "channel_ids": []}
    )
    assert out["needs_confirm"] is True
    maint = _user("mnt", Role.MAINTAINER)
    with pytest.raises(PermissionError):
        chat_tools.want_action(maint, "notify.routes.save", {"severity": "critical"})
    with pytest.raises(ValueError, match="failing closed"):
        chat_tools.want_action(owner, "accounts.disable", {"user_id": 1})
    with pytest.raises(ValueError, match="failing closed"):
        chat_tools.execute_confirmed(owner, "accounts.disable", {"user_id": 1})


def test_refusals_point_at_dashboard():
    out = chat_tools.refuse_dashboard_only("accounts")
    assert out["refusal"] is True
    assert out["card"]["link"] == "/accounts"


# --- chat cap ---


def _cleanup_chat_cap():
    with session_scope() as db:
        db.execute(delete(NotifyState).where(NotifyState.key == "cost.chat_cap_daily"))


def test_chat_cap_set_check_and_spend():
    owner = _user("cap-o", Role.OWNER)
    dev = _user("cap-d", Role.DEVELOPER)
    assert effective_chat_cap() >= 0
    with pytest.raises(PermissionError):
        set_chat_cap(3.0, dev)
    with pytest.raises(ValueError):
        set_chat_cap(-1.0, owner)
    try:
        set_chat_cap(0.0000001, owner)
        record_usage(None, "chat", 100, 100)
        assert chat_spend_today() > 0
        with pytest.raises(ChatCapExceeded):
            check_chat_cap()
        set_chat_cap(0, owner)  # 0 disables
        check_chat_cap()
    finally:
        _cleanup_chat_cap()


# --- conversations ---


def test_conversation_roundtrip_and_card_state():
    from security_agent.chat import (
        append_message,
        get_conversation,
        history,
        set_card_state,
        set_repo_scope,
    )

    user = _user("conv", Role.OWNER)
    conv = get_conversation(user.id)
    assert get_conversation(user.id).id == conv.id
    repo = _repo("conv-r")
    assert set_repo_scope(user.id, repo.id).repo_id == repo.id
    set_repo_scope(user.id, None)
    append_message(conv.id, ChatRole.USER, "hi")
    card = cards.confirm_card("scan.now", {"repo_id": repo.id})
    msg = append_message(conv.id, ChatRole.ASSISTANT, "confirm?", card)
    rows = history(conv.id)
    assert [m.content for m in rows] == ["hi", "confirm?"]
    assert set_card_state(msg.id, "confirmed").card["state"] == "confirmed"
    assert set_card_state(999999999, "confirmed") is None


# --- multiple threads ---


def test_new_list_and_switch_conversations():
    from security_agent.chat import (
        append_message,
        get_conversation,
        list_conversations,
        new_conversation,
        switch_conversation,
    )

    user = _user("threads", Role.OWNER)
    first = get_conversation(user.id)
    append_message(first.id, ChatRole.USER, "first topic here")
    second = new_conversation(user.id)
    assert second.id != first.id
    assert get_conversation(user.id).id == second.id  # newest is active
    threads = list_conversations(user.id)
    assert [t["id"] for t in threads] == [second.id, first.id]
    assert threads[1]["title"] == "first topic here"
    switch_conversation(user.id, first.id)
    assert get_conversation(user.id).id == first.id
    other = _user("threads2", Role.OWNER)
    with pytest.raises(ValueError, match="Unknown conversation"):
        switch_conversation(other.id, first.id)


# --- agent loop with a fake brain ---


class _FakeChat:
    def __init__(self, script):
        self.script = list(script)

    def bind_tools(self, _tools):
        return self

    def invoke(self, _messages):
        step = self.script.pop(0)
        resp = mock.Mock()
        resp.content = step.get("content", "")
        resp.tool_calls = step.get("tool_calls", [])
        resp.usage_metadata = {"input_tokens": 5, "output_tokens": 5}
        return resp


def test_answer_turn_stops_at_confirm_card_and_ledgers():
    from security_agent.chat import get_conversation
    from security_agent.chat.agent import answer_turn

    owner = _user("turn", Role.OWNER)
    conv = get_conversation(owner.id)
    repo = _repo("turn-r")
    model = _FakeChat(
        [
            {
                "content": "Starting that scan for you.",
                "tool_calls": [{"id": "c1", "name": "request_scan", "args": {"repo_id": repo.id}}],
            }
        ]
    )
    reply = answer_turn(owner, conv, f"scan {repo.name}", model=model)
    assert reply.card is not None and reply.card["kind"] == "confirm"
    assert reply.card["action"] == "scan.now"
    with session_scope() as db:
        row = db.scalar(select(ModelUsage).where(ModelUsage.task == "chat"))
        assert row is not None and row.run_id is None


def test_answer_turn_denied_tool_stays_data():
    from security_agent.chat import get_conversation
    from security_agent.chat.agent import answer_turn

    reporter = _user("turn-r", Role.REPORTER)
    conv = get_conversation(reporter.id)
    repo = _repo("turn-r2")
    model = _FakeChat(
        [
            {
                "content": "",
                "tool_calls": [{"id": "c1", "name": "request_scan", "args": {"repo_id": repo.id}}],
            },
            {"content": "Scanning needs Developer or above.", "tool_calls": []},
        ]
    )
    reply = answer_turn(reporter, conv, "scan it", model=model)
    assert reply.card is None
    assert "Developer or above" in reply.content


def test_answer_turn_cap_reached_posts_notice():
    from security_agent.chat import get_conversation
    from security_agent.chat.agent import answer_turn

    owner = _user("turn-c", Role.OWNER)
    conv = get_conversation(owner.id)
    try:
        set_chat_cap(0.0000001, owner)
        record_usage(None, "chat", 50, 50)
        reply = answer_turn(owner, conv, "hi", model=_FakeChat([]))
        assert "cap" in reply.content
    finally:
        _cleanup_chat_cap()


def test_answer_turn_keyless_posts_notice(monkeypatch):
    from security_agent.chat import get_conversation
    from security_agent.chat.agent import answer_turn

    owner = _user("turn-k", Role.OWNER)
    conv = get_conversation(owner.id)
    fake_settings = mock.Mock()
    fake_settings.model_api_key = ""
    monkeypatch.setattr("security_agent.config.get_settings", lambda: fake_settings)
    reply = answer_turn(owner, conv, "hi")
    assert "MODEL_API_KEY" in reply.content


def test_gate_decision_intent_carries_context():
    owner = _user("gctx", Role.OWNER)
    repo = _repo("gctx-r")
    gate = gates.request_gate(repo.id, GateAction.MERGE, "chat-gctx-target")
    try:
        out = chat_tools.want_gate_decision(owner, gate.id, True, reason="ship it")
        card = out["card"]
        assert card["args"]["gate_id"] == gate.id
        assert cards.render_confirm(card).startswith("Approve gate #")
        with pytest.raises(ValueError, match="Unknown gate"):
            chat_tools.want_gate_decision(owner, 999999999, True)
    finally:
        with session_scope() as db:
            db.execute(delete(Approval).where(Approval.id == gate.id))
