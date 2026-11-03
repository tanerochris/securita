"""Chat agent: persistent conversations (many threads per user, latest active)."""

from datetime import UTC, datetime

from sqlalchemy import func, select

from security_agent.db.models import ChatMessage, ChatRole, Conversation
from security_agent.db.session import session_scope

HISTORY_LIMIT = 40
THREAD_LIST_LIMIT = 20


def get_conversation(user_id: int) -> Conversation:
    """Active conversation (most recently updated), created on first chat."""
    with session_scope() as db:
        conv = db.scalar(
            select(Conversation)
            .where(Conversation.user_id == user_id)
            .order_by(Conversation.updated_at.desc(), Conversation.id.desc())
        )
        if conv is None:
            conv = Conversation(user_id=user_id)
            db.add(conv)
            db.flush()
        db.expunge(conv)
        return conv


def new_conversation(user_id: int) -> Conversation:
    """Start a fresh thread; it becomes active immediately."""
    with session_scope() as db:
        conv = Conversation(user_id=user_id)
        db.add(conv)
        db.flush()
        db.expunge(conv)
        return conv


def switch_conversation(user_id: int, conversation_id: int) -> Conversation:
    """Make a thread active (ownership-checked)."""
    with session_scope() as db:
        conv = db.get(Conversation, conversation_id)
        if conv is None or conv.user_id != user_id:
            raise ValueError("Unknown conversation.")
        conv.updated_at = datetime.now(UTC)
        db.flush()
        db.expunge(conv)
        return conv


def list_conversations(user_id: int, limit: int = THREAD_LIST_LIMIT) -> list[dict]:
    """Threads newest-first with title preview (first user message)."""
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(Conversation)
                .where(Conversation.user_id == user_id)
                .order_by(Conversation.updated_at.desc(), Conversation.id.desc())
                .limit(limit)
            )
        )
        out = []
        for row in rows:
            first = db.scalar(
                select(ChatMessage.content)
                .where(
                    ChatMessage.conversation_id == row.id,
                    ChatMessage.role == ChatRole.USER,
                )
                .order_by(ChatMessage.id)
                .limit(1)
            )
            count = db.scalar(
                select(func.count())
                .select_from(ChatMessage)
                .where(ChatMessage.conversation_id == row.id)
            )
            title = (first or "").strip().split("\n")[0][:60] or "New chat"
            out.append(
                {
                    "id": row.id,
                    "title": title,
                    "messages": int(count or 0),
                    "updated_at": row.updated_at,
                }
            )
        return out


def set_repo_scope(user_id: int, repo_id: int | None) -> Conversation:
    conv = get_conversation(user_id)
    with session_scope() as db:
        row = db.get(Conversation, conv.id)
        if row is None:
            raise ValueError("Conversation is gone.")
        row.repo_id = repo_id
        db.flush()
        db.expunge(row)
        return row


def append_message(
    conversation_id: int,
    role: ChatRole,
    content: str,
    card: dict | None = None,
) -> ChatMessage:
    with session_scope() as db:
        msg = ChatMessage(conversation_id=conversation_id, role=role, content=content, card=card)
        db.add(msg)
        conv = db.get(Conversation, conversation_id)
        if conv is not None:
            conv.updated_at = datetime.now(UTC)
        db.flush()
        db.expunge(msg)
        return msg


def history(conversation_id: int, limit: int = HISTORY_LIMIT) -> list[ChatMessage]:
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(ChatMessage)
                .where(ChatMessage.conversation_id == conversation_id)
                .order_by(ChatMessage.id.desc())
                .limit(limit)
            )
        )
        for row in rows:
            db.expunge(row)
        return list(reversed(rows))


def set_card_state(message_id: int, state: str) -> ChatMessage | None:
    """Flip a card's state (pending -> confirmed/dismissed/failed)."""
    with session_scope() as db:
        msg = db.get(ChatMessage, message_id)
        if msg is None or not msg.card:
            return None
        msg.card = {**msg.card, "state": state}
        db.flush()
        db.expunge(msg)
        return msg


def get_message(message_id: int) -> ChatMessage | None:
    with session_scope() as db:
        msg = db.get(ChatMessage, message_id)
        if msg is None:
            return None
        db.expunge(msg)
        return msg
