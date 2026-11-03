"""Chat agent history: one conversation per user + messages with cards.

Forward: creates `conversations` (user_id unique) and `chat_messages`
(conversation FK, role enum, JSON card for gate/confirm/info cards).
Rollback: drops both tables; chat history is convenience state, safe to lose.
"""

import sqlalchemy as sa
from alembic import op

revision = "0022_chat"
down_revision = "0021_run_spend"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "conversations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), unique=True, index=True),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=True, index=True),
        sa.Column("title", sa.String(200), nullable=False, server_default="Chat"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "chat_messages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "conversation_id",
            sa.Integer(),
            sa.ForeignKey("conversations.id"),
            index=True,
            nullable=False,
        ),
        sa.Column(
            "role",
            sa.Enum("user", "assistant", "system", name="chat_role"),
            nullable=False,
        ),
        sa.Column("content", sa.Text(), nullable=False, server_default=""),
        sa.Column("card", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
    )


def downgrade() -> None:
    op.drop_table("chat_messages")
    op.drop_table("conversations")
    op.execute("DROP TYPE IF EXISTS chat_role")
