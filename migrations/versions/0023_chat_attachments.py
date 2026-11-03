"""Chat attachments: files on messages (vision images, context docs).

Forward: creates `chat_attachments` (conversation + message FKs, capped
blobs validated at upload). Rollback: drops the table; attachments are
conversation convenience state, safe to lose.
"""

import sqlalchemy as sa
from alembic import op

revision = "0023_chat_attachments"
down_revision = "0022_chat"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "chat_attachments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "conversation_id",
            sa.Integer(),
            sa.ForeignKey("conversations.id"),
            index=True,
            nullable=False,
        ),
        sa.Column(
            "message_id",
            sa.Integer(),
            sa.ForeignKey("chat_messages.id"),
            nullable=True,
            index=True,
        ),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("mime", sa.String(100), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("blob", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("chat_attachments")
