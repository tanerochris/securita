"""Multi-conversation chat: drop the one-thread-per-user unique constraint.

Forward: `conversations.user_id` loses UNIQUE so a user can keep many
threads (history + new chat); existing rows untouched, no data migration.
Postgres drops the `conversations_user_id_key` constraint; SQLite rebuilds
the table (copy out, drop, rename) since it cannot drop constraints.

Rollback: re-adds UNIQUE — DESTRUCTIVE unless one thread per user: extra
threads (all but the most recently updated per user, with their messages
and attachments) are deleted first. Run only on explicit operator request.
"""

import sqlalchemy as sa
from alembic import op

revision = "0024_chat_multi"
down_revision = "0023_chat_attachments"
branch_labels = None
depends_on = None


def _columns(unique: bool) -> list:
    return [
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id"),
            unique=unique,
            index=True,
            nullable=False,
        ),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=True, index=True),
        sa.Column("title", sa.String(200), nullable=False, server_default="Chat"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    ]


def _rebuild(unique: bool, temp: str) -> None:
    op.create_table(temp, *_columns(unique))
    op.execute(
        f"INSERT INTO {temp} "  # noqa: S608 internal fixed table name
        "(id, user_id, repo_id, title, created_at, updated_at) "
        "SELECT id, user_id, repo_id, title, created_at, updated_at FROM conversations"
    )
    op.drop_table("conversations")
    op.rename_table(temp, "conversations")


def _user_unique_names(bind) -> list:
    """Names of UNIQUE constraints covering exactly conversations.user_id.

    Fresh installs that never carried the one-thread-per-user shape have
    none; dropping unconditionally would abort the whole upgrade (the
    worker retries the migration on every boot, so a hard failure is a
    crash loop). Match by covered column, not just the stock Postgres
    name, so renamed constraints still go.
    """
    insp = sa.inspect(bind)
    return [
        const["name"]
        for const in insp.get_unique_constraints("conversations")
        if list(const.get("column_names") or []) == ["user_id"]
    ]


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        _rebuild(unique=False, temp="conversations_new")
    else:
        for name in _user_unique_names(bind):
            op.drop_constraint(name, "conversations", type_="unique")


def downgrade() -> None:
    from collections import defaultdict

    bind = op.get_bind()
    # Keep the most recently updated thread per user; delete the rest.
    rows = bind.execute(sa.text("SELECT id, user_id, updated_at FROM conversations")).all()
    by_user: dict = defaultdict(list)
    for row in rows:
        by_user[row.user_id].append(row)
    doomed: list[int] = []
    for user_rows in by_user.values():
        user_rows.sort(key=lambda r: (str(r.updated_at), r.id), reverse=True)
        doomed.extend(r.id for r in user_rows[1:])
    deletes = {
        "chat_messages": "conversation_id",
        "chat_attachments": "conversation_id",
        "conversations": "id",
    }
    for table, column in deletes.items():
        if doomed:
            bind.execute(
                sa.text(
                    f"DELETE FROM {table} WHERE {column} IN :ids"  # noqa: S608 fixed names
                ).bindparams(sa.bindparam("ids", expanding=True)),
                {"ids": doomed},
            )
    if bind.dialect.name == "sqlite":
        _rebuild(unique=True, temp="conversations_old")
    elif not _user_unique_names(bind):
        op.create_unique_constraint("conversations_user_id_key", "conversations", ["user_id"])
