"""Notify: Discord, Telegram, PagerDuty channel kinds (additive enum labels).

Forward (Postgres): ALTER TYPE channel_kind ADD VALUE for the three new
labels. Idempotent (IF NOT EXISTS), preserves all rows, and runs in an
autocommit block because Postgres forbids ADD VALUE inside a transaction.
SQLite needs no DDL: test databases are built from the models, which now
include the new labels, and production is Postgres-only.

Rollback: intentionally a no-op. Postgres cannot drop enum values without
rebuilding the type, and leftover labels are harmless — old code only
reads and writes its own kinds.
"""

import sqlalchemy as sa
from alembic import op

revision = "0018_notify_extra_channels"
down_revision = "0017_dependencies"
branch_labels = None
depends_on = None

_NEW_LABELS = ("discord", "telegram", "pagerduty")


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    with op.get_context().autocommit_block():
        for label in _NEW_LABELS:
            op.execute(sa.text(f"ALTER TYPE channel_kind ADD VALUE IF NOT EXISTS '{label}'"))


def downgrade() -> None:
    # Labels stay; see module docstring.
    pass
