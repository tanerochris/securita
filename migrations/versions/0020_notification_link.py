"""Dashboard notifications: deep-link column for mirrored channel events.

Forward: nullable `link` on dashboard_notifications. Mirrored rows
(secret alerts, approvals, cost, policy, digest, findings) carry the
same dashboard path the channel message links to; existing rows keep
NULL and fall back to their repo/report links, so no backfill is
needed and old code (which selects the full row but ignores the new
column) keeps running against the new schema.

Rollback: drops the column. Mirrored rows keep their title/body but
lose deep links; dependency rows are unaffected (they never set it).
New code must not run against the rolled-back schema: the dashboard
mirror degrades to a warning, but direct pool writes with a link
would fail — deploy migrations before code as usual.
"""

import sqlalchemy as sa
from alembic import op

revision = "0020_notification_link"
down_revision = "0019_dep_report_guard"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("dashboard_notifications", sa.Column("link", sa.String(500), nullable=True))


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("dashboard_notifications") as batch:
            batch.drop_column("link")
    else:
        op.drop_column("dashboard_notifications", "link")
