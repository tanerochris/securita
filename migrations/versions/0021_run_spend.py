"""Per-run spend cap: cost_usd accumulator on scan_runs.

Caps moved from tokens to USD: enforcement compares each run's
accumulated model spend against the USD cap. token_usage stays as an
informational counter.

Forward: nullable `cost_usd` on scan_runs, backfilled from the
model_usage ledger so historical runs keep meaningful spend (runs
without ledger rows get 0). Code coalesces NULL defensively, so old
code (which ignores the new column) keeps running against the new
schema.

Rollback: drops the column. New code must not run against the
rolled-back schema (record_usage increments it) — deploy migrations
before code as usual.
"""

import sqlalchemy as sa
from alembic import op

revision = "0021_run_spend"
down_revision = "0020_notification_link"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_runs", sa.Column("cost_usd", sa.Float(), nullable=True))
    op.execute(
        "UPDATE scan_runs SET cost_usd = "
        "(SELECT COALESCE(SUM(cost_usd), 0) FROM model_usage "
        "WHERE model_usage.run_id = scan_runs.id)"
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("scan_runs") as batch:
            batch.drop_column("cost_usd")
    else:
        op.drop_column("scan_runs", "cost_usd")
