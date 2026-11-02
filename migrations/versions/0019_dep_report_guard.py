"""Dependency report invariant: one pending combined report per repo.

Forward: partial unique index on dependency_reports(repo_id) WHERE
status='pending' (D9 single decision point), mirroring the approvals
one-pending precedent. Existing duplicate pending reports (possible
only via the pre-fix double-execution window) are superseded except
the newest per repo before the index lands, so the upgrade cannot
fail on dirty data; no report content is deleted.

Rollback: drops the index. Superseded duplicates stay superseded;
the next check re-reports the update set if it is still live.
"""

import sqlalchemy as sa
from alembic import op

revision = "0019_dep_report_guard"
down_revision = "0018_notify_extra_channels"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE dependency_reports SET status = 'superseded' "
            "WHERE status = 'pending' AND id NOT IN ("
            "SELECT MAX(id) FROM dependency_reports "
            "WHERE status = 'pending' GROUP BY repo_id)"
        )
    )
    op.execute(
        sa.text(
            "CREATE UNIQUE INDEX uq_dependency_reports_one_pending "
            "ON dependency_reports (repo_id) WHERE status = 'pending'"
        )
    )


def downgrade() -> None:
    op.execute(sa.text("DROP INDEX uq_dependency_reports_one_pending"))
