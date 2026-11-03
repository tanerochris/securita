"""Queued vs running run status (scan runs + dependency checks).

Forward (Postgres):
- ALTER TYPE run_status ADD VALUE 'queued' (autocommit block; Postgres
  forbids ADD VALUE inside a transaction).
- Data fix: RUNNING rows no worker ever claimed were really queued.
- Single-flight partial indexes widen from `status = 'running'` to
  `status IN ('queued', 'running')` (renamed `..._one_inflight`), so a
  queued run still blocks a second enqueue for its repo.
SQLite needs no DDL: test databases are built from the models.

Mixed-version window: app and worker ship in one image and both upgrade
at boot before serving, so no old reader should meet a queued row. An
old reader that loads one fails to deserialize it (unknown label) —
deploy app and worker together, never staggered across this revision.

Rollback: queued rows flip back to running and the old indexes return.
The enum label stays (Postgres cannot drop values without rebuilding
the type); leftover labels are harmless.
"""

import sqlalchemy as sa
from alembic import op

revision = "0025_queued_runs"
down_revision = "0024_chat_multi"
branch_labels = None
depends_on = None

_TABLES = ("scan_runs", "dependency_checks")
_NEW_WHERE = "status IN ('queued', 'running')"
_OLD_WHERE = "status = 'running'"


def _index_names(table: str) -> tuple[str, str]:
    stem = "uq_scan_runs" if table == "scan_runs" else "uq_dependency_checks"
    return f"{stem}_one_running", f"{stem}_one_inflight"


def _existing_indexes(table: str) -> set[str]:
    """Index names on `table`; a partial run must be resumable.

    The worker retries the migration on every boot, so a hard failure
    is a crash loop: drops and creates check existence first.
    """
    return {ix["name"] for ix in sa.inspect(op.get_bind()).get_indexes(table)}


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    with op.get_context().autocommit_block():
        op.execute(sa.text("ALTER TYPE run_status ADD VALUE IF NOT EXISTS 'queued'"))
    for table in _TABLES:
        op.execute(
            sa.text(
                f"UPDATE {table} SET status = 'queued' "  # noqa: S608 internal fixed table
                "WHERE status = 'running' AND claimed_by IS NULL"
            )
        )
    for table in _TABLES:
        old, new = _index_names(table)
        present = _existing_indexes(table)
        # Create before drop: the single-flight guard never lapses, and a
        # resumed run skips whichever half already landed.
        if new not in present:
            op.create_index(
                new, table, ["repo_id"], unique=True, postgresql_where=sa.text(_NEW_WHERE)
            )
        if old in present:
            op.drop_index(old, table_name=table)


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in _TABLES:
        op.execute(
            sa.text(
                f"UPDATE {table} SET status = 'running' "  # noqa: S608 internal fixed table
                "WHERE status = 'queued'"
            )
        )
    for table in _TABLES:
        old, new = _index_names(table)
        present = _existing_indexes(table)
        if old not in present:
            op.create_index(
                old, table, ["repo_id"], unique=True, postgresql_where=sa.text(_OLD_WHERE)
            )
        if new in present:
            op.drop_index(new, table_name=table)
