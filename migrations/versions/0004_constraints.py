"""Single-flight runs + unique token owners + lowercase enum storage.

The ORM now persists enum values (see models._stored), matching the
lowercase labels in 0001-0003. Pre-existing SQLite rows are normalized;
Postgres could never have received mismatched writes (native enum
rejects unknown labels), so no data fix is needed there.
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_constraints"
down_revision = "0003_phase1"
branch_labels = None
depends_on = None

_ENUM_COLUMNS: tuple[tuple[str, str], ...] = (
    ("users", "role"),
    ("invites", "role"),
    ("repos", "kind"),
    ("scan_runs", "status"),
    ("scan_runs", "trigger"),
    ("findings", "status"),
    ("findings", "scope"),
    ("proposals", "status"),
    ("approvals", "action"),
    ("approvals", "status"),
)


def upgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        for table, column in _ENUM_COLUMNS:
            op.execute(
                sa.text(
                    f"UPDATE {table} SET {column} = lower({column}) "  # noqa: S608
                    f"WHERE {column} IS NOT NULL"
                )
            )
        with op.batch_alter_table("encrypted_tokens") as batch:
            batch.create_unique_constraint("uq_encrypted_tokens_owner", ["owner"])
    else:
        op.create_unique_constraint("uq_encrypted_tokens_owner", "encrypted_tokens", ["owner"])
    op.create_index(
        "uq_scan_runs_one_running",
        "scan_runs",
        ["repo_id"],
        unique=True,
        sqlite_where=sa.text("status = 'running'"),
        postgresql_where=sa.text("status = 'running'"),
    )
    op.create_index(
        "uq_approvals_one_pending",
        "approvals",
        ["repo_id", "action", "target"],
        unique=True,
        sqlite_where=sa.text("status = 'pending'"),
        postgresql_where=sa.text("status = 'pending'"),
    )


def downgrade() -> None:
    op.drop_index("uq_approvals_one_pending", table_name="approvals")
    op.drop_index("uq_scan_runs_one_running", table_name="scan_runs")
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("encrypted_tokens") as batch:
            batch.drop_constraint("uq_encrypted_tokens_owner", type_="unique")
    else:
        op.drop_constraint("uq_encrypted_tokens_owner", "encrypted_tokens", type_="unique")
