"""Dependency updates: Dependency table, checks, reports, notifications.

Forward: two additive nullable columns on repos (cadence override +
last-check stamp, so existing rows are untouched) plus four new tables
(dependencies, dependency_reports, dependency_checks, dashboard
notifications + per-user reads). The dependency_status enum persists by
value on Postgres; SQLite stores plain strings.

Rollback: drops the tables, indexes, and columns. Dependency tracking
data does not survive a downgrade — the next scheduled check rebuilds
the table from the manifests.
"""

import sqlalchemy as sa
from alembic import op

revision = "0017_dependencies"
down_revision = "0016_policy_rag"
branch_labels = None
depends_on = None


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    op.add_column("repos", sa.Column("dep_schedule_hours", sa.Integer(), nullable=True))
    op.add_column(
        "repos", sa.Column("dep_last_check_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_index(
        "ix_repos_dep_last_check_at", "repos", ["dep_last_check_at"], unique=False
    )
    if _is_postgres():
        op.execute(
            sa.text(
                "CREATE TYPE dependency_status AS ENUM "
                "('up_to_date', 'update_available', 'awaiting_decision', 'proposed', "
                "'declined', 'ignored', 'covered_by_finding', 'check_failed', "
                "'report_pending_cap')"
            )
        )
        status_col = sa.Column(
            "status",
            sa.Enum(
                "up_to_date",
                "update_available",
                "awaiting_decision",
                "proposed",
                "declined",
                "ignored",
                "covered_by_finding",
                "check_failed",
                "report_pending_cap",
                name="dependency_status",
                native_enum=True,
                create_type=False,
            ),
            nullable=False,
            server_default="up_to_date",
        )
    else:
        status_col = sa.Column("status", sa.String(30), nullable=False, server_default="up_to_date")
    op.create_table(
        "dependencies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=False),
        sa.Column("ecosystem", sa.String(50), nullable=False),
        sa.Column("manifest_path", sa.String(2000), nullable=False),
        sa.Column("package", sa.String(500), nullable=False),
        sa.Column("section", sa.String(100), nullable=True),
        sa.Column("manifest_spec", sa.String(200), nullable=True),
        sa.Column("installed_version", sa.String(100), nullable=True),
        sa.Column("latest_version", sa.String(100), nullable=True),
        sa.Column("wanted_version", sa.String(100), nullable=True),
        sa.Column("update_class", sa.String(10), nullable=True),
        sa.Column("security", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=True),
        sa.Column("proposal_id", sa.Integer(), sa.ForeignKey("proposals.id"), nullable=True),
        status_col,
        sa.Column("declined_version", sa.String(100), nullable=True),
        sa.Column("ignored_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("ignored_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stale", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("check_error", sa.Text(), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "repo_id",
            "ecosystem",
            "manifest_path",
            "package",
            name="uq_dependency_repo_eco_manifest_pkg",
        ),
    )
    op.create_index("ix_dependencies_repo_id", "dependencies", ["repo_id"], unique=False)
    op.create_index("ix_dependencies_package", "dependencies", ["package"], unique=False)
    op.create_index(
        "ix_dependencies_repo_status", "dependencies", ["repo_id", "status"], unique=False
    )
    # Checks and reports reference each other (check.report_id, report.check_id),
    # so checks go first with a plain integer; the FK lands after both exist.
    op.create_table(
        "dependency_checks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=False),
        sa.Column(
            "status",
            sa.Enum("running", "done", "failed", name="run_status", create_type=False),
            nullable=False,
        ),
        sa.Column(
            "trigger",
            sa.Enum(
                "connect",
                "manual",
                "scheduled",
                "webhook",
                name="run_trigger",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("manifests", sa.JSON(), nullable=True),
        sa.Column("update_set_hash", sa.String(64), nullable=True),
        sa.Column("report_id", sa.Integer(), nullable=True),
        sa.Column("token_usage", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("claimed_by", sa.String(100), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "dependency_reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=False),
        sa.Column(
            "check_id", sa.Integer(), sa.ForeignKey("dependency_checks.id"), nullable=True
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("sections", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("update_set_hash", sa.String(64), nullable=True),
        sa.Column("model_backed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("undecided_keys", sa.JSON(), nullable=True),
        sa.Column("decided_keys", sa.JSON(), nullable=True),
        sa.Column("excluded_keys", sa.JSON(), nullable=True),
        sa.Column("decided_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_dependency_reports_repo_id", "dependency_reports", ["repo_id"], unique=False
    )
    if _is_postgres():
        # SQLite takes no ALTER for constraints and enforces no FKs here;
        # the column stands alone on SQLite, constrained on Postgres.
        op.create_foreign_key(
            "fk_dependency_checks_report_id",
            "dependency_checks",
            "dependency_reports",
            ["report_id"],
            ["id"],
        )
    op.create_index(
        "ix_dependency_checks_repo_id", "dependency_checks", ["repo_id"], unique=False
    )
    if _is_postgres():
        op.execute(
            sa.text(
                "CREATE UNIQUE INDEX uq_dependency_checks_one_running "
                "ON dependency_checks (repo_id) WHERE status = 'running'"
            )
        )
        op.create_index(
            "ix_dependency_checks_status_started",
            "dependency_checks",
            ["status", "started_at"],
            unique=False,
        )
    else:
        op.execute(
            sa.text(
                "CREATE UNIQUE INDEX uq_dependency_checks_one_running "
                "ON dependency_checks (repo_id) WHERE status = 'running'"
            )
        )
        op.create_index(
            "ix_dependency_checks_status_started",
            "dependency_checks",
            ["status", "started_at"],
            unique=False,
        )
    op.create_table(
        "dashboard_notifications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(50), nullable=False),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=True),
        sa.Column(
            "report_id", sa.Integer(), sa.ForeignKey("dependency_reports.id"), nullable=True
        ),
        sa.Column(
            "check_id", sa.Integer(), sa.ForeignKey("dependency_checks.id"), nullable=True
        ),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_dashboard_notifications_kind", "dashboard_notifications", ["kind"], unique=False
    )
    op.create_index(
        "ix_dashboard_notifications_repo_id",
        "dashboard_notifications",
        ["repo_id"],
        unique=False,
    )
    op.create_index(
        "ix_dashboard_notifications_created_at",
        "dashboard_notifications",
        ["created_at"],
        unique=False,
    )
    op.create_table(
        "notification_reads",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "notification_id",
            sa.Integer(),
            sa.ForeignKey("dashboard_notifications.id"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "notification_id", "user_id", name="uq_notification_read_notif_user"
        ),
    )
    op.create_index(
        "ix_notification_reads_notification_id",
        "notification_reads",
        ["notification_id"],
        unique=False,
    )
    op.create_index(
        "ix_notification_reads_user_id", "notification_reads", ["user_id"], unique=False
    )


def downgrade() -> None:
    op.drop_table("notification_reads")
    op.drop_table("dashboard_notifications")
    if _is_postgres():
        # SQLite DROP TABLE ignores FK references; Postgres needs the
        # circular leg removed before either side can drop.
        op.drop_constraint(
            "fk_dependency_checks_report_id", "dependency_checks", type_="foreignkey"
        )
    op.drop_table("dependency_reports")
    op.drop_index("ix_dependency_checks_status_started", table_name="dependency_checks")
    op.execute(sa.text("DROP INDEX uq_dependency_checks_one_running"))
    op.drop_table("dependency_checks")
    op.drop_index("ix_dependencies_repo_status", table_name="dependencies")
    op.drop_table("dependencies")
    op.drop_index("ix_repos_dep_last_check_at", table_name="repos")
    op.drop_column("repos", "dep_last_check_at")
    op.drop_column("repos", "dep_schedule_hours")
    if _is_postgres():
        op.execute(sa.text("DROP TYPE dependency_status"))
