"""Phase-1 tables: repos, scan_runs, findings, verdicts, proposals, approvals."""

import sqlalchemy as sa
from alembic import op

revision = "0003_phase1"
down_revision = "0002_resets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repos",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("kind", sa.Enum("git", "local", name="repo_kind"), nullable=False),
        sa.Column("url", sa.String(2000), nullable=True),
        sa.Column("local_path", sa.String(2000), nullable=True),
        sa.Column("default_branch", sa.String(200), nullable=True),
        sa.Column("schedule_hours", sa.Integer(), nullable=False, server_default="6"),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "scan_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), index=True),
        sa.Column(
            "status",
            sa.Enum("running", "done", "failed", name="run_status"),
            nullable=False,
        ),
        sa.Column(
            "trigger",
            sa.Enum("connect", "manual", "scheduled", "webhook", name="run_trigger"),
            nullable=False,
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), index=True),
        sa.Column("package", sa.String(500), index=True, nullable=False),
        sa.Column("installed_version", sa.String(100), nullable=False),
        sa.Column("advisory_id", sa.String(100), index=True, nullable=False),
        sa.Column("aliases", sa.JSON(), nullable=True),
        sa.Column("severity_score", sa.Float(), nullable=True),
        sa.Column("severity_source", sa.String(50), nullable=True),
        sa.Column("kev_exploited", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("dep_path", sa.JSON(), nullable=True),
        sa.Column("scope", sa.Enum("prod", "dev", name="finding_scope"), nullable=False),
        sa.Column("fixed_versions", sa.JSON(), nullable=True),
        sa.Column("citations", sa.JSON(), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "open",
                "proposed",
                "resolved",
                "closed",
                "unpatchable",
                "silent",
                name="finding_status",
            ),
            nullable=False,
        ),
        sa.Column("silent_reason", sa.String(100), nullable=True),
        sa.Column("guidance", sa.Text(), nullable=True),
        sa.Column("issue_url", sa.String(2000), nullable=True),
        sa.Column("first_run_id", sa.Integer(), sa.ForeignKey("scan_runs.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("repo_id", "package", "advisory_id", name="uq_finding_repo_pkg_adv"),
    )
    op.create_table(
        "verdicts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), index=True),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("scan_runs.id"), index=True),
        sa.Column("reachable", sa.Boolean(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("reason_code", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "proposals",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), index=True),
        sa.Column("finding_ids", sa.JSON(), nullable=False),
        sa.Column("grouping_reason", sa.Text(), nullable=True),
        sa.Column("package_from", sa.String(100), nullable=False),
        sa.Column("package_to", sa.String(100), nullable=False),
        sa.Column("verification_result", sa.Text(), nullable=False),
        sa.Column("ignored_tests", sa.JSON(), nullable=True),
        sa.Column("pr_url", sa.String(2000), nullable=True),
        sa.Column("pr_state", sa.String(50), nullable=True),
        sa.Column("branch", sa.String(300), nullable=True),
        sa.Column("base_branch", sa.String(200), nullable=True),
        sa.Column("patch", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.Enum("open", "merged", "closed", "superseded", name="proposal_status"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "approvals",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), index=True),
        sa.Column("proposal_id", sa.Integer(), sa.ForeignKey("proposals.id")),
        sa.Column(
            "action",
            sa.Enum("merge", "rotation", "publish", name="gate_action"),
            nullable=False,
        ),
        sa.Column("target", sa.String(2000), nullable=False),
        sa.Column(
            "status",
            sa.Enum("pending", "approved", "denied", "expired", name="gate_status"),
            nullable=False,
        ),
        sa.Column("request_run_id", sa.Integer(), sa.ForeignKey("scan_runs.id")),
        sa.Column("decider_id", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("source", sa.String(50), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("requeues", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "delegations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), index=True),
        sa.Column("delegate_id", sa.Integer(), sa.ForeignKey("users.id"), index=True),
        sa.Column("classes", sa.JSON(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("delegations")
    op.drop_table("approvals")
    op.drop_table("proposals")
    op.drop_table("verdicts")
    op.drop_table("findings")
    op.drop_table("scan_runs")
    op.drop_table("repos")
    if op.get_bind().dialect.name != "postgresql":
        return
    for name in (
        "repo_kind",
        "run_status",
        "run_trigger",
        "finding_scope",
        "finding_status",
        "proposal_status",
        "gate_action",
        "gate_status",
    ):
        op.execute(f"DROP TYPE IF EXISTS {name}")
