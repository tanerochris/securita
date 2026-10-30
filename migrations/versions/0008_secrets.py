"""H5: secrets loop tables + proposal link (FR-8 D5/D7)."""

import sqlalchemy as sa
from alembic import op

revision = "0008_secrets"
down_revision = "0007_ecosystem"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "secret_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), index=True),
        sa.Column("rule_id", sa.String(200), nullable=False),
        sa.Column("path", sa.String(2000), nullable=False),
        sa.Column("start_line", sa.Integer(), nullable=True),
        sa.Column("fingerprint", sa.String(200), nullable=False),
        sa.Column("commit_sha", sa.String(100), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "open",
                "proposed",
                "awaiting_rotation",
                "closed",
                "informational",
                name="secret_status",
            ),
            nullable=False,
        ),
        sa.Column("liveness", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("dead_verdict", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("from_history", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("guidance", sa.Text(), nullable=True),
        sa.Column("proposal_id", sa.Integer(), sa.ForeignKey("proposals.id"), nullable=True),
        sa.Column("rotated_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_run_id", sa.Integer(), sa.ForeignKey("scan_runs.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "repo_id", "rule_id", "path", "fingerprint", name="uq_secret_repo_rule_path_fp"
        ),
    )
    op.create_table(
        "secret_baselines",
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), primary_key=True),
        sa.Column("baseline_sha", sa.String(100), nullable=False),
        sa.Column("config_hash", sa.String(200), nullable=True),
        sa.Column("baseline_at", sa.DateTime(timezone=True), nullable=False),
    )
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("proposals") as batch:
            batch.add_column(sa.Column("secret_finding_id", sa.Integer(), nullable=True))
    else:
        op.add_column(
            "proposals",
            sa.Column(
                "secret_finding_id",
                sa.Integer(),
                sa.ForeignKey("secret_findings.id"),
                nullable=True,
            ),
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("proposals") as batch:
            batch.drop_column("secret_finding_id")
    else:
        op.drop_column("proposals", "secret_finding_id")
    op.drop_table("secret_baselines")
    op.drop_table("secret_findings")
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TYPE IF EXISTS secret_status")
