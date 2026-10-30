"""H5 hardening: secret-findings status index + one proposal per secret (FR-8)."""

from alembic import op

revision = "0009_secret_indexes"
down_revision = "0008_secrets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_secret_findings_repo_status", "secret_findings", ["repo_id", "status"])
    op.create_index("uq_proposals_secret_finding", "proposals", ["secret_finding_id"], unique=True)


def downgrade() -> None:
    op.drop_index("uq_proposals_secret_finding", table_name="proposals")
    op.drop_index("ix_secret_findings_repo_status", table_name="secret_findings")
