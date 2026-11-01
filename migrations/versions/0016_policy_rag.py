"""Policy RAG: pgvector extension + policy tables + policy gate action.

Forward: CREATE EXTENSION vector, add the 'policy' gate_action label, new
tables (documents, chunks, rules, run snapshots), and the two additive
columns (both nullable/defaulted, so existing rows are untouched).
Postgres-only statements are dialect-guarded: the SQLite migration smoke
test builds the same tables without the extension, the enum label, or
the HNSW index.

Rollback: drops the tables, index, and columns. The extension and the
'policy' enum label stay (Postgres has no DROP VALUE; both are harmless
and re-upgrade is idempotent). Policy data itself does not survive a
downgrade — re-upload after re-upgrade.
"""

import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector

revision = "0016_policy_rag"
down_revision = "0015_news_relevance"
branch_labels = None
depends_on = None

EMBEDDING_DIM = 1536


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    if _is_postgres():
        op.execute(sa.text("CREATE EXTENSION IF NOT EXISTS vector"))
        labels = [
            row[0]
            for row in op.get_bind().execute(
                sa.text(
                    "SELECT enumlabel FROM pg_enum "
                    "JOIN pg_type ON pg_enum.enumtypid = pg_type.oid "
                    "WHERE pg_type.typname = 'gate_action'"
                )
            )
        ]
        if "policy" not in labels:
            # ADD VALUE cannot run inside a transaction block.
            with op.get_context().autocommit_block():
                op.execute(sa.text("ALTER TYPE gate_action ADD VALUE 'policy'"))
    op.create_table(
        "policy_documents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("doc_key", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("scope", sa.String(20), nullable=False),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=True),
        sa.Column("tasks", sa.JSON(), nullable=True),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column("file_name", sa.String(300), nullable=True),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="ready"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("doc_key", "version", name="uq_policy_doc_key_version"),
    )
    op.create_index("ix_policy_documents_doc_key", "policy_documents", ["doc_key"])
    op.create_index("ix_policy_docs_current", "policy_documents", ["doc_key", "is_current"])
    op.create_index("ix_policy_docs_scope", "policy_documents", ["scope", "repo_id"])
    op.create_table(
        "policy_chunks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "document_id",
            sa.Integer(),
            sa.ForeignKey("policy_documents.id"),
            nullable=False,
        ),
        sa.Column("chunk_index", sa.Integer(), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("source_ref", sa.String(300), nullable=True),
        sa.Column("embedding", Vector(EMBEDDING_DIM), nullable=True),
    )
    op.create_index("ix_policy_chunks_document_id", "policy_chunks", ["document_id"])
    if _is_postgres():
        op.execute(
            sa.text(
                "CREATE INDEX IF NOT EXISTS ix_policy_chunks_embedding "
                "ON policy_chunks USING hnsw (embedding vector_cosine_ops)"
            )
        )
    op.create_table(
        "policy_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rule_key", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("scope", sa.String(20), nullable=False),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=True),
        sa.Column("tasks", sa.JSON(), nullable=True),
        sa.Column("effect", sa.String(20), nullable=False),
        sa.Column("match", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "source_document_id",
            sa.Integer(),
            sa.ForeignKey("policy_documents.id"),
            nullable=True,
        ),
        sa.Column("source_quote", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("overridable", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("override_of", sa.String(64), nullable=True),
        sa.Column("confirmed_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("rule_key", "version", name="uq_policy_rule_key_version"),
    )
    op.create_index("ix_policy_rules_rule_key", "policy_rules", ["rule_key"])
    op.create_index("ix_policy_rules_current", "policy_rules", ["rule_key", "is_current"])
    op.create_index("ix_policy_rules_scope", "policy_rules", ["scope", "repo_id"])
    op.create_table(
        "policy_run_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("doc_key", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "doc_key", name="uq_policy_snap_run_doc"),
    )
    op.create_index("ix_policy_run_snapshots_run_id", "policy_run_snapshots", ["run_id"])
    op.add_column(
        "repos",
        sa.Column("readme_policy_enabled", sa.Boolean(), nullable=True, server_default=sa.true()),
    )
    op.add_column("findings", sa.Column("policy_block", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "policy_block")
    op.drop_column("repos", "readme_policy_enabled")
    op.drop_index("ix_policy_run_snapshots_run_id", table_name="policy_run_snapshots")
    op.drop_table("policy_run_snapshots")
    op.drop_index("ix_policy_rules_scope", table_name="policy_rules")
    op.drop_index("ix_policy_rules_current", table_name="policy_rules")
    op.drop_index("ix_policy_rules_rule_key", table_name="policy_rules")
    op.drop_table("policy_rules")
    if _is_postgres():
        op.execute(sa.text("DROP INDEX IF EXISTS ix_policy_chunks_embedding"))
    op.drop_index("ix_policy_chunks_document_id", table_name="policy_chunks")
    op.drop_table("policy_chunks")
    op.drop_index("ix_policy_docs_scope", table_name="policy_documents")
    op.drop_index("ix_policy_docs_current", table_name="policy_documents")
    op.drop_index("ix_policy_documents_doc_key", table_name="policy_documents")
    op.drop_table("policy_documents")
    # The vector extension and the 'policy' enum label stay behind by
    # design (see module docstring); re-upgrade stays idempotent.
