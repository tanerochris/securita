"""Localized news: per-repo relevance assessments (news_repo_relevance)."""

import sqlalchemy as sa
from alembic import op

revision = "0015_news_relevance"
down_revision = "0014_news_finding_links"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "news_repo_relevance",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("news_item_id", sa.Integer(), sa.ForeignKey("news_items.id"), nullable=False),
        sa.Column("repo_id", sa.Integer(), sa.ForeignKey("repos.id"), nullable=False),
        sa.Column("relevance", sa.String(20), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("matched_signals", sa.JSON(), nullable=True),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("news_item_id", "repo_id", name="uq_news_relevance_item_repo"),
    )
    op.create_index("ix_news_repo_relevance_item", "news_repo_relevance", ["news_item_id"])
    op.create_index("ix_news_repo_relevance_repo", "news_repo_relevance", ["repo_id"])
    op.create_index("ix_news_repo_relevance_level", "news_repo_relevance", ["relevance"])


def downgrade() -> None:
    op.drop_index("ix_news_repo_relevance_level", table_name="news_repo_relevance")
    op.drop_index("ix_news_repo_relevance_repo", table_name="news_repo_relevance")
    op.drop_index("ix_news_repo_relevance_item", table_name="news_repo_relevance")
    op.drop_table("news_repo_relevance")
