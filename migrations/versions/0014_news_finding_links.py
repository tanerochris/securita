"""Repo-tagged news: news_finding_links join (mint/link provenance)."""

import sqlalchemy as sa
from alembic import op

revision = "0014_news_finding_links"
down_revision = "0013_news_intel"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "news_finding_links",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("news_item_id", sa.Integer(), sa.ForeignKey("news_items.id"), nullable=False),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("kind", sa.String(10), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("news_item_id", "finding_id", name="uq_news_link_item_finding"),
    )
    op.create_index("ix_news_finding_links_item", "news_finding_links", ["news_item_id"])
    op.create_index("ix_news_finding_links_finding", "news_finding_links", ["finding_id"])


def downgrade() -> None:
    op.drop_index("ix_news_finding_links_finding", table_name="news_finding_links")
    op.drop_index("ix_news_finding_links_item", table_name="news_finding_links")
    op.drop_table("news_finding_links")
