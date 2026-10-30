"""News hardening: retention indexes + cross-worker scrape throttle (#5/#8)."""

from alembic import op
import sqlalchemy as sa

revision = "0010_news_hardening"
down_revision = "0009_secret_indexes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_news_items_fetched_at", "news_items", ["fetched_at"])
    op.create_index("ix_news_polls_finished_at", "news_polls", ["finished_at"])
    op.create_table(
        "scrape_throttles",
        sa.Column("host", sa.String(length=500), primary_key=True),
        sa.Column("last_fetch_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("scrape_throttles")
    op.drop_index("ix_news_polls_finished_at", table_name="news_polls")
    op.drop_index("ix_news_items_fetched_at", table_name="news_items")
