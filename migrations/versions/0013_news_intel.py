"""Standalone news intel: classification columns + finding provenance."""

import sqlalchemy as sa
from alembic import op

revision = "0013_news_intel"
down_revision = "0012_provider_connections"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("news_items", sa.Column("verdict", sa.String(20), nullable=True))
    op.add_column("news_items", sa.Column("category", sa.String(30), nullable=True))
    op.add_column(
        "news_items", sa.Column("classified_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("news_items", sa.Column("minted_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "findings",
        sa.Column("provenance", sa.String(20), nullable=False, server_default="scanner"),
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("findings") as batch:
            batch.drop_column("provenance")
        with op.batch_alter_table("news_items") as batch:
            batch.drop_column("minted_at")
            batch.drop_column("classified_at")
            batch.drop_column("category")
            batch.drop_column("verdict")
    else:
        op.drop_column("findings", "provenance")
        op.drop_column("news_items", "minted_at")
        op.drop_column("news_items", "classified_at")
        op.drop_column("news_items", "category")
        op.drop_column("news_items", "verdict")
