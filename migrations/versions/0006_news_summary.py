"""H3 hardening: store feed summaries for title/summary matching."""

import sqlalchemy as sa
from alembic import op

revision = "0006_news_summary"
down_revision = "0005_news"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("news_items", sa.Column("summary", sa.Text(), nullable=True))


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("news_items") as batch:
            batch.drop_column("summary")
    else:
        op.drop_column("news_items", "summary")
