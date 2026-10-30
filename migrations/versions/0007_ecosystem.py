"""H4: record finding ecosystem for multi-language routing (FR-7 D2)."""

import sqlalchemy as sa
from alembic import op

revision = "0007_ecosystem"
down_revision = "0006_news_summary"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("ecosystem", sa.String(50), nullable=True))


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("findings") as batch:
            batch.drop_column("ecosystem")
    else:
        op.drop_column("findings", "ecosystem")
