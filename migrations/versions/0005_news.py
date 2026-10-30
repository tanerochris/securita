"""H3 slice A: news tables + finding boost fields."""

import sqlalchemy as sa
from alembic import op

revision = "0005_news"
down_revision = "0004_constraints"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "news_items",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source", sa.String(20), nullable=False, index=True),
        sa.Column("external_id", sa.String(500), nullable=False),
        sa.Column("url", sa.String(2000), nullable=True),
        sa.Column("title", sa.String(1000), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cve_ids", sa.JSON(), nullable=True),
        sa.Column("body_excerpt", sa.Text(), nullable=True),
        sa.UniqueConstraint("source", "external_id", name="uq_news_source_external"),
    )
    op.create_table(
        "news_boosts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), index=True),
        sa.Column("news_item_id", sa.Integer(), sa.ForeignKey("news_items.id"), index=True),
        sa.Column("weight", sa.Integer(), nullable=False),
        sa.Column("matched_on", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("finding_id", "news_item_id", name="uq_boost_finding_item"),
    )
    op.create_table(
        "news_polls",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source", sa.String(20), nullable=False, index=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("items", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column("findings", sa.Column("news_weight", sa.Integer(), server_default="0"))
    op.add_column("findings", sa.Column("news_url", sa.String(2000), nullable=True))


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("findings") as batch:
            batch.drop_column("news_url")
            batch.drop_column("news_weight")
    else:
        op.drop_column("findings", "news_url")
        op.drop_column("findings", "news_weight")
    op.drop_table("news_polls")
    op.drop_table("news_boosts")
    op.drop_table("news_items")
