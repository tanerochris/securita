"""H6: notifications + cost ledger tables, run claim/park columns, scheduler indexes."""

import sqlalchemy as sa
from alembic import op

revision = "0011_h6_notify_cost"
down_revision = "0010_news_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notify_channels",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "kind",
            sa.Enum("email", "slack", "webhook", name="channel_kind"),
            nullable=False,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "notify_routes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("severity", sa.String(20), nullable=False, index=True),
        sa.Column("channel_id", sa.Integer(), sa.ForeignKey("notify_channels.id"), index=True),
        sa.UniqueConstraint("severity", "channel_id", name="uq_route_severity_channel"),
    )
    op.create_table(
        "notify_state",
        sa.Column("key", sa.String(100), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "model_usage",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("scan_runs.id"), nullable=True, index=True),
        sa.Column("task", sa.String(100), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completion_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cost_usd", sa.Float(), nullable=False, server_default="0"),
        sa.Column("estimated", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
    )
    op.create_index("ix_scan_runs_status_started", "scan_runs", ["status", "started_at"])
    op.create_index("ix_repos_last_scan_at", "repos", ["last_scan_at"])
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("scan_runs") as batch:
            batch.add_column(sa.Column("claimed_by", sa.String(100), nullable=True))
            batch.add_column(sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True))
            batch.add_column(
                sa.Column("parked", sa.Boolean(), nullable=False, server_default="false")
            )
            batch.add_column(sa.Column("park_reason", sa.Text(), nullable=True))
            batch.add_column(
                sa.Column("token_usage", sa.Integer(), nullable=False, server_default="0")
            )
            batch.add_column(
                sa.Column("cost_warned", sa.Boolean(), nullable=False, server_default="false")
            )
    else:
        op.add_column("scan_runs", sa.Column("claimed_by", sa.String(100), nullable=True))
        op.add_column("scan_runs", sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True))
        op.add_column(
            "scan_runs",
            sa.Column("parked", sa.Boolean(), nullable=False, server_default="false"),
        )
        op.add_column("scan_runs", sa.Column("park_reason", sa.Text(), nullable=True))
        op.add_column(
            "scan_runs",
            sa.Column("token_usage", sa.Integer(), nullable=False, server_default="0"),
        )
        op.add_column(
            "scan_runs",
            sa.Column("cost_warned", sa.Boolean(), nullable=False, server_default="false"),
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("scan_runs") as batch:
            batch.drop_column("cost_warned")
            batch.drop_column("token_usage")
            batch.drop_column("park_reason")
            batch.drop_column("parked")
            batch.drop_column("claimed_at")
            batch.drop_column("claimed_by")
    else:
        op.drop_column("scan_runs", "cost_warned")
        op.drop_column("scan_runs", "token_usage")
        op.drop_column("scan_runs", "park_reason")
        op.drop_column("scan_runs", "parked")
        op.drop_column("scan_runs", "claimed_at")
        op.drop_column("scan_runs", "claimed_by")
    op.drop_index("ix_repos_last_scan_at", table_name="repos")
    op.drop_index("ix_scan_runs_status_started", table_name="scan_runs")
    op.drop_table("model_usage")
    op.drop_table("notify_state")
    op.drop_table("notify_routes")
    op.drop_table("notify_channels")
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TYPE IF EXISTS channel_kind")
