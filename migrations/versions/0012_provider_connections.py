"""Hybrid git-provider connect: provider_connections + repos.connection_id."""

import sqlalchemy as sa
from alembic import op

revision = "0012_provider_connections"
down_revision = "0011_h6_notify_cost"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "provider_connections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False, index=True),
        sa.Column(
            "provider",
            sa.Enum("github", "gitlab", name="git_provider"),
            nullable=False,
        ),
        sa.Column("base_url", sa.String(2000), nullable=False),
        sa.Column(
            "auth_type",
            sa.Enum("oauth", "pat", name="connection_auth"),
            nullable=False,
        ),
        sa.Column("external_id", sa.String(200), nullable=False),
        sa.Column("username", sa.String(320), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=True),
        sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "user_id", "provider", "base_url", "external_id", name="uq_conn_user_provider_account"
        ),
    )
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("repos") as batch:
            batch.add_column(
                sa.Column(
                    "connection_id",
                    sa.Integer(),
                    sa.ForeignKey("provider_connections.id", name="fk_repos_connection_id"),
                    nullable=True,
                )
            )
        op.create_index("ix_repos_connection_id", "repos", ["connection_id"])
    else:
        op.add_column(
            "repos",
            sa.Column(
                "connection_id",
                sa.Integer(),
                sa.ForeignKey("provider_connections.id"),
                nullable=True,
                index=True,
            ),
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        op.drop_index("ix_repos_connection_id", table_name="repos")
        with op.batch_alter_table("repos") as batch:
            batch.drop_column("connection_id")
    else:
        op.drop_column("repos", "connection_id")
    op.drop_table("provider_connections")
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TYPE IF EXISTS git_provider")
        op.execute("DROP TYPE IF EXISTS connection_auth")
