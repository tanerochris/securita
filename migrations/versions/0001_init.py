"""Initial schema: users, invites, sessions, encrypted_tokens."""

import sqlalchemy as sa
from alembic import op

revision = "0001_init"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(320), unique=True, index=True, nullable=False),
        sa.Column("password_hash", sa.String(512), nullable=True),
        sa.Column(
            "role",
            sa.Enum("owner", "maintainer", "developer", "reporter", name="role"),
            nullable=False,
        ),
        sa.Column("disabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("sso_provider", sa.String(32), nullable=True),
        sa.Column("sso_subject", sa.String(320), nullable=True),
        sa.Column("totp_secret", sa.Text(), nullable=True),
        sa.Column("backup_code_hashes", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "invites",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(320), index=True, nullable=False),
        sa.Column(
            "role",
            sa.Enum("owner", "maintainer", "developer", "reporter", name="role"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(128), unique=True, index=True, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("session_id", sa.String(128), unique=True, index=True, nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), index=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "encrypted_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner", sa.String(200), index=True, nullable=False),
        sa.Column("ciphertext", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("encrypted_tokens")
    op.drop_table("sessions")
    op.drop_table("invites")
    op.drop_table("users")
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TYPE IF EXISTS role")
