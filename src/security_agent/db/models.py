"""SQLAlchemy 2 models (Phase 0: accounts, invites, sessions, encrypted tokens)."""

import enum
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _stored(member: type[enum.Enum], name: str) -> Enum:
    """Native enum persisted by value, matching the alembic DDL labels.

    The default (persist member names) disagrees with the lowercase labels
    in migrations 0001-0003, which breaks every Postgres insert.
    """

    def _values(e: type[enum.Enum]) -> list[str]:
        return [str(m.value) for m in e]

    return Enum(member, name=name, values_callable=_values)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Role(enum.StrEnum):
    OWNER = "owner"
    MAINTAINER = "maintainer"
    DEVELOPER = "developer"
    REPORTER = "reporter"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str | None] = mapped_column(String(512), nullable=True)
    role: Mapped[Role] = mapped_column(_stored(Role, "role"), default=Role.REPORTER)
    disabled: Mapped[bool] = mapped_column(default=False)
    sso_provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sso_subject: Mapped[str | None] = mapped_column(String(320), nullable=True)
    totp_secret: Mapped[str | None] = mapped_column(Text, nullable=True)  # encrypted
    backup_code_hashes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Invite(Base):
    """Single-use invite; token stored as hash only, never re-viewable (FR-10 D1)."""

    __tablename__ = "invites"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    role: Mapped[Role] = mapped_column(_stored(Role, "role"))
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class PasswordReset(Base):
    """Single-use reset; token stored as hash only (FR-10 D2)."""

    __tablename__ = "password_resets"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Session(Base):
    """Server-side session: 24h absolute, 30min idle (FR-10 D4)."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class EncryptedToken(Base):
    """Provider token stored only as AES-256-GCM ciphertext; never re-viewed (NFR-4)."""

    __tablename__ = "encrypted_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    ciphertext: Mapped[str] = mapped_column(Text)


class GitProvider(enum.StrEnum):
    GITHUB = "github"
    GITLAB = "gitlab"


class ConnectionAuth(enum.StrEnum):
    OAUTH = "oauth"
    PAT = "pat"


class ProviderConnection(Base):
    """One user's GitHub/GitLab connection (PAT; `oauth` kept for legacy rows).

    Tokens never live here: access/refresh ciphertext sits in
    `encrypted_tokens` under `provider-conn:{id}:access|refresh`.
    `base_url` is the web root (https://github.com, a GHE/GitLab
    self-hosted root, …); the API root derives from it.
    """

    __tablename__ = "provider_connections"
    __table_args__ = (
        UniqueConstraint(
            "user_id", "provider", "base_url", "external_id", name="uq_conn_user_provider_account"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    provider: Mapped[GitProvider] = mapped_column(_stored(GitProvider, "git_provider"))
    base_url: Mapped[str] = mapped_column(String(2000))
    auth_type: Mapped[ConnectionAuth] = mapped_column(_stored(ConnectionAuth, "connection_auth"))
    external_id: Mapped[str] = mapped_column(String(200))
    username: Mapped[str] = mapped_column(String(320))
    scopes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class RepoKind(enum.StrEnum):
    GIT = "git"
    LOCAL = "local"


class RunStatus(enum.StrEnum):
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class RunTrigger(enum.StrEnum):
    CONNECT = "connect"
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    WEBHOOK = "webhook"


class FindingStatus(enum.StrEnum):
    OPEN = "open"
    PROPOSED = "proposed"
    RESOLVED = "resolved"
    CLOSED = "closed"
    UNPATCHABLE = "unpatchable"
    SILENT = "silent"


class FindingScope(enum.StrEnum):
    PROD = "prod"
    DEV = "dev"


class ProposalStatus(enum.StrEnum):
    OPEN = "open"
    MERGED = "merged"
    CLOSED = "closed"
    SUPERSEDED = "superseded"


class GateAction(enum.StrEnum):
    MERGE = "merge"
    ROTATION = "rotation"
    PUBLISH = "publish"


class GateStatus(enum.StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class SecretStatus(enum.StrEnum):
    OPEN = "open"
    PROPOSED = "proposed"
    AWAITING_ROTATION = "awaiting_rotation"
    CLOSED = "closed"
    INFORMATIONAL = "informational"


class Repo(Base):
    """Tracked repo: git URL or local path (FR-1 intake, FR-2 D2/D3)."""

    __tablename__ = "repos"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[RepoKind] = mapped_column(_stored(RepoKind, "repo_kind"))
    url: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    local_path: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    default_branch: Mapped[str | None] = mapped_column(String(200), nullable=True)
    connection_id: Mapped[int | None] = mapped_column(
        ForeignKey("provider_connections.id"), nullable=True, index=True
    )
    schedule_hours: Mapped[int] = mapped_column(default=6)
    last_scan_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class ScanRun(Base):
    """One per-repo scan in its own disposable sandbox (FR-2 D2)."""

    __tablename__ = "scan_runs"
    __table_args__ = (
        # Single-flight invariant: at most one in-flight run per repo,
        # enforced atomically so concurrent enqueues coalesce.
        Index(
            "uq_scan_runs_one_running",
            "repo_id",
            unique=True,
            sqlite_where=text("status = 'running'"),
            postgresql_where=text("status = 'running'"),
        ),
        # H6 #14: reap/claim scan RUNNING rows by age.
        Index("ix_scan_runs_status_started", "status", "started_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repos.id"), index=True)
    status: Mapped[RunStatus] = mapped_column(
        _stored(RunStatus, "run_status"), default=RunStatus.RUNNING
    )
    trigger: Mapped[RunTrigger] = mapped_column(_stored(RunTrigger, "run_trigger"))
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # H6: atomic claim/lease (#31) + cost park (NFR-8 D5). Parked runs stay
    # RUNNING (single-flight slot held) but are never claimed or reaped.
    claimed_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    parked: Mapped[bool] = mapped_column(default=False)
    park_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_usage: Mapped[int] = mapped_column(default=0)
    cost_warned: Mapped[bool] = mapped_column(default=False)


class Finding(Base):
    """One per (repo, package, canonical advisory); see FR-2 D4/D6."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("repo_id", "package", "advisory_id", name="uq_finding_repo_pkg_adv"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repos.id"), index=True)
    package: Mapped[str] = mapped_column(String(500), index=True)
    installed_version: Mapped[str] = mapped_column(String(100))
    advisory_id: Mapped[str] = mapped_column(String(100), index=True)
    ecosystem: Mapped[str | None] = mapped_column(String(50), nullable=True)
    aliases: Mapped[list | None] = mapped_column(JSON, nullable=True)
    severity_score: Mapped[float | None] = mapped_column(nullable=True)
    severity_source: Mapped[str | None] = mapped_column(String(50), nullable=True)
    kev_exploited: Mapped[bool] = mapped_column(default=False)
    dep_path: Mapped[list | None] = mapped_column(JSON, nullable=True)
    scope: Mapped[FindingScope] = mapped_column(
        _stored(FindingScope, "finding_scope"), default=FindingScope.PROD
    )
    fixed_versions: Mapped[list | None] = mapped_column(JSON, nullable=True)
    citations: Mapped[list | None] = mapped_column(JSON, nullable=True)
    status: Mapped[FindingStatus] = mapped_column(
        _stored(FindingStatus, "finding_status"), default=FindingStatus.OPEN
    )
    silent_reason: Mapped[str | None] = mapped_column(String(100), nullable=True)
    guidance: Mapped[str | None] = mapped_column(Text, nullable=True)
    issue_url: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    news_weight: Mapped[int] = mapped_column(default=0)
    news_url: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    first_run_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class Verdict(Base):
    """Reachability verdict per (finding, run); flips drive transitions (FR-3 D4)."""

    __tablename__ = "verdicts"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), index=True)
    reachable: Mapped[bool] = mapped_column()
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Proposal(Base):
    """Verified patch proposal: one PR per package, grouped when related (FR-5 D2)."""

    __tablename__ = "proposals"
    __table_args__ = (
        # One removal proposal per secret finding: concurrent runs
        # serialize here instead of double-proposing (NULLs unrestricted).
        Index("uq_proposals_secret_finding", "secret_finding_id", unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repos.id"), index=True)
    finding_ids: Mapped[list] = mapped_column(JSON)
    grouping_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    package_from: Mapped[str] = mapped_column(String(100))
    package_to: Mapped[str] = mapped_column(String(100))
    verification_result: Mapped[str] = mapped_column(Text)
    ignored_tests: Mapped[list | None] = mapped_column(JSON, nullable=True)
    pr_url: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    pr_state: Mapped[str | None] = mapped_column(String(50), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(300), nullable=True)
    base_branch: Mapped[str | None] = mapped_column(String(200), nullable=True)
    patch: Mapped[str | None] = mapped_column(Text, nullable=True)
    secret_finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("secret_findings.id"), nullable=True
    )
    status: Mapped[ProposalStatus] = mapped_column(
        _stored(ProposalStatus, "proposal_status"), default=ProposalStatus.OPEN
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Approval(Base):
    """Pre-execution gate for merge/rotation/publish (FR-9)."""

    __tablename__ = "approvals"
    __table_args__ = (
        # Idempotent gate requests: one pending gate per (repo, action, target).
        Index(
            "uq_approvals_one_pending",
            "repo_id",
            "action",
            "target",
            unique=True,
            sqlite_where=text("status = 'pending'"),
            postgresql_where=text("status = 'pending'"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repos.id"), index=True)
    proposal_id: Mapped[int | None] = mapped_column(ForeignKey("proposals.id"), nullable=True)
    action: Mapped[GateAction] = mapped_column(_stored(GateAction, "gate_action"))
    target: Mapped[str] = mapped_column(String(2000))
    status: Mapped[GateStatus] = mapped_column(
        _stored(GateStatus, "gate_status"), default=GateStatus.PENDING
    )
    request_run_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id"), nullable=True)
    decider_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    source: Mapped[str | None] = mapped_column(String(50), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    requeues: Mapped[int] = mapped_column(default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Delegation(Base):
    """Owner-to-Developer approval delegation: time-boxed, revocable (FR-9 D7)."""

    __tablename__ = "delegations"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    delegate_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    classes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class NewsItem(Base):
    """One Tier-2 signal: an HN story or feed entry (FR-6)."""

    __tablename__ = "news_items"
    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_news_source_external"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(20), index=True)
    external_id: Mapped[str] = mapped_column(String(500))
    url: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    title: Mapped[str] = mapped_column(String(1000))
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
    cve_ids: Mapped[list | None] = mapped_column(JSON, nullable=True)
    body_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)


class NewsBoost(Base):
    """One finding matched by one news item; weight feeds queue ordering."""

    __tablename__ = "news_boosts"
    __table_args__ = (UniqueConstraint("finding_id", "news_item_id", name="uq_boost_finding_item"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    news_item_id: Mapped[int] = mapped_column(ForeignKey("news_items.id"), index=True)
    weight: Mapped[int] = mapped_column()
    matched_on: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class NewsPoll(Base):
    """Poll log per source; the latest row gates the hourly cadence."""

    __tablename__ = "news_polls"

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(20), index=True)
    finished_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
    items: Mapped[int] = mapped_column(default=0)


class ScrapeThrottle(Base):
    """Cross-worker per-host scrape throttle claim (follow-up #8)."""

    __tablename__ = "scrape_throttles"

    host: Mapped[str] = mapped_column(String(500), primary_key=True)
    last_fetch_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class SecretFinding(Base):
    """One leaked secret per (repo, rule, path, fingerprint); see FR-8 D5/D7.

    Secret VALUES are never stored here — only the scanner's fingerprint
    plus location and liveness. Rotation proof arrives via mark-rotated
    (human) or a sticky dead validation verdict (re-validated dead).
    """

    __tablename__ = "secret_findings"
    __table_args__ = (
        UniqueConstraint(
            "repo_id", "rule_id", "path", "fingerprint", name="uq_secret_repo_rule_path_fp"
        ),
        Index("ix_secret_findings_repo_status", "repo_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repos.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(200))
    path: Mapped[str] = mapped_column(String(2000))
    start_line: Mapped[int | None] = mapped_column(nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(200))
    commit_sha: Mapped[str | None] = mapped_column(String(100), nullable=True)
    status: Mapped[SecretStatus] = mapped_column(
        _stored(SecretStatus, "secret_status"), default=SecretStatus.OPEN
    )
    liveness: Mapped[str] = mapped_column(String(20), default="unknown")
    dead_verdict: Mapped[bool] = mapped_column(default=False)
    from_history: Mapped[bool] = mapped_column(default=False)
    guidance: Mapped[str | None] = mapped_column(Text, nullable=True)
    proposal_id: Mapped[int | None] = mapped_column(ForeignKey("proposals.id"), nullable=True)
    rotated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_run_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class SecretBaseline(Base):
    """Per-repo secrets scan baseline: HEAD sha + rule-config hash (FR-8 D5/D6)."""

    __tablename__ = "secret_baselines"

    repo_id: Mapped[int] = mapped_column(ForeignKey("repos.id"), primary_key=True)
    baseline_sha: Mapped[str] = mapped_column(String(100))
    config_hash: Mapped[str | None] = mapped_column(String(200), nullable=True)
    baseline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class ChannelKind(enum.StrEnum):
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"


class NotifyChannel(Base):
    """One FR-13 delivery channel; secrets live encrypted, never in `config`.

    `config` holds non-secret fields only (SMTP host/port/user/from/to,
    Slack label, webhook display host). Credentials (SMTP password,
    webhook URLs) live in `encrypted_tokens` under `notify-channel:{id}`.
    """

    __tablename__ = "notify_channels"

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[ChannelKind] = mapped_column(_stored(ChannelKind, "channel_kind"))
    name: Mapped[str] = mapped_column(String(200))
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class NotifyRoute(Base):
    """Per-severity routing: which channels a severity fans out to (FR-13)."""

    __tablename__ = "notify_routes"
    __table_args__ = (UniqueConstraint("severity", "channel_id", name="uq_route_severity_channel"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    channel_id: Mapped[int] = mapped_column(ForeignKey("notify_channels.id"), index=True)


class NotifyState(Base):
    """Tiny KV for notification bookkeeping: digest cursor, spend-alert day."""

    __tablename__ = "notify_state"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class ModelUsage(Base):
    """Token ledger per (run, task); spend alerts aggregate this (NFR-8)."""

    __tablename__ = "model_usage"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_runs.id"), nullable=True, index=True
    )
    task: Mapped[str] = mapped_column(String(100))
    prompt_tokens: Mapped[int] = mapped_column(default=0)
    completion_tokens: Mapped[int] = mapped_column(default=0)
    total_tokens: Mapped[int] = mapped_column(default=0)
    cost_usd: Mapped[float] = mapped_column(default=0.0)
    estimated: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
