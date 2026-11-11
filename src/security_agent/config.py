"""Typed settings via pydantic-settings (env-driven, no secrets in code)."""

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

#: Zero-config local database (also the `.env.example` default). A blank
#: `DATABASE_URL` behaves as unset (this default), not as "".
SQLITE_DEFAULT_URL = "sqlite:///./agent.db"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = Field(default="dev", alias="APP_ENV")
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")  # noqa: S104 container bind
    app_port: int = Field(default=8000, alias="APP_PORT")
    # SQLite by default: a stock local checkout boots with zero
    # config. Docker Compose keeps Postgres via .env (DATABASE_URL
    # there overrides this); local Postgres just needs the URL set.
    database_url: str = Field(
        default=SQLITE_DEFAULT_URL,
        alias="DATABASE_URL",
    )

    @field_validator("database_url", mode="before")
    @classmethod
    def _blank_database_url_means_default(cls, value):
        if value is None or (isinstance(value, str) and not value.strip()):
            return SQLITE_DEFAULT_URL
        return value

    master_key: str = Field(default="", alias="MASTER_KEY")
    # Brain provider: configured in Settings → Brain (Owner-managed org
    # keys), never env. Legacy MODEL_* env imports once on upgrade, then
    # is ignored (see control/brain_settings.maybe_migrate_env).
    # Chat agent daily spend cap in USD (install-wide, Owner/Maintainer
    # adjustable from Settings; 0 disables the cap).
    chat_spend_cap_daily_usd: float = Field(default=5.0, alias="CHAT_SPEND_CAP_DAILY_USD")
    # Git provider connect (PAT-only, self-hosted): default hosts offered
    # in the connect form; users can override per connection for
    # GitHub Enterprise / self-hosted GitLab. No OAuth app to register.
    github_base_url: str = Field(default="https://github.com", alias="GITHUB_BASE_URL")
    gitlab_base_url: str = Field(default="https://gitlab.com", alias="GITLAB_BASE_URL")
    google_client_id: str = Field(default="", alias="GOOGLE_CLIENT_ID")
    google_client_secret: str = Field(default="", alias="GOOGLE_CLIENT_SECRET")
    microsoft_client_id: str = Field(default="", alias="MICROSOFT_CLIENT_ID")
    microsoft_client_secret: str = Field(default="", alias="MICROSOFT_CLIENT_SECRET")
    public_url: str = Field(default="http://localhost:8000", alias="PUBLIC_URL")
    bot_name: str = Field(default="security-agent-bot", alias="BOT_NAME")
    bot_email: str = Field(default="security-agent@localhost", alias="BOT_EMAIL")
    bot_signing_key: str = Field(default="", alias="BOT_SIGNING_KEY")
    news_hn_query: str = Field(default="CVE", alias="NEWS_HN_QUERY")
    news_rss_feeds: str = Field(default="", alias="NEWS_RSS_FEEDS")
    news_poll_hours: float = Field(default=1.0, alias="NEWS_POLL_HOURS")
    news_hn_max_pages: int = Field(default=5, alias="NEWS_HN_MAX_PAGES")
    news_classify_enabled: bool = Field(default=True, alias="NEWS_CLASSIFY_ENABLED")
    news_classify_max_items: int = Field(default=20, alias="NEWS_CLASSIFY_MAX_ITEMS")
    news_mint_enabled: bool = Field(default=True, alias="NEWS_MINT_ENABLED")
    news_relevance_enabled: bool = Field(default=True, alias="NEWS_RELEVANCE_ENABLED")
    news_relevance_max_pairs: int = Field(default=50, alias="NEWS_RELEVANCE_MAX_PAIRS")
    secrets_config_path: str = Field(default="", alias="SECRETS_CONFIG_PATH")
    # Sandbox execution (follow-up #1): auto = docker in prod, else
    # docker when the CLI and image are usable, host otherwise.
    sandbox_backend: str = Field(default="auto", alias="SANDBOX_BACKEND")
    sandbox_image: str = Field(default="security-agent-sandbox:latest", alias="SANDBOX_IMAGE")
    sandbox_work_root: str = Field(default="", alias="SANDBOX_WORK_ROOT")
    # Daemon-side name of the volume mounted at SANDBOX_WORK_ROOT (compose
    # pins it via `name:` so it is not project-prefixed). Sibling sandbox
    # containers share workdirs through this volume, never host bind paths.
    sandbox_work_volume: str = Field(default="sandbox-work", alias="SANDBOX_WORK_VOLUME")
    sandbox_network: str = Field(default="none", alias="SANDBOX_NETWORK")
    # Audit backend (follow-up #2): memory (dev/test) or loki.
    audit_backend: str = Field(default="memory", alias="AUDIT_BACKEND")
    loki_url: str = Field(default="http://loki:3100", alias="LOKI_URL")
    loki_tenant: str = Field(default="", alias="LOKI_TENANT")
    loki_timeout_seconds: float = Field(default=5.0, alias="LOKI_TIMEOUT_SECONDS")
    # Model-backed patch adaptation (follow-up #3); off until live probe passes.
    model_adapt_enabled: bool = Field(default=False, alias="MODEL_ADAPT_ENABLED")
    # Model-written PR titles/bodies (FR-5); the deterministic template
    # stays as the fallback when disabled, keyless, or on any model miss.
    pr_text_model_enabled: bool = Field(default=True, alias="PR_TEXT_MODEL_ENABLED")
    # Model-written dependency impact summaries (D6); the deterministic
    # evidence template stays as the fallback when disabled, keyless, or
    # on any model miss. Budgeted separately from the security pipeline.
    deps_report_model_enabled: bool = Field(default=True, alias="DEPS_REPORT_MODEL_ENABLED")
    # Policy RAG (D4): the operator picks the embeddings provider.
    # "local" (default) runs a small ONNX model in-process via fastembed
    # — no extra service. "ollama" talks to an Ollama server's
    # OpenAI-compatible /v1/embeddings (compose profile "ollama").
    # "hosted" is any OpenAI-compatible API (set EMBEDDING_BASE_URL +
    # EMBEDDING_API_KEY; the brain provider is separate). "off" is
    # keyword retrieval only. Vectors are optional: chunks without
    # embeddings still serve, never a hard failure.
    embedding_provider: str = Field(default="local", alias="EMBEDDING_PROVIDER")
    embedding_base_url: str = Field(default="", alias="EMBEDDING_BASE_URL")
    embedding_api_key: str = Field(default="", alias="EMBEDDING_API_KEY")
    embedding_model: str = Field(default="", alias="EMBEDDING_MODEL")
    embedding_local_cache_dir: str = Field(default="", alias="EMBEDDING_LOCAL_CACHE_DIR")
    embedding_dim: int = Field(default=1536, alias="EMBEDDING_DIM")
    embedding_timeout_seconds: float = Field(default=30.0, alias="EMBEDDING_TIMEOUT_SECONDS")
    # Policy ingestion/retrieval budgets.
    policy_chunk_chars: int = Field(default=2000, alias="POLICY_CHUNK_CHARS")
    policy_chunk_overlap_chars: int = Field(default=200, alias="POLICY_CHUNK_OVERLAP_CHARS")
    policy_top_k: int = Field(default=6, alias="POLICY_TOP_K")
    policy_prompt_budget_chars: int = Field(default=8000, alias="POLICY_PROMPT_BUDGET_CHARS")
    policy_upload_max_bytes: int = Field(default=1_000_000, alias="POLICY_UPLOAD_MAX_BYTES")
    policy_max_chunks_per_doc: int = Field(default=200, alias="POLICY_MAX_CHUNKS_PER_DOC")
    policy_readme_max_bytes: int = Field(default=200_000, alias="POLICY_README_MAX_BYTES")
    # H6 cost control (NFR-8 D4/D5): per-run spend cap + daily spend alerts.
    # RUN_SPEND_CAP_USD is the cap; legacy RUN_TOKEN_CAP (tokens) still
    # converts at the default model price when the USD var is unset.
    run_token_cap: int = Field(default=1_000_000, alias="RUN_TOKEN_CAP")
    run_spend_cap_usd: float | None = Field(default=None, alias="RUN_SPEND_CAP_USD")
    run_spend_warn_fraction: float = Field(
        default=0.8,
        validation_alias=AliasChoices("RUN_SPEND_WARN_FRACTION", "RUN_TOKEN_WARN_FRACTION"),
    )
    spend_warn_daily_usd: float = Field(default=25.0, alias="SPEND_WARN_DAILY_USD")
    spend_critical_daily_usd: float = Field(default=100.0, alias="SPEND_CRITICAL_DAILY_USD")
    # Per-model ledger pricing lives in Settings → Brain (cached gateway
    # prices, native table, operator override). No env price remains.
    # Overall AI budget: monthly spend cap in USD across every ledgered
    # model call (security pipeline, dependencies, embeddings, probe).
    # Alert-only: warn at 80%, exceeded at 100%, once per level per
    # month; pipelines keep running. Owners/Maintainers can raise it
    # from the settings page (NotifyState cost.spend_cap_monthly wins).
    spend_cap_monthly_usd: float = Field(default=500.0, alias="SPEND_CAP_MONTHLY_USD")
    # Worker role: "all" schedules and executes (dev/single-process),
    # "orchestrator" only ticks/enqueues, "executor" only claims/runs.
    # Deploy exactly one orchestrator; scale executors freely.
    worker_role: str = Field(default="all", alias="WORKER_ROLE")
    # H6 recovery (NFR-9 D1/D2): backup dir + key-ceremony file target.
    backup_dir: str = Field(default="./backups", alias="BACKUP_DIR")
    backup_retention_count: int = Field(default=14, alias="BACKUP_RETENTION_COUNT")
    master_key_file: str = Field(default="./master.key", alias="MASTER_KEY_FILE")

    @property
    def run_cap_default_usd(self) -> float:
        """Default per-run cap in USD (0 disables the cap).

        RUN_SPEND_CAP_USD wins when set; otherwise the legacy
        RUN_TOKEN_CAP converts at the default model price, so
        pre-USD installs keep their tuned limit. The config layer
        stays DB-free, so this uses the same $2/MTok fallback the
        ledger uses when no model price resolves (see
        brain.providers.DEFAULT_PRICE_PER_MTOK_USD).
        """
        if self.run_spend_cap_usd is not None:
            return max(0.0, self.run_spend_cap_usd)
        return max(0, self.run_token_cap) * 2.0 / 1_000_000

    @property
    def is_prod(self) -> bool:
        return self.app_env.lower() in {"prod", "production"}


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
