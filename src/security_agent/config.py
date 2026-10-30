"""Typed settings via pydantic-settings (env-driven, no secrets in code)."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = Field(default="dev", alias="APP_ENV")
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")  # noqa: S104 container bind
    app_port: int = Field(default=8000, alias="APP_PORT")
    database_url: str = Field(
        default="postgresql+psycopg://agent:agent@db:5432/agent",
        alias="DATABASE_URL",
    )
    master_key: str = Field(default="", alias="MASTER_KEY")
    model_base_url: str = Field(default="https://api.meta.ai/v1", alias="MODEL_BASE_URL")
    model_api_key: str = Field(default="", alias="MODEL_API_KEY")
    model_name: str = Field(default="muse-spark", alias="MODEL_NAME")
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
    secrets_config_path: str = Field(default="", alias="SECRETS_CONFIG_PATH")
    # Sandbox execution (follow-up #1): auto = docker in prod, host otherwise.
    sandbox_backend: str = Field(default="auto", alias="SANDBOX_BACKEND")
    sandbox_image: str = Field(default="security-agent-sandbox:latest", alias="SANDBOX_IMAGE")
    sandbox_work_root: str = Field(default="", alias="SANDBOX_WORK_ROOT")
    sandbox_network: str = Field(default="none", alias="SANDBOX_NETWORK")
    # Audit backend (follow-up #2): memory (dev/test) or loki.
    audit_backend: str = Field(default="memory", alias="AUDIT_BACKEND")
    loki_url: str = Field(default="http://loki:3100", alias="LOKI_URL")
    loki_tenant: str = Field(default="", alias="LOKI_TENANT")
    loki_timeout_seconds: float = Field(default=5.0, alias="LOKI_TIMEOUT_SECONDS")
    # Model-backed patch adaptation (follow-up #3); off until live probe passes.
    model_adapt_enabled: bool = Field(default=False, alias="MODEL_ADAPT_ENABLED")
    # H6 cost control (NFR-8 D4/D5): per-run token cap + daily spend alerts.
    run_token_cap: int = Field(default=1_000_000, alias="RUN_TOKEN_CAP")
    run_token_warn_fraction: float = Field(default=0.8, alias="RUN_TOKEN_WARN_FRACTION")
    spend_warn_daily_usd: float = Field(default=25.0, alias="SPEND_WARN_DAILY_USD")
    spend_critical_daily_usd: float = Field(default=100.0, alias="SPEND_CRITICAL_DAILY_USD")
    model_price_per_mtok_usd: float = Field(default=2.0, alias="MODEL_PRICE_PER_MTOK_USD")
    # H6 recovery (NFR-9 D1/D2): backup dir + key-ceremony file target.
    backup_dir: str = Field(default="./backups", alias="BACKUP_DIR")
    backup_retention_count: int = Field(default=14, alias="BACKUP_RETENTION_COUNT")
    master_key_file: str = Field(default="./master.key", alias="MASTER_KEY_FILE")

    @property
    def is_prod(self) -> bool:
        return self.app_env.lower() in {"prod", "production"}


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
