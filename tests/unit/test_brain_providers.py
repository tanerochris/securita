"""Brain provider strategies: registry, factory, pricing, settings, migration."""

from datetime import UTC, datetime
from unittest import mock

import pytest
from sqlalchemy import delete

from security_agent.app import accounts as accounts_svc
from security_agent.brain import BrainError, BrainNotConfigured, get_chat_model, tracked_invoke
from security_agent.brain.providers import (
    DEFAULT_PRICE_PER_MTOK_USD,
    NATIVE_PRICES,
    STRATEGIES,
    STRATEGY_ORDER,
    build_chat_model,
    strategy_label,
)
from security_agent.control.brain_settings import (
    brain_status,
    current_model_price,
    delete_brain_key,
    get_brain_config,
    get_brain_key,
    has_brain_key,
    list_models,
    maybe_migrate_env,
    price_per_token_usd,
    save_brain_config,
)
from security_agent.db.models import EncryptedToken, NotifyState, Role
from security_agent.db.session import session_scope


@pytest.fixture(autouse=True)
def _clean_brain_state():
    """Brain selection/keys never leak across tests (shared test DB)."""
    _wipe()
    yield
    _wipe()


def _wipe():
    with session_scope() as db:
        db.execute(delete(NotifyState).where(NotifyState.key.like("brain.%")))
        db.execute(delete(EncryptedToken).where(EncryptedToken.owner.like("brain:%")))


def _owner():
    email = f"brain-owner-{datetime.now(UTC).timestamp()}@example.com"
    return accounts_svc.create_user(email, None, Role.OWNER)


def _dev():
    email = f"brain-dev-{datetime.now(UTC).timestamp()}@example.com"
    return accounts_svc.create_user(email, None, Role.DEVELOPER)


# --- Registry ---


def test_registry_has_six_launch_entries_in_ui_order():
    assert set(STRATEGIES) == {"openrouter", "vercel", "ollama", "custom", "google", "anthropic"}
    assert tuple(STRATEGY_ORDER) == (
        "openrouter",
        "vercel",
        "ollama",
        "custom",
        "google",
        "anthropic",
    )
    for key in STRATEGY_ORDER:
        assert STRATEGIES[key].key == key
        assert STRATEGIES[key].label
        assert STRATEGIES[key].blurb
        assert STRATEGIES[key].kind in ("openai", "anthropic")


def test_only_anthropic_needs_its_own_client():
    kinds = {k: v.kind for k, v in STRATEGIES.items()}
    assert kinds["anthropic"] == "anthropic"
    assert all(v == "openai" for k, v in kinds.items() if k != "anthropic")


def test_key_needs_match_plan():
    assert STRATEGIES["openrouter"].needs_key is True
    assert STRATEGIES["vercel"].needs_key is True
    assert STRATEGIES["ollama"].needs_key is False
    assert STRATEGIES["custom"].needs_key is False
    assert STRATEGIES["google"].needs_key is True
    assert STRATEGIES["anthropic"].needs_key is True


def test_strategy_label_falls_back():
    assert strategy_label("openrouter") == "OpenRouter"
    assert strategy_label("nope") == "nope"
    assert strategy_label("") == "unconfigured"


# --- build_chat_model (pure: no DB, no network) ---


def test_build_openai_shaped_strategies():
    from langchain_openai import ChatOpenAI

    cases = {
        "openrouter": "https://openrouter.ai/api/v1",
        "vercel": "https://ai-gateway.vercel.sh/v1",
        "ollama": "http://localhost:11434/v1",
        "google": "https://generativelanguage.googleapis.com/v1beta/openai/",
    }
    for strategy, base in cases.items():
        model = build_chat_model(strategy, model="m1", api_key="k")
        assert isinstance(model, ChatOpenAI)
        assert model.model_name == "m1"
        assert str(model.openai_api_base) == base or base in str(model.openai_api_base)


def test_build_custom_uses_given_base_and_optional_key():
    from langchain_openai import ChatOpenAI

    model = build_chat_model("custom", model="local", base_url="http://x:8080/v1")
    assert isinstance(model, ChatOpenAI)
    assert "x:8080" in str(model.openai_api_base)
    model = build_chat_model("custom", model="local", api_key="k", base_url="http://x:8080/v1")
    assert isinstance(model, ChatOpenAI)


def test_build_ollama_needs_no_key():
    from langchain_openai import ChatOpenAI

    assert isinstance(build_chat_model("ollama", model="llama3"), ChatOpenAI)


def test_build_anthropic_sets_max_tokens_and_omits_sampling():
    from langchain_anthropic import ChatAnthropic

    from security_agent.brain.providers import ANTHROPIC_MAX_TOKENS

    model = build_chat_model("anthropic", model="claude-sonnet-4-5", api_key="k")
    assert isinstance(model, ChatAnthropic)
    assert model.max_tokens == ANTHROPIC_MAX_TOKENS
    assert model.temperature is None


def test_build_errors_are_brain_errors():
    with pytest.raises(BrainError, match="Unknown brain strategy"):
        build_chat_model("watson", model="m")
    with pytest.raises(BrainNotConfigured, match="model is empty"):
        build_chat_model("openrouter", model="  ", api_key="k")
    with pytest.raises(BrainNotConfigured, match="needs an API key"):
        build_chat_model("openrouter", model="m")
    with pytest.raises(BrainNotConfigured, match="needs an API key"):
        build_chat_model("anthropic", model="m")
    with pytest.raises(BrainNotConfigured, match="needs a base URL"):
        build_chat_model("custom", model="m")


# --- Factory ---


def test_factory_unconfigured_raises_loud():
    with pytest.raises(BrainNotConfigured, match="Settings → Brain"):
        get_chat_model()


def test_factory_builds_saved_strategy():
    from langchain_openai import ChatOpenAI

    save_brain_config(strategy="openrouter", model="x/y", api_key="k", user=_owner())
    model = get_chat_model()
    assert isinstance(model, ChatOpenAI)
    assert model.model_name == "x/y"


def test_factory_builds_anthropic_from_settings():
    from langchain_anthropic import ChatAnthropic

    save_brain_config(strategy="anthropic", model="claude-haiku-4-5", api_key="k", user=_owner())
    model = get_chat_model()
    assert isinstance(model, ChatAnthropic)


def test_factory_missing_key_raises_loud():
    save_brain_config(strategy="google", model="gemini-2.5-flash", user=_owner())
    assert not has_brain_key("google")
    with pytest.raises(BrainNotConfigured, match="needs an API key"):
        get_chat_model()


def test_factory_unknown_strategy_saved_as_is_fails_loud():
    save_brain_config(strategy="watson", model="m", user=_owner())
    assert get_brain_config()["strategy"] == "watson"
    with pytest.raises(BrainError, match="Unknown brain strategy"):
        get_chat_model()


# --- tracked_invoke ---


class _Boom:
    def invoke(self, prompt):
        raise RuntimeError("provider down")


def test_tracked_invoke_wraps_provider_failures():
    save_brain_config(strategy="openrouter", model="x/y", api_key="k", user=_owner())
    with pytest.raises(BrainError, match="openrouter/x/y"):
        tracked_invoke(_Boom(), "hi", task="probe")


# --- Settings persistence ---


def test_save_round_trip_and_owner_only():
    owner = _owner()
    cfg = save_brain_config(
        strategy="vercel",
        model="vercel/v1",
        base_url="",
        price_override="1.5",
        api_key="sk-1",
        user=owner,
    )
    assert cfg["configured"] is True
    assert cfg["price_override"] == 1.5
    assert cfg["has_key"] is True
    assert "sk-1" not in str(cfg)
    assert get_brain_key("vercel") == "sk-1"
    with pytest.raises(PermissionError):
        save_brain_config(strategy="vercel", model="m", user=_dev())
    with pytest.raises(PermissionError):
        delete_brain_key("vercel", _dev())


def test_key_never_re_viewed_and_rotates():
    owner = _owner()
    save_brain_config(strategy="google", model="gemini-2.5-flash", api_key="k1", user=owner)
    assert get_brain_key("google") == "k1"
    save_brain_config(strategy="google", model="gemini-2.5-flash", api_key="k2", user=owner)
    assert get_brain_key("google") == "k2"
    save_brain_config(strategy="google", model="gemini-2.5-flash", user=owner)
    assert get_brain_key("google") == "k2"  # blank keeps the stored key
    assert delete_brain_key("google", owner) is True
    assert get_brain_key("google") is None
    assert delete_brain_key("google", owner) is False


def test_status_never_leaks_keys():
    save_brain_config(strategy="openrouter", model="x/y", api_key="super-secret", user=_owner())
    blob = str(brain_status())
    assert "super-secret" not in blob
    assert brain_status()["has_key"] is True


# --- Pricing ---


def test_native_table_price_and_version():
    from security_agent.brain.providers import NATIVE_PRICE_TABLE_VERSION

    assert NATIVE_PRICE_TABLE_VERSION >= 1
    save_brain_config(strategy="anthropic", model="claude-sonnet-4-5", api_key="k", user=_owner())
    assert current_model_price() == NATIVE_PRICES["claude-sonnet-4-5"]


def test_cached_gateway_price_wins_then_override_then_zero():
    owner = _owner()
    with mock.patch(
        "security_agent.control.brain_settings.fetch_openrouter_models",
        return_value=[{"id": "x/y", "price": 3.0}],
    ):
        assert list_models("openrouter")["source"] == "live"
    save_brain_config(strategy="openrouter", model="x/y", price_override="1.0", user=owner)
    assert current_model_price() == 3.0  # cache beats override
    save_brain_config(strategy="custom", model="anything", base_url="http://x/v1", user=owner)
    assert current_model_price() == 0.0  # custom/ollama default $0
    save_brain_config(
        strategy="custom",
        model="anything",
        base_url="http://x/v1",
        price_override="1.25",
        user=owner,
    )
    assert current_model_price() == 1.25  # override applies when nothing else prices
    save_brain_config(strategy="ollama", model="llama3", user=owner)
    assert current_model_price() == 0.0


def test_native_price_beats_override_per_plan_order():
    save_brain_config(
        strategy="anthropic",
        model="claude-haiku-4-5",
        api_key="k",
        price_override="0.01",
        user=_owner(),
    )
    assert current_model_price() == NATIVE_PRICES["claude-haiku-4-5"]


def test_unconfigured_price_falls_back_to_default():
    assert current_model_price() is None
    assert price_per_token_usd() == pytest.approx(DEFAULT_PRICE_PER_MTOK_USD / 1_000_000)


def test_ledger_uses_resolved_model_price():
    from security_agent.control.cost import record_usage

    owner = _owner()
    save_brain_config(strategy="custom", model="m", base_url="http://x/v1", user=owner)
    assert record_usage(None, "brain-price-zero", 100, 50)["cost_usd"] == 0.0
    save_brain_config(strategy="anthropic", model="claude-haiku-4-5", api_key="k", user=owner)
    out = record_usage(None, "brain-price-native", 1_000_000, 0)
    assert out["cost_usd"] == pytest.approx(NATIVE_PRICES["claude-haiku-4-5"])


# --- Model lists ---


def test_curated_natives_need_no_network():
    google = list_models("google")
    assert google["source"] == "curated"
    assert [m["id"] for m in google["models"]]
    assert all(m["price"] for m in google["models"])
    anthropic = list_models("anthropic")
    assert anthropic["source"] == "curated"
    assert [m["id"] for m in anthropic["models"]]


def test_gateway_failure_falls_back_to_cache_then_free_text():
    with mock.patch(
        "security_agent.control.brain_settings.fetch_openrouter_models",
        side_effect=BrainError("down"),
    ):
        assert list_models("openrouter")["source"] == "none"
    with mock.patch(
        "security_agent.control.brain_settings.fetch_openrouter_models",
        return_value=[{"id": "x/y", "price": 3.0}],
    ):
        assert list_models("openrouter")["source"] == "live"
    with mock.patch(
        "security_agent.control.brain_settings.fetch_openrouter_models",
        side_effect=BrainError("down"),
    ):
        cached = list_models("openrouter")
        assert cached["source"] == "cache"
        assert [m["id"] for m in cached["models"]] == ["x/y"]
        assert cached["fetched_at"]
    assert list_models("custom")["source"] == "none"
    assert list_models("custom")["models"] == []
    assert list_models("nope")["source"] == "none"


def test_list_models_no_refresh_never_touches_network():
    with mock.patch(
        "security_agent.control.brain_settings.fetch_openrouter_models",
        return_value=[{"id": "x/y", "price": 3.0}],
    ) as fetch:
        assert list_models("openrouter")["source"] == "live"
        assert fetch.call_count == 1
        cached = list_models("openrouter", refresh=False)
        assert cached["source"] == "cache"
        assert [m["id"] for m in cached["models"]] == ["x/y"]
        assert fetch.call_count == 1  # render path: cache only
    assert list_models("google", refresh=False)["source"] == "curated"
    assert list_models("openrouter", refresh=False)["source"] == "cache"


def test_ollama_tags_list_and_failure_shape():
    payload = {"models": [{"name": "llama3:latest"}, {"name": "nomic-embed-text"}]}
    resp = mock.Mock()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    with mock.patch("httpx.get", return_value=resp) as get:
        models = list_models("ollama", base_url="http://o:11434/v1")
        assert models["source"] == "live"
        assert [m["id"] for m in models["models"]] == ["llama3:latest", "nomic-embed-text"]
        assert get.call_args.args[0] == "http://o:11434/api/tags"
    with mock.patch("httpx.get", side_effect=RuntimeError("refused")):
        assert list_models("ollama", base_url="http://o:11434/v1")["source"] == "cache"


# --- One-time env migration ---


def _clear_marker():
    with session_scope() as db:
        db.execute(delete(NotifyState).where(NotifyState.key == "brain.migrated"))


def _clear_env(monkeypatch):
    for var in (
        "MODEL_BASE_URL",
        "MODEL_API_KEY",
        "MODEL_NAME",
        "MODEL_CHAT_NAME",
        "MODEL_PRICE_PER_MTOK_USD",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize(
    ("base", "strategy"),
    [
        ("https://openrouter.ai/api/v1", "openrouter"),
        ("https://ai-gateway.vercel.sh/v1", "vercel"),
        ("http://localhost:11434/v1", "ollama"),
        ("https://generativelanguage.googleapis.com/v1beta/openai/", "google"),
        ("https://api.anthropic.com", "anthropic"),
        ("https://api.meta.ai/v1", "custom"),
        ("", "custom"),
    ],
)
def test_migrate_env_strategy_guess(monkeypatch, base, strategy):
    _clear_env(monkeypatch)
    _clear_marker()
    monkeypatch.setenv("MODEL_API_KEY", "legacy-key")
    monkeypatch.setenv("MODEL_NAME", "legacy-model")
    if base:
        monkeypatch.setenv("MODEL_BASE_URL", base)
    out = maybe_migrate_env()
    assert out == {"migrated": True, "strategy": strategy, "model": "legacy-model", "notes": []}
    cfg = get_brain_config()
    assert (cfg["strategy"], cfg["model"]) == (strategy, "legacy-model")
    assert get_brain_key(strategy) == "legacy-key"
    if strategy in ("custom", "ollama"):
        assert cfg["base_url"]


def test_migrate_env_imports_price_override_and_notes_chat_slot(monkeypatch):
    _clear_env(monkeypatch)
    _clear_marker()
    monkeypatch.setenv("MODEL_API_KEY", "k")
    monkeypatch.setenv("MODEL_NAME", "m")
    monkeypatch.setenv("MODEL_PRICE_PER_MTOK_USD", "4.5")
    monkeypatch.setenv("MODEL_CHAT_NAME", "chat-m")
    out = maybe_migrate_env()
    assert out["migrated"] is True
    assert get_brain_config()["price_override"] == 4.5
    assert any("MODEL_CHAT_NAME" in note for note in out["notes"])


def test_migrate_env_runs_once_then_env_ignored(monkeypatch):
    _clear_env(monkeypatch)
    _clear_marker()
    assert maybe_migrate_env() == {"migrated": False, "notes": []}
    monkeypatch.setenv("MODEL_API_KEY", "late-key")
    monkeypatch.setenv("MODEL_NAME", "late-model")
    assert maybe_migrate_env() == {"migrated": False}
    assert get_brain_config()["configured"] is False


# --- Probe ---


class _ProbeStub:
    """bind_tools/invoke stub with a canned native tool call."""

    def __init__(self, calls):
        self._calls = calls

    def bind_tools(self, tools):
        assert tools
        return self

    def invoke(self, prompt):
        return mock.Mock(content="done", tool_calls=self._calls, usage_metadata={})


def test_probe_pass_and_fail_through_factory():
    from security_agent.brain.probe import run_probe

    save_brain_config(strategy="ollama", model="llama3", user=_owner())
    with mock.patch(
        "security_agent.brain.get_chat_model",
        return_value=_ProbeStub([{"name": "probe_echo", "args": {}, "id": "1"}]),
    ):
        assert run_probe() is True
    with mock.patch("security_agent.brain.get_chat_model", return_value=_ProbeStub([])):
        assert run_probe() is False


def test_probe_unconfigured_raises_loud():
    from security_agent.brain.probe import run_probe

    with pytest.raises(BrainNotConfigured):
        run_probe()


def test_probe_cli_reports_brain_failure(capsys):
    from security_agent.brain.probe import main

    with pytest.raises(SystemExit) as code:
        main()
    assert code.value.code == 1
    assert capsys.readouterr().out.startswith("PROBE_FAIL")


# --- Brain park + resume ---


def _repo_and_run():
    from sqlalchemy import select

    from security_agent.control import repos as repo_svc
    from security_agent.db.models import RepoKind, ScanRun

    repo = repo_svc.connect_repo(
        f"brain-r-{datetime.now(UTC).timestamp()}", RepoKind.GIT, url="https://example.com/b.git"
    )
    with session_scope() as db:  # connect enqueues the run; reuse it (single-flight)
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        run_id = run.id
        db.expunge(run)
    return repo.id, run_id


def test_brain_park_and_resume_without_raise():
    from security_agent.control.cost import list_parked_runs, park_run_for_brain, resume_run
    from security_agent.db.models import RunStatus, ScanRun

    _repo_id, run_id = _repo_and_run()
    try:
        assert park_run_for_brain(run_id, "Brain is not configured.") is True
        assert park_run_for_brain(run_id, "again") is False
        parked = [r for r in list_parked_runs() if r["id"] == run_id]
        assert len(parked) == 1
        assert "brain" in parked[0]["reason"].lower()
        out = resume_run(run_id, _owner())
        assert out["run_id"] == run_id
    finally:
        with session_scope() as db:
            run = db.get(ScanRun, run_id)
            run.parked = False
            run.status = RunStatus.DONE


def _settle_inflight():
    """Settle rows other tests left in-flight; this pass is ours."""
    from sqlalchemy import select

    from security_agent.db.models import RunStatus, ScanRun

    with session_scope() as db:
        rows = list(
            db.scalars(
                select(ScanRun)
                .where(ScanRun.status.in_([RunStatus.QUEUED, RunStatus.RUNNING]))
                .where(ScanRun.parked.is_(False))
            )
        )
        for row in rows:
            row.status = RunStatus.DONE


def test_execute_once_parks_on_brain_error():
    import security_agent.worker.main as worker_main
    from security_agent.db.models import RunStatus, ScanRun

    _settle_inflight()
    _repo_id, run_id = _repo_and_run()

    def _invoke(state):
        if state.get("run_id") == run_id:
            raise BrainError("Brain is not configured.")
        return {}

    graph = mock.Mock()
    graph.invoke.side_effect = _invoke
    with (
        mock.patch("security_agent.worker.build_graph", return_value=graph),
        mock.patch(
            "security_agent.worker.deps_check.drain_dep_checks",
            return_value={"executed": 0, "failed": 0},
        ),
        mock.patch(
            "security_agent.worker.deps_check.drain_dep_patches",
            return_value={"proposal_ids": [], "errors": []},
        ),
    ):
        summary = worker_main.execute_once()
    assert summary["parked"] >= 1
    with session_scope() as db:
        run = db.get(ScanRun, run_id)
        assert run.parked is True
        assert "brain" in (run.park_reason or "").lower()
        run.parked = False  # settle: leave no parked rows behind
        run.status = RunStatus.DONE


# --- Fail-loud callers ---


def test_pr_text_propagates_brain_error_past_template():
    from security_agent.brain.pr_text import generate_pr_text

    with (
        mock.patch(
            "security_agent.config.get_settings",
            return_value=mock.Mock(pr_text_model_enabled=True),
        ),
        mock.patch("security_agent.brain.tracked_invoke", side_effect=BrainError("no brain")),
    ):
        with pytest.raises(BrainError):
            generate_pr_text("p", "1", "2", ["CVE-1"], [], ["v"], "g", [], "d")


def test_deliver_reraises_brain_error_past_template():
    from security_agent.worker.deliver import _render_pr_text

    with mock.patch(
        "security_agent.brain.pr_text.generate_pr_text", side_effect=BrainError("no brain")
    ):
        with pytest.raises(BrainError):
            _render_pr_text("p", "1", "2", ["A"], [], ["v"], "g", [], "d")


def test_deps_summary_converts_brain_error_to_report_error():
    from security_agent.worker.deps_report import ReportError, generate_summary

    with (
        mock.patch(
            "security_agent.config.get_settings",
            return_value=mock.Mock(deps_report_model_enabled=True),
        ),
        mock.patch("security_agent.brain.get_chat_model", side_effect=BrainError("no brain")),
    ):
        with pytest.raises(ReportError, match="brain unavailable"):
            generate_summary([{"key": "k"}])


def test_news_classification_surfaces_brain_error_and_stops():
    from security_agent.db.models import NewsItem
    from security_agent.worker import news_intel

    tag = f"brain-{datetime.now(UTC).timestamp()}"
    with session_scope() as db:
        db.add(
            NewsItem(
                source="test", external_id=tag, title="t", summary="s", body_excerpt="excerpt"
            )  # skip enrichment: no network
        )
        db.flush()
    try:
        with mock.patch("security_agent.brain.get_chat_model", side_effect=BrainError("no brain")):
            with pytest.raises(BrainError):
                news_intel.classify_item(_latest_news_id())
            counts = news_intel.classify_pending(limit=5)
            assert counts == {"classified": 0, "major": 0}
    finally:
        with session_scope() as db:
            db.execute(delete(NewsItem).where(NewsItem.external_id == tag))


def _latest_news_id():
    from sqlalchemy import select

    from security_agent.db.models import NewsItem

    with session_scope() as db:
        return db.scalar(select(NewsItem.id).order_by(NewsItem.id.desc()).limit(1))


def test_chat_turn_surfaces_configure_brain_notice():
    from security_agent.chat import get_conversation
    from security_agent.chat.agent import answer_turn

    owner = _owner()
    conv = get_conversation(owner.id)
    reply = answer_turn(owner, conv, "hi")
    assert "Settings → Brain" in reply.content
