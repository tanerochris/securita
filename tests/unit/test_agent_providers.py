"""Agent provider strategies: registry, factory, pricing, settings, migration."""

from datetime import UTC, datetime
from unittest import mock

import pytest
from sqlalchemy import delete, select

from security_agent.agent import AgentError, AgentNotConfigured, get_chat_model, tracked_invoke
from security_agent.agent.providers import (
    DEFAULT_PRICE_PER_MTOK_USD,
    NATIVE_PRICES,
    STRATEGIES,
    STRATEGY_ORDER,
    build_chat_model,
    strategy_label,
)
from security_agent.app import accounts as accounts_svc
from security_agent.control.agent_settings import (
    agent_status,
    current_model_price,
    delete_agent_key,
    get_agent_config,
    get_agent_key,
    has_agent_key,
    key_hint,
    list_models,
    maybe_migrate_legacy_brain_keys,
    price_per_token_usd,
    save_agent_config,
)
from security_agent.db.models import EncryptedToken, NotifyState, Role
from security_agent.db.session import session_scope


@pytest.fixture(autouse=True)
def _clean_agent_state():
    """Agent selection/keys never leak across tests (shared test DB)."""
    _wipe()
    yield
    _wipe()


def _wipe():
    with session_scope() as db:
        db.execute(delete(NotifyState).where(NotifyState.key.like("agent.%")))
        db.execute(delete(EncryptedToken).where(EncryptedToken.owner.like("agent:%")))
        db.execute(delete(NotifyState).where(NotifyState.key.like("brain.%")))
        db.execute(delete(EncryptedToken).where(EncryptedToken.owner.like("brain:%")))


def _owner():
    email = f"agent-owner-{datetime.now(UTC).timestamp()}@example.com"
    return accounts_svc.create_user(email, None, Role.OWNER)


def _dev():
    email = f"agent-dev-{datetime.now(UTC).timestamp()}@example.com"
    return accounts_svc.create_user(email, None, Role.DEVELOPER)


# --- Registry ---


def test_registry_has_seven_launch_entries_in_ui_order():
    assert set(STRATEGIES) == {
        "openrouter",
        "vercel",
        "ollama",
        "custom",
        "google",
        "anthropic",
        "deepseek",
    }
    assert tuple(STRATEGY_ORDER) == (
        "openrouter",
        "vercel",
        "ollama",
        "custom",
        "google",
        "anthropic",
        "deepseek",
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


def test_base_url_modes_match_plan():
    modes = {k: v.base_url_mode for k, v in STRATEGIES.items()}
    assert modes == {
        "openrouter": "fixed",
        "vercel": "fixed",
        "ollama": "optional",
        "custom": "required",
        "google": "fixed",
        "anthropic": "unused",
        "deepseek": "fixed",
    }


def test_save_clears_base_url_for_fixed_strategies():
    owner = _owner()
    save_agent_config(strategy="custom", model="m", base_url="http://x/v1", user=owner)
    assert get_agent_config()["base_url"] == "http://x/v1"
    save_agent_config(strategy="openrouter", model="x/y", base_url="http://x/v1", user=owner)
    assert get_agent_config()["base_url"] == ""
    save_agent_config(strategy="anthropic", model="c", base_url="http://x/v1", user=owner)
    assert get_agent_config()["base_url"] == ""


def test_save_keeps_base_url_for_custom_and_ollama():
    owner = _owner()
    save_agent_config(strategy="ollama", model="llama3", base_url="http://o:11434/v1", user=owner)
    assert get_agent_config()["base_url"] == "http://o:11434/v1"


def test_key_hint_shows_first12_and_last4():
    assert key_hint("sk-or-v1-83eabcdefghijklmnd776") == "sk-or-v1-83e••••••••d776"
    assert key_hint("short") == "••••••••"
    assert key_hint("") == "••••••••"


def test_save_stores_hint_and_delete_clears_it():
    owner = _owner()
    save_agent_config(
        strategy="openrouter", model="x/y", api_key="sk-or-v1-83eabcdefghijklmnd776", user=owner
    )
    assert get_agent_config()["key_hint"] == "sk-or-v1-83e••••••••d776"
    assert delete_agent_key("openrouter", owner) is True
    assert get_agent_config()["key_hint"] == ""
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
        "deepseek": "https://api.deepseek.com/v1",
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

    from security_agent.agent.providers import ANTHROPIC_MAX_TOKENS

    model = build_chat_model("anthropic", model="claude-sonnet-4-5", api_key="k")
    assert isinstance(model, ChatAnthropic)
    assert model.max_tokens == ANTHROPIC_MAX_TOKENS
    assert model.temperature is None


def test_build_errors_are_agent_errors():
    with pytest.raises(AgentError, match="Unknown agent strategy"):
        build_chat_model("watson", model="m")
    with pytest.raises(AgentNotConfigured, match="model is empty"):
        build_chat_model("openrouter", model="  ", api_key="k")
    with pytest.raises(AgentNotConfigured, match="needs an API key"):
        build_chat_model("openrouter", model="m")
    with pytest.raises(AgentNotConfigured, match="needs an API key"):
        build_chat_model("anthropic", model="m")
    with pytest.raises(AgentNotConfigured, match="needs a base URL"):
        build_chat_model("custom", model="m")


# --- Factory ---


def test_factory_unconfigured_raises_loud():
    with pytest.raises(AgentNotConfigured, match="Settings → Agent"):
        get_chat_model()


def test_factory_builds_saved_strategy():
    from langchain_openai import ChatOpenAI

    save_agent_config(strategy="openrouter", model="x/y", api_key="k", user=_owner())
    model = get_chat_model()
    assert isinstance(model, ChatOpenAI)
    assert model.model_name == "x/y"


def test_factory_builds_anthropic_from_settings():
    from langchain_anthropic import ChatAnthropic

    save_agent_config(strategy="anthropic", model="claude-haiku-4-5", api_key="k", user=_owner())
    model = get_chat_model()
    assert isinstance(model, ChatAnthropic)


def test_factory_missing_key_raises_loud():
    save_agent_config(strategy="google", model="gemini-2.5-flash", user=_owner())
    assert not has_agent_key("google")
    with pytest.raises(AgentNotConfigured, match="needs an API key"):
        get_chat_model()


def test_factory_unknown_strategy_saved_as_is_fails_loud():
    save_agent_config(strategy="watson", model="m", user=_owner())
    assert get_agent_config()["strategy"] == "watson"
    with pytest.raises(AgentError, match="Unknown agent strategy"):
        get_chat_model()


# --- tracked_invoke ---


class _Boom:
    def invoke(self, prompt):
        raise RuntimeError("provider down")


def test_tracked_invoke_wraps_provider_failures():
    save_agent_config(strategy="openrouter", model="x/y", api_key="k", user=_owner())
    with pytest.raises(AgentError, match="openrouter/x/y"):
        tracked_invoke(_Boom(), "hi", task="probe")


# --- Settings persistence ---


def test_save_round_trip_and_owner_only():
    owner = _owner()
    cfg = save_agent_config(
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
    assert get_agent_key("vercel") == "sk-1"
    with pytest.raises(PermissionError):
        save_agent_config(strategy="vercel", model="m", user=_dev())
    with pytest.raises(PermissionError):
        delete_agent_key("vercel", _dev())


def test_key_never_re_viewed_and_rotates():
    owner = _owner()
    save_agent_config(strategy="google", model="gemini-2.5-flash", api_key="k1", user=owner)
    assert get_agent_key("google") == "k1"
    save_agent_config(strategy="google", model="gemini-2.5-flash", api_key="k2", user=owner)
    assert get_agent_key("google") == "k2"
    save_agent_config(strategy="google", model="gemini-2.5-flash", user=owner)
    assert get_agent_key("google") == "k2"  # blank keeps the stored key
    assert delete_agent_key("google", owner) is True
    assert get_agent_key("google") is None
    assert delete_agent_key("google", owner) is False


def test_status_never_leaks_keys():
    save_agent_config(strategy="openrouter", model="x/y", api_key="super-secret", user=_owner())
    blob = str(agent_status())
    assert "super-secret" not in blob
    assert agent_status()["has_key"] is True


# --- Pricing ---


def test_native_table_price_and_version():
    from security_agent.agent.providers import NATIVE_PRICE_TABLE_VERSION

    assert NATIVE_PRICE_TABLE_VERSION >= 1
    save_agent_config(strategy="anthropic", model="claude-sonnet-4-5", api_key="k", user=_owner())
    assert current_model_price() == NATIVE_PRICES["claude-sonnet-4-5"]


def test_cached_gateway_price_wins_then_override_then_zero():
    owner = _owner()
    with mock.patch(
        "security_agent.control.agent_settings.fetch_openrouter_models",
        return_value=[{"id": "x/y", "price": 3.0}],
    ):
        assert list_models("openrouter")["source"] == "live"
    save_agent_config(strategy="openrouter", model="x/y", price_override="1.0", user=owner)
    assert current_model_price() == 3.0  # cache beats override
    save_agent_config(strategy="custom", model="anything", base_url="http://x/v1", user=owner)
    assert current_model_price() == 0.0  # custom/ollama default $0
    save_agent_config(
        strategy="custom",
        model="anything",
        base_url="http://x/v1",
        price_override="1.25",
        user=owner,
    )
    assert current_model_price() == 1.25  # override applies when nothing else prices
    save_agent_config(strategy="ollama", model="llama3", user=owner)
    assert current_model_price() == 0.0


def test_native_price_beats_override_per_plan_order():
    save_agent_config(
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
    save_agent_config(strategy="custom", model="m", base_url="http://x/v1", user=owner)
    assert record_usage(None, "agent-price-zero", 100, 50)["cost_usd"] == 0.0
    save_agent_config(strategy="anthropic", model="claude-haiku-4-5", api_key="k", user=owner)
    out = record_usage(None, "agent-price-native", 1_000_000, 0)
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
    deepseek = list_models("deepseek")
    assert deepseek["source"] == "curated"
    assert [m["id"] for m in deepseek["models"]] == ["deepseek-chat", "deepseek-reasoner"]
    assert all(m["price"] for m in deepseek["models"])


def test_gateway_failure_falls_back_to_cache_then_free_text():
    with mock.patch(
        "security_agent.control.agent_settings.fetch_openrouter_models",
        side_effect=AgentError("down"),
    ):
        assert list_models("openrouter")["source"] == "none"
    with mock.patch(
        "security_agent.control.agent_settings.fetch_openrouter_models",
        return_value=[{"id": "x/y", "price": 3.0}],
    ):
        assert list_models("openrouter")["source"] == "live"
    with mock.patch(
        "security_agent.control.agent_settings.fetch_openrouter_models",
        side_effect=AgentError("down"),
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
        "security_agent.control.agent_settings.fetch_openrouter_models",
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


def _anthropic_page(rows, *, has_more=False, last_id=""):
    resp = mock.Mock()
    resp.json.return_value = {"data": rows, "has_more": has_more, "last_id": last_id}
    resp.raise_for_status.return_value = None
    return resp


def test_anthropic_live_lists_active_only_with_table_prices():
    from security_agent.agent.providers import fetch_anthropic_models

    page1 = _anthropic_page(
        [
            {"id": "claude-sonnet-4-5", "lifecycle": "active"},
            {"id": "claude-old", "lifecycle": "deprecated"},
            {"id": "broken"},
        ],
        has_more=True,
        last_id="broken",
    )
    page2 = _anthropic_page([{"id": "claude-new-9", "lifecycle": "active"}])
    with mock.patch("httpx.get", side_effect=[page1, page2]) as get:
        models = fetch_anthropic_models("k")
    assert [m["id"] for m in models] == ["claude-sonnet-4-5", "broken", "claude-new-9"]
    assert models[0]["price"] == NATIVE_PRICES["claude-sonnet-4-5"]
    assert models[2]["price"] is None
    assert get.call_count == 2
    _, kwargs = get.call_args_list[0]
    assert kwargs["headers"]["anthropic-version"]
    assert kwargs["headers"]["Authorization"] == "Bearer k"
    assert get.call_args_list[1][1]["params"]["after_id"] == "broken"


def test_anthropic_live_needs_key_and_falls_back_to_curated():
    from security_agent.agent.providers import fetch_anthropic_models

    with pytest.raises(AgentError, match="No API key"):
        fetch_anthropic_models("")
    assert list_models("anthropic")["source"] == "curated"  # no key: no network


def test_anthropic_refresh_prefers_live_then_cache_then_curated():
    save_agent_config(strategy="anthropic", model="m", api_key="k", user=_owner())
    live = [{"id": "claude-live-1", "price": None}]
    with mock.patch(
        "security_agent.control.agent_settings.fetch_anthropic_models",
        return_value=live,
    ) as fetch:
        assert list_models("anthropic")["source"] == "live"
        assert fetch.call_count == 1
        args, _ = fetch.call_args
        assert args == ("k",)  # stored key, server-side only
    with mock.patch(
        "security_agent.control.agent_settings.fetch_anthropic_models",
        side_effect=AgentError("down"),
    ):
        cached = list_models("anthropic")
        assert cached["source"] == "cache"
        assert [m["id"] for m in cached["models"]] == ["claude-live-1"]


def test_anthropic_failure_without_cache_falls_back_to_curated():
    save_agent_config(strategy="anthropic", model="m", api_key="k", user=_owner())
    with mock.patch(
        "security_agent.control.agent_settings.fetch_anthropic_models",
        side_effect=AgentError("down"),
    ):
        out = list_models("anthropic")
        assert out["source"] == "curated"
        assert [m["id"] for m in out["models"]]


# --- One-time legacy rename migration ---


def test_legacy_rename_carries_config_but_clears_model_and_base_url():
    from security_agent.crypto import encrypt_field
    from security_agent.db.keys import get_encryption_key

    with session_scope() as db:
        db.add(NotifyState(key="brain.strategy", value="custom"))
        db.add(NotifyState(key="brain.model", value="old-model"))
        db.add(NotifyState(key="brain.base_url", value="https://old.example/v1"))
        db.add(NotifyState(key="brain.price_override_usd", value="3.5"))
        db.add(NotifyState(key="brain.cache.custom", value='{"models": []}'))
        db.add(
            EncryptedToken(
                owner="brain:custom",
                ciphertext=encrypt_field("k", get_encryption_key()),
            )
        )
    out = maybe_migrate_legacy_brain_keys()
    assert out["migrated"] is True
    assert "agent.strategy" in out["carried"]
    assert "agent:custom" in out["carried"]
    cfg = get_agent_config()
    assert cfg["strategy"] == "custom"
    assert cfg["model"] == "" and cfg["base_url"] == ""  # cleared, form starts blank
    assert cfg["price_override"] == 3.5
    assert get_agent_key("custom") == "k"
    with session_scope() as db:  # legacy rows kept for rollback
        assert db.get(NotifyState, "brain.model").value == "old-model"
        assert (
            db.scalar(select(EncryptedToken).where(EncryptedToken.owner == "brain:custom"))
            is not None
        )
    assert maybe_migrate_legacy_brain_keys() == {"migrated": False}


def test_legacy_rename_never_overwrites_agent_keys():
    with session_scope() as db:
        db.add(NotifyState(key="brain.strategy", value="custom"))
        db.add(NotifyState(key="agent.strategy", value="anthropic"))
    out = maybe_migrate_legacy_brain_keys()
    assert out["migrated"] is True
    assert "agent.strategy" not in out["carried"]
    assert get_agent_config()["strategy"] == "anthropic"


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
    from security_agent.agent.probe import run_probe

    save_agent_config(strategy="ollama", model="llama3", user=_owner())
    with mock.patch(
        "security_agent.agent.get_chat_model",
        return_value=_ProbeStub([{"name": "probe_echo", "args": {}, "id": "1"}]),
    ):
        assert run_probe() is True
    with mock.patch("security_agent.agent.get_chat_model", return_value=_ProbeStub([])):
        assert run_probe() is False


def test_probe_unconfigured_raises_loud():
    from security_agent.agent.probe import run_probe

    with pytest.raises(AgentNotConfigured):
        run_probe()


def test_probe_cli_reports_agent_failure(capsys):
    from security_agent.agent.probe import main

    with pytest.raises(SystemExit) as code:
        main()
    assert code.value.code == 1
    assert capsys.readouterr().out.startswith("PROBE_FAIL")


# --- Agent park + resume ---


def _repo_and_run():
    from sqlalchemy import select

    from security_agent.control import repos as repo_svc
    from security_agent.db.models import RepoKind, ScanRun

    repo = repo_svc.connect_repo(
        f"agent-r-{datetime.now(UTC).timestamp()}", RepoKind.GIT, url="https://example.com/b.git"
    )
    with session_scope() as db:  # connect enqueues the run; reuse it (single-flight)
        run = db.scalar(select(ScanRun).where(ScanRun.repo_id == repo.id))
        run_id = run.id
        db.expunge(run)
    return repo.id, run_id


def test_agent_park_and_resume_without_raise():
    from security_agent.control.cost import list_parked_runs, park_run_for_agent, resume_run
    from security_agent.db.models import RunStatus, ScanRun

    _repo_id, run_id = _repo_and_run()
    try:
        assert park_run_for_agent(run_id, "Agent is not configured.") is True
        assert park_run_for_agent(run_id, "again") is False
        parked = [r for r in list_parked_runs() if r["id"] == run_id]
        assert len(parked) == 1
        assert "agent" in parked[0]["reason"].lower()
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


def test_execute_once_parks_on_agent_error():
    import security_agent.worker.main as worker_main
    from security_agent.db.models import RunStatus, ScanRun

    _settle_inflight()
    _repo_id, run_id = _repo_and_run()

    def _invoke(state):
        if state.get("run_id") == run_id:
            raise AgentError("Agent is not configured.")
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
        assert "agent" in (run.park_reason or "").lower()
        run.parked = False  # settle: leave no parked rows behind
        run.status = RunStatus.DONE


# --- Fail-loud callers ---


def test_pr_text_propagates_agent_error_past_template():
    from security_agent.agent.pr_text import generate_pr_text

    with (
        mock.patch(
            "security_agent.config.get_settings",
            return_value=mock.Mock(pr_text_model_enabled=True),
        ),
        mock.patch("security_agent.agent.tracked_invoke", side_effect=AgentError("no agent")),
    ):
        with pytest.raises(AgentError):
            generate_pr_text("p", "1", "2", ["CVE-1"], [], ["v"], "g", [], "d")


def test_deliver_reraises_agent_error_past_template():
    from security_agent.worker.deliver import _render_pr_text

    with mock.patch(
        "security_agent.agent.pr_text.generate_pr_text", side_effect=AgentError("no agent")
    ):
        with pytest.raises(AgentError):
            _render_pr_text("p", "1", "2", ["A"], [], ["v"], "g", [], "d")


def test_deps_summary_converts_agent_error_to_report_error():
    from security_agent.worker.deps_report import ReportError, generate_summary

    with (
        mock.patch(
            "security_agent.config.get_settings",
            return_value=mock.Mock(deps_report_model_enabled=True),
        ),
        mock.patch("security_agent.agent.get_chat_model", side_effect=AgentError("no agent")),
    ):
        with pytest.raises(ReportError, match="agent unavailable"):
            generate_summary([{"key": "k"}])


def test_news_classification_surfaces_agent_error_and_stops():
    from security_agent.db.models import NewsItem
    from security_agent.worker import news_intel

    tag = f"agent-{datetime.now(UTC).timestamp()}"
    with session_scope() as db:
        db.add(
            NewsItem(
                source="test", external_id=tag, title="t", summary="s", body_excerpt="excerpt"
            )  # skip enrichment: no network
        )
        db.flush()
    try:
        with mock.patch("security_agent.agent.get_chat_model", side_effect=AgentError("no agent")):
            with pytest.raises(AgentError):
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


def test_chat_turn_surfaces_configure_agent_notice():
    from security_agent.chat import get_conversation
    from security_agent.chat.agent import answer_turn

    owner = _owner()
    conv = get_conversation(owner.id)
    reply = answer_turn(owner, conv, "hi")
    assert "Settings → Agent" in reply.content
