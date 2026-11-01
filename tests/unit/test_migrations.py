"""Alembic chain smoke: full upgrade plus 0007 downgrade/upgrade on SQLite.

Migrations load by path so the test needs no sys.path games; each runs
inside an Operations context against a throwaway database.
"""

import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect

VERSIONS = Path(__file__).resolve().parents[2] / "migrations" / "versions"
CHAIN = [
    "0001_init",
    "0002_resets",
    "0003_phase1",
    "0004_constraints",
    "0005_news",
    "0006_news_summary",
    "0007_ecosystem",
    "0008_secrets",
    "0009_secret_indexes",
    "0010_news_hardening",
    "0011_h6_notify_cost",
    "0012_provider_connections",
    "0013_news_intel",
    "0014_news_finding_links",
    "0015_news_relevance",
    "0016_policy_rag",
]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"mig_{name}", VERSIONS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(engine, *modules, direction="upgrade"):
    with engine.begin() as connection:
        context = MigrationContext.configure(connection)
        with Operations.context(context):
            for module in modules:
                getattr(module, direction)()


def _columns(engine, table: str) -> set[str]:
    return {column["name"] for column in inspect(engine).get_columns(table)}


def test_migration_chain_links_head_to_tail():
    modules = [_load(name) for name in CHAIN]
    assert modules[0].down_revision is None
    for prev, module in zip(modules, modules[1:], strict=False):
        assert module.down_revision == prev.revision


def test_migration_chain_upgrades_and_0007_roundtrips(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/mig.db")
    modules = [_load(name) for name in CHAIN]
    _run(engine, *modules)
    assert "verdict" in _columns(engine, "news_items")
    assert "category" in _columns(engine, "news_items")
    assert "classified_at" in _columns(engine, "news_items")
    assert "minted_at" in _columns(engine, "news_items")
    assert "provenance" in _columns(engine, "findings")
    assert "connection_id" in _columns(engine, "repos")
    assert "ecosystem" in _columns(engine, "findings")
    assert "news_weight" in _columns(engine, "findings")
    assert "secret_finding_id" in _columns(engine, "proposals")
    assert "rule_id" in _columns(engine, "secret_findings")
    assert "baseline_sha" in _columns(engine, "secret_baselines")
    assert "relevance" in _columns(engine, "news_repo_relevance")
    assert "score" in _columns(engine, "news_repo_relevance")
    assert "matched_signals" in _columns(engine, "news_repo_relevance")
    eco = _load("0007_ecosystem")
    _run(engine, eco, direction="downgrade")
    assert "ecosystem" not in _columns(engine, "findings")
    _run(engine, eco)
    assert "ecosystem" in _columns(engine, "findings")


def test_migration_0008_roundtrips(tmp_path):
    from sqlalchemy import inspect as sa_inspect

    engine = create_engine(f"sqlite:///{tmp_path}/mig8.db")
    modules = [_load(name) for name in CHAIN]
    _run(engine, *modules)
    eco8 = _load("0008_secrets")
    eco9 = _load("0009_secret_indexes")
    # Roll back in reverse dependency order: 0009's index needs 0008's column.
    _run(engine, eco9, direction="downgrade")
    _run(engine, eco8, direction="downgrade")
    assert "secret_finding_id" not in _columns(engine, "proposals")
    assert "secret_findings" not in sa_inspect(engine).get_table_names()
    assert "secret_baselines" not in sa_inspect(engine).get_table_names()
    _run(engine, eco8)
    _run(engine, eco9)
    assert "secret_finding_id" in _columns(engine, "proposals")
    assert "rule_id" in _columns(engine, "secret_findings")


def test_migration_0009_roundtrips(tmp_path):
    from sqlalchemy import inspect as sa_inspect

    engine = create_engine(f"sqlite:///{tmp_path}/mig9.db")
    modules = [_load(name) for name in CHAIN]
    _run(engine, *modules)

    def indexes(table: str) -> dict[str, dict]:
        return {ix["name"]: ix for ix in sa_inspect(engine).get_indexes(table)}

    assert "ix_secret_findings_repo_status" in indexes("secret_findings")
    assert indexes("proposals")["uq_proposals_secret_finding"]["unique"]
    mod9 = _load("0009_secret_indexes")
    _run(engine, mod9, direction="downgrade")
    assert "ix_secret_findings_repo_status" not in indexes("secret_findings")
    assert "uq_proposals_secret_finding" not in indexes("proposals")
    _run(engine, mod9)
    assert "ix_secret_findings_repo_status" in indexes("secret_findings")
    assert "uq_proposals_secret_finding" in indexes("proposals")


def test_migration_0010_roundtrips(tmp_path):
    from sqlalchemy import inspect as sa_inspect

    engine = create_engine(f"sqlite:///{tmp_path}/mig10.db")
    modules = [_load(name) for name in CHAIN]
    _run(engine, *modules)
    assert "scrape_throttles" in sa_inspect(engine).get_table_names()

    def indexes(table: str) -> dict[str, dict]:
        return {ix["name"]: ix for ix in sa_inspect(engine).get_indexes(table)}

    assert "ix_news_items_fetched_at" in indexes("news_items")
    _run(engine, _load("0011_h6_notify_cost"), direction="downgrade")
    _run(engine, _load("0010_news_hardening"), direction="downgrade")
    assert "scrape_throttles" not in sa_inspect(engine).get_table_names()
    assert "ix_news_items_fetched_at" not in indexes("news_items")
    _run(engine, _load("0010_news_hardening"))
    _run(engine, _load("0011_h6_notify_cost"))
    assert "scrape_throttles" in sa_inspect(engine).get_table_names()
    assert "ix_news_items_fetched_at" in indexes("news_items")


def test_migration_0011_roundtrips(tmp_path):
    from sqlalchemy import inspect as sa_inspect

    engine = create_engine(f"sqlite:///{tmp_path}/mig11.db")
    modules = [_load(name) for name in CHAIN]
    _run(engine, *modules)
    tables = sa_inspect(engine).get_table_names()
    for table in ("notify_channels", "notify_routes", "notify_state", "model_usage"):
        assert table in tables
    cols = _columns(engine, "scan_runs")
    for col in ("claimed_by", "claimed_at", "parked", "park_reason", "token_usage", "cost_warned"):
        assert col in cols

    def indexes(table: str) -> dict[str, dict]:
        return {ix["name"]: ix for ix in sa_inspect(engine).get_indexes(table)}

    assert "ix_scan_runs_status_started" in indexes("scan_runs")
    mod11 = _load("0011_h6_notify_cost")
    _run(engine, mod11, direction="downgrade")
    tables = sa_inspect(engine).get_table_names()
    for table in ("notify_channels", "notify_routes", "notify_state", "model_usage"):
        assert table not in tables
    cols = _columns(engine, "scan_runs")
    assert "claimed_by" not in cols and "parked" not in cols
    _run(engine, mod11)
    assert "notify_channels" in sa_inspect(engine).get_table_names()
    assert "claimed_by" in _columns(engine, "scan_runs")


def test_migration_0013_roundtrips(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/mig13.db")
    modules = [_load(name) for name in CHAIN]
    _run(engine, *modules)
    assert "verdict" in _columns(engine, "news_items")
    assert "provenance" in _columns(engine, "findings")
    mod13 = _load("0013_news_intel")
    _run(engine, mod13, direction="downgrade")
    assert "verdict" not in _columns(engine, "news_items")
    assert "provenance" not in _columns(engine, "findings")
    _run(engine, mod13)
    assert "verdict" in _columns(engine, "news_items")
    assert "provenance" in _columns(engine, "findings")


def test_migration_0015_roundtrips(tmp_path):
    from sqlalchemy import inspect as sa_inspect

    engine = create_engine(f"sqlite:///{tmp_path}/mig15.db")
    modules = [_load(name) for name in CHAIN]
    _run(engine, *modules)
    assert "news_repo_relevance" in sa_inspect(engine).get_table_names()
    mod15 = _load("0015_news_relevance")
    _run(engine, mod15, direction="downgrade")
    assert "news_repo_relevance" not in sa_inspect(engine).get_table_names()
    _run(engine, mod15)
    assert "news_repo_relevance" in sa_inspect(engine).get_table_names()


def test_migration_0016_roundtrips(tmp_path):
    from sqlalchemy import inspect as sa_inspect

    engine = create_engine(f"sqlite:///{tmp_path}/mig16.db")
    modules = [_load(name) for name in CHAIN]
    _run(engine, *modules)
    tables = sa_inspect(engine).get_table_names()
    for table in (
        "policy_documents",
        "policy_chunks",
        "policy_rules",
        "policy_run_snapshots",
    ):
        assert table in tables
    assert "readme_policy_enabled" in _columns(engine, "repos")
    assert "policy_block" in _columns(engine, "findings")
    mod16 = _load("0016_policy_rag")
    _run(engine, mod16, direction="downgrade")
    tables = sa_inspect(engine).get_table_names()
    for table in (
        "policy_documents",
        "policy_chunks",
        "policy_rules",
        "policy_run_snapshots",
    ):
        assert table not in tables
    assert "readme_policy_enabled" not in _columns(engine, "repos")
    assert "policy_block" not in _columns(engine, "findings")
    _run(engine, mod16)
    assert "policy_documents" in sa_inspect(engine).get_table_names()


def test_migration_0014_roundtrips(tmp_path):
    from sqlalchemy import inspect as sa_inspect

    engine = create_engine(f"sqlite:///{tmp_path}/mig14.db")
    modules = [_load(name) for name in CHAIN]
    _run(engine, *modules)
    assert "news_finding_links" in sa_inspect(engine).get_table_names()
    assert "kind" in _columns(engine, "news_finding_links")
    mod14 = _load("0014_news_finding_links")
    _run(engine, mod14, direction="downgrade")
    assert "news_finding_links" not in sa_inspect(engine).get_table_names()
    _run(engine, mod14)
    assert "news_finding_links" in sa_inspect(engine).get_table_names()
