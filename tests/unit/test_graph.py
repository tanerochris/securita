from unittest import mock

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from security_agent.worker import NODES, build_graph


@pytest.fixture(autouse=True)
def _no_live_news():
    """fetch_signals must never hit the network in graph tests."""
    with (
        mock.patch("security_agent.worker.news.poll_news", return_value={}),
        mock.patch(
            "security_agent.worker.news_intel.process_news",
            return_value={"classified": 0, "major": 0, "minted": 0, "linked": 0},
        ),
    ):
        yield


def test_graph_runs_all_nodes():
    result = build_graph().invoke({"repo": "demo"})
    assert list(result["done"]) == list(NODES)


def test_fetch_signals_skipped_for_scan_runs():
    """Per-run executions skip the news poll: the orchestrator tick owns it.

    Re-running model-backed classification ahead of every scan only
    delays the run's first log line; the node still reports done.
    (Calls the node directly: a full graph invoke with repo_id would
    run a real scan through the later stages.)
    """
    from security_agent.worker.graph import _fetch_signals

    with (
        mock.patch("security_agent.worker.news.poll_news") as poll,
        mock.patch("security_agent.worker.news_intel.process_news") as process,
    ):
        result = _fetch_signals({"repo_id": 1, "run_id": 2})
    poll.assert_not_called()
    process.assert_not_called()
    assert result == {"done": ["fetch_signals"]}


def test_fetch_signals_isolated_from_news_outage():
    """Tier-2 failures must never gate Tier-1 scanning."""
    with (
        mock.patch("security_agent.worker.news.poll_news", side_effect=RuntimeError("HN down")),
        mock.patch(
            "security_agent.worker.news_intel.process_news", side_effect=RuntimeError("db locked")
        ),
    ):
        result = build_graph().invoke({"repo": "demo"})
    assert list(result["done"]) == list(NODES)


def test_approval_checkpoint_between_nodes():
    graph = build_graph(checkpointer=InMemorySaver(), interrupt_before=["deliver"])
    cfg = {"configurable": {"thread_id": "t1"}}
    graph.invoke({"repo": "demo"}, cfg)
    state = graph.get_state(cfg)
    assert state.next == ("deliver",)  # paused BEFORE deliver, never mid-node
    assert "patch" in state.values["done"]
    final = graph.invoke(Command(resume=True), cfg)
    assert "notify" in final["done"]
