"""LangGraph pipeline (FR-2/3/4/5/8). Real nodes land per H2 slice; the rest stub.

Approval gates are graph checkpoints *between* nodes via interrupt_before —
never mid-shell (decision 9). Gated actions (merge/rotation/publish) execute
from the backend post-approval; H1 proves the mechanism with a test.
"""

import operator
from typing import Annotated, Any

from typing_extensions import TypedDict


class AgentState(TypedDict, total=False):
    repo: str
    repo_id: int
    run_id: int
    findings: list[dict[str, Any]]
    verdicts: list[dict[str, Any]]
    proposals: list[dict[str, Any]]
    merges: list[dict[str, Any]]
    done: Annotated[list[str], operator.add]


NODES = (
    "fetch_signals",
    "sandbox_scan",
    "reachability",
    "patch",
    "deliver",
    "merge",
    "notify",
)


def _stub(name: str):
    def _node(state: AgentState) -> dict:
        return {"done": [name]}

    _node.__name__ = name
    return _node


def _fetch_signals(state: AgentState) -> dict:
    """H3: poll Tier-2 news sources, then classify and mint intel.

    Tier-2 signals must never gate Tier-1 scanning: each half is isolated
    so a news outage still lets the pipeline reach the sandbox scan.
    Per-run executions skip the poll entirely — the orchestrator tick
    already polls/processes every 60s, and re-running model-backed
    classification ahead of every scan only delays its first log line.
    """
    if state.get("repo_id") is not None:
        return {"done": ["fetch_signals"]}
    import logging

    from security_agent.worker.news import poll_news
    from security_agent.worker.news_intel import process_news

    log = logging.getLogger(__name__)
    try:
        poll_news()
    except Exception as exc:  # noqa: BLE001 - news must never block a scan
        log.warning("fetch_signals poll failed: %s", exc)
    try:
        process_news()
    except Exception as exc:  # noqa: BLE001 - news must never block a scan
        log.warning("fetch_signals intel failed: %s", exc)
    return {"done": ["fetch_signals"]}


def _sandbox_scan(state: AgentState) -> dict:
    """Slice C: real scan when repo_id/run_id ride along, else stub passthrough."""
    repo_id, run_id = state.get("repo_id"), state.get("run_id")
    if repo_id is None or run_id is None:
        return {"done": ["sandbox_scan"]}
    from security_agent.worker.scan import run_scan

    result = run_scan(repo_id, run_id)
    return {
        "done": ["sandbox_scan"],
        "findings": [{"id": fid} for fid in result.get("finding_ids", [])],
    }


def _reachability(state: AgentState) -> dict:
    """Slice D: real verdicts when repo_id/run_id ride along, else passthrough."""
    repo_id, run_id = state.get("repo_id"), state.get("run_id")
    if repo_id is None or run_id is None:
        return {"done": ["reachability"]}
    from security_agent.worker.reachability import run_reachability

    result = run_reachability(repo_id, run_id)
    return {
        "done": ["reachability"],
        "verdicts": [{"id": vid} for vid in result.get("verdict_ids", [])],
    }


def _patch(state: AgentState) -> dict:
    """Slice E: real patches when repo_id/run_id ride along, else passthrough."""
    repo_id, run_id = state.get("repo_id"), state.get("run_id")
    if repo_id is None or run_id is None:
        return {"done": ["patch"]}
    from security_agent.brain.adapt import select_adapt
    from security_agent.control.cost import run_context
    from security_agent.worker.patch import run_patch

    with run_context(run_id):
        result = run_patch(repo_id, run_id, adapt=select_adapt())
    return {
        "done": ["patch"],
        "proposals": [{"id": pid} for pid in result.get("proposal_ids", [])],
    }


def _deliver(state: AgentState) -> dict:
    """Slice F: real delivery when repo_id/run_id ride along, else passthrough."""
    repo_id, run_id = state.get("repo_id"), state.get("run_id")
    if repo_id is None or run_id is None:
        return {"done": ["deliver"]}
    from security_agent.worker.deliver import run_deliver

    result = run_deliver(repo_id, run_id)
    return {
        "done": ["deliver"],
        "proposals": [{"id": pid} for pid in result.get("proposal_ids", [])],
    }


def _merge(state: AgentState) -> dict:
    """Slice G: merge APPROVED gates for delivered proposals, else skip.

    Runs behind interrupt_before=["merge"]: withhold approval and this node
    observes zero approved gates, so zero merges happen.
    """
    repo_id, run_id = state.get("repo_id"), state.get("run_id")
    if repo_id is None or run_id is None:
        return {"done": ["merge"]}
    from security_agent.control.gates import run_merge

    proposal_ids: list[int] = []
    for ref in state.get("proposals", []):
        pid = ref.get("id")
        if isinstance(pid, int):
            proposal_ids.append(pid)
    result = run_merge(repo_id, run_id, proposal_ids)
    return {
        "done": ["merge"],
        "merges": [{"id": pid} for pid in result.get("merged", [])],
    }


def _notify(state: AgentState) -> dict:
    """H6: severity-split run summary over FR-13 channels (never breaks the run).

    New KEV findings page high even with no verdicts yet; new reachable
    non-KEV findings go medium; unreachable-only runs stay silent.
    """
    repo_id, run_id = state.get("repo_id"), state.get("run_id")
    if repo_id is None or run_id is None:
        return {"done": ["notify"]}
    import logging

    log = logging.getLogger(__name__)
    try:
        from sqlalchemy import select

        from security_agent.db.models import Finding, FindingStatus, Repo, Verdict
        from security_agent.db.session import session_scope
        from security_agent.notify import notify_event

        with session_scope() as db:
            repo = db.get(Repo, repo_id)
            name = repo.name if repo else f"repo#{repo_id}"
            fresh = list(
                db.scalars(
                    select(Finding).where(
                        Finding.repo_id == repo_id,
                        Finding.first_run_id == run_id,
                        Finding.status.in_([FindingStatus.OPEN, FindingStatus.PROPOSED]),
                    )
                )
            )
            reachable_ids = set(
                db.scalars(
                    select(Verdict.finding_id).where(
                        Verdict.run_id == run_id, Verdict.reachable.is_(True)
                    )
                )
            )
            kev = [(f.id, f.advisory_id) for f in fresh if f.kev_exploited]
            reached = [
                (f.id, f.advisory_id)
                for f in fresh
                if not f.kev_exploited and f.id in reachable_ids
            ]
        if kev:
            advisories = ", ".join(sorted({a for _, a in kev})[:10])
            notify_event(
                "high",
                f"{name}: {len(kev)} new KEV finding(s) ({advisories})",
                f"Run {run_id} opened {len(kev)} KEV exploited finding(s): "
                f"{advisories}. Review them in the dashboard.",
                link=f"/repos/{repo_id}/findings",
                kind="new-kev",
            )
        if reached:
            advisories = ", ".join(sorted({a for _, a in reached})[:10])
            notify_event(
                "medium",
                f"{name}: {len(reached)} new reachable finding(s) ({advisories})",
                f"Run {run_id} opened {len(reached)} reachable finding(s): "
                f"{advisories}. Review them in the dashboard.",
                link=f"/repos/{repo_id}/findings",
                kind="new-reachable",
            )
    except Exception as exc:  # noqa: BLE001 - notify must never break a run
        log.warning("notify node failed: %s", exc)
    return {"done": ["notify"]}


def build_graph(checkpointer=None, *, interrupt_before: list[str] | None = None):
    from langgraph.graph import END, START, StateGraph

    builders = {
        "fetch_signals": _fetch_signals,
        "sandbox_scan": _sandbox_scan,
        "reachability": _reachability,
        "patch": _patch,
        "deliver": _deliver,
        "merge": _merge,
        "notify": _notify,
    }
    g = StateGraph(AgentState)
    prev = START
    for name in NODES:
        g.add_node(name, builders.get(name, _stub(name)))
        g.add_edge(prev, name)
        prev = name
    g.add_edge(prev, END)
    return g.compile(checkpointer=checkpointer, interrupt_before=interrupt_before or [])
