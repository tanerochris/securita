"""Live worker-log streams (SSE) for run + dependency-check detail pages.

The worker is a separate process; the DB row is the shared state. Each
stream polls its row, diffs the append-only ``notes`` column, and emits
the new tail as events. EventSource reconnects on drops and always gets
a full ``init`` snapshot first, so reconnects self-heal without
Last-Event-ID bookkeeping.

Terminal statuses are not final by themselves: the scan node finishes
the run mid-pipeline and later stages reopen it while they append, so
the stream closes (with an explicit ``complete`` event) only after a
terminal status sits unchanged for a few polls. The client reloads on
``complete`` alone — never on ``status`` — so a mid-pipeline DONE can
never strand the page on a stale snapshot.
"""

import json
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from security_agent.db.models import RunStatus

POLL_SECONDS = 2.0
STABLE_POLLS_TO_CLOSE = 3
TERMINAL = frozenset({RunStatus.DONE, RunStatus.FAILED})


@dataclass(frozen=True)
class LiveState:
    status: RunStatus
    notes: str  # "" when the worker recorded nothing yet


def _frame(name: str, payload: dict) -> str:
    return f"event: {name}\ndata: {json.dumps(payload)}\n\n"


def stream_states(
    fetch: Callable[[], LiveState | None],
    *,
    poll_seconds: float | None = None,
    stable_polls_to_close: int = STABLE_POLLS_TO_CLOSE,
) -> Iterator[str]:
    """Yield SSE frames until the row is terminal *and* quiet, or gone.

    ``fetch`` returns None when the row is gone (repo disconnected).
    Notes are append-only, so the common case emits just the tail; a
    ``reset`` frame resyncs if the prefix ever disagrees.
    """
    if poll_seconds is None:
        poll_seconds = POLL_SECONDS
    yield "retry: 3000\n\n"
    sent_notes: str | None = None
    sent_status: RunStatus | None = None
    prev: tuple[RunStatus, str] | None = None
    stable = 0
    while True:
        state = fetch()
        if state is None:
            yield _frame("gone", {})
            return
        if sent_notes is None:
            yield _frame("init", {"status": state.status.value, "notes": state.notes})
        elif state.notes != sent_notes:
            if state.notes.startswith(sent_notes):
                yield _frame("log", {"append": state.notes[len(sent_notes) :]})
            else:
                yield _frame("reset", {"notes": state.notes})
        if sent_status is not None and state.status != sent_status:
            yield _frame("status", {"status": state.status.value})
        sent_notes, sent_status = state.notes, state.status
        current = (state.status, state.notes)
        if state.status in TERMINAL and current == prev:
            stable += 1
        else:
            stable = 0
        prev = current
        if stable >= stable_polls_to_close:
            yield _frame("complete", {"status": state.status.value})
            return
        yield ": ping\n\n"  # idle keep-alive; ignored by EventSource
        time.sleep(poll_seconds)
