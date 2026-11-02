"""SSE frame diffing: init snapshot, tails, resync, quiet-close, reopen."""

from security_agent.app.live import LiveState, stream_states
from security_agent.db.models import RunStatus


def _collect(frames: list) -> str:
    it = iter(frames)
    return "".join(stream_states(lambda: next(it), poll_seconds=0))


def _done(notes: str, times: int = 4) -> list:
    return [LiveState(RunStatus.DONE, notes) for _ in range(times)]


def test_init_then_append_then_complete():
    text = _collect(
        [
            LiveState(RunStatus.RUNNING, "cloning\n"),
            LiveState(RunStatus.RUNNING, "cloning\nscanned 3 lockfiles\n"),
            *_done("cloning\nscanned 3 lockfiles\n"),
        ]
    )
    assert text.startswith("retry: 3000\n\n")
    assert text.count("event: init") == 1
    assert 'data: {"status": "running", "notes": "cloning\\n"}' in text
    assert 'event: log\ndata: {"append": "scanned 3 lockfiles\\n"}' in text
    assert 'event: status\ndata: {"status": "done"}' in text
    assert 'event: complete\ndata: {"status": "done"}' in text


def test_terminal_snapshot_completes_after_quiet():
    text = _collect(_done("boom"))
    assert 'data: {"status": "done", "notes": "boom"}' in text
    assert "event: log" not in text
    assert "event: status" not in text
    assert text.count("event: complete") == 1


def test_mid_pipeline_done_keeps_streaming_until_quiet():
    """Scan marks DONE, a later stage reopens: no close until truly quiet."""
    text = _collect(
        [
            LiveState(RunStatus.RUNNING, "a\n"),
            LiveState(RunStatus.DONE, "a\n"),
            LiveState(RunStatus.RUNNING, "a\n"),
            LiveState(RunStatus.RUNNING, "a\nb\n"),
            *_done("a\nb\n"),
        ]
    )
    assert text.count("event: status") == 3  # done, running, done
    assert 'event: log\ndata: {"append": "b\\n"}' in text
    assert text.count("event: complete") == 1


def test_prefix_mismatch_resyncs_full_notes():
    text = _collect(
        [
            LiveState(RunStatus.RUNNING, "old\n"),
            LiveState(RunStatus.RUNNING, "rewritten\n"),
            *_done("rewritten\n"),
        ]
    )
    assert "event: log" not in text
    assert 'event: reset\ndata: {"notes": "rewritten\\n"}' in text
    assert text.count("event: complete") == 1


def test_missing_row_emits_gone_and_closes():
    text = _collect([LiveState(RunStatus.RUNNING, "a\n"), None])
    assert text.count("event: gone") == 1
    assert "event: complete" not in text
