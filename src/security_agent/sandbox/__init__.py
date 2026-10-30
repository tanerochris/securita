"""Sandbox execution policy (FR-14, NFR-1/NFR-2). Host execution banned in prod."""

import enum
import shutil
import tempfile
from pathlib import Path


class ExecutionPolicy(enum.StrEnum):
    DOCKER = "docker"
    HOST = "host"


def resolve_policy() -> ExecutionPolicy:
    """Target execution policy. Docker everywhere; host is never resolved."""
    return ExecutionPolicy.DOCKER


def resolve_backend() -> str:
    """Execution backend: 'docker' (fresh container per tool call) or 'host'.

    SANDBOX_BACKEND=auto (default) resolves to docker in prod and host
    elsewhere. Prod never falls back to host: a missing Docker CLI or
    sandbox image fails the run loud instead of executing on the host.
    """
    from security_agent.config import get_settings as live_settings

    s = live_settings()
    raw = getattr(s, "sandbox_backend", "auto")
    raw = raw.strip().lower() if isinstance(raw, str) else "auto"
    if raw in ("docker", "host"):
        return raw
    return "docker" if s.is_prod else "host"


def assert_allowed(policy: ExecutionPolicy) -> None:
    from security_agent.config import get_settings as live_settings

    s = live_settings()
    if policy == ExecutionPolicy.HOST and s.is_prod:
        raise PermissionError("Host execution policy is banned in prod (NFR-1).")
    if policy == ExecutionPolicy.HOST:
        raise PermissionError("Host execution requires an explicit dev-only opt-in.")


def assert_execution_allowed() -> None:
    """Gate pipeline entry points on a usable execution backend."""
    from security_agent.config import get_settings as live_settings

    s = live_settings()
    backend = resolve_backend()
    if backend == "docker":
        if shutil.which("docker") is None:
            raise PermissionError(
                "Prod scans require the Docker sandbox (NFR-1): docker CLI unavailable."
            )
        return
    if s.is_prod:
        raise PermissionError("Prod scans require the Docker sandbox (NFR-1).")


def assert_host_execution_allowed() -> None:
    """Backward-compatible name for assert_execution_allowed()."""
    assert_execution_allowed()


def make_workdir(prefix: str) -> Path:
    """Per-run workdir. Under SANDBOX_WORK_ROOT when set (shared volume)."""
    from security_agent.config import get_settings as live_settings

    _root = getattr(live_settings(), "sandbox_work_root", "")
    root = _root.strip() if isinstance(_root, str) else ""
    if root:
        base = Path(root)
        base.mkdir(parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix=prefix, dir=str(base)))
    return Path(tempfile.mkdtemp(prefix=prefix))
