"""Sandbox execution policy (FR-14, NFR-1/NFR-2). Host execution banned in prod."""

import enum
import shutil
import subprocess
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


def assert_sandbox_image() -> None:
    """Fail boot loud when the docker backend's image is missing locally.

    Without this, every run dies with the daemon's pull error
    ("repository does not exist or may require 'docker login'"), which
    reads like an auth problem when it is really an unbuilt image.
    No-op unless the docker backend is selected.
    """
    from security_agent.config import get_settings as live_settings

    if resolve_backend() != "docker":
        return
    image = getattr(live_settings(), "sandbox_image", "") or "security-agent-sandbox:latest"
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError(
            "docker CLI unavailable: the worker cannot scan. "
            "The worker image ships it; reinstall if it is missing."
        )
    try:
        subprocess.run(  # noqa: S603 - fixed argv, image is one arg
            [docker, "image", "inspect", image],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            f"Sandbox image '{image}' is missing locally: the worker cannot scan. "
            "Build it with: docker compose build sandbox-runner"
        ) from exc


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
