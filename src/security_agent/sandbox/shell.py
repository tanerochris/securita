"""Ad-hoc sandboxed shell via ShellToolMiddleware + DockerExecutionPolicy (FR-14).

Fresh container per run, removed on exit, no network. Host policy is banned:
the factory refuses to build it, mirroring sandbox.assert_allowed.
"""

from langchain.agents.middleware import (
    DockerExecutionPolicy,
    ShellToolMiddleware,
)

from security_agent.config import get_settings
from security_agent.sandbox import ExecutionPolicy, assert_allowed


def _sandbox_image() -> str:
    return getattr(get_settings(), "sandbox_image", "security-agent-sandbox:latest")


def build_shell_middleware(
    policy: ExecutionPolicy = ExecutionPolicy.DOCKER,
) -> ShellToolMiddleware:
    assert_allowed(policy)
    if policy != ExecutionPolicy.DOCKER:
        raise PermissionError("Only the Docker execution policy is supported.")
    return ShellToolMiddleware(
        execution_policy=DockerExecutionPolicy(
            image=_sandbox_image(),
            remove_container_on_exit=True,
            network_enabled=False,
        )
    )
