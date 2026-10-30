import pytest
from langchain.agents.middleware import DockerExecutionPolicy

from security_agent.sandbox import ExecutionPolicy
from security_agent.sandbox.shell import build_shell_middleware


def test_shell_uses_docker_policy():
    mw = build_shell_middleware()
    # No public accessor in langchain 1.x; _execution_policy is the stored policy.
    policy = mw._execution_policy  # noqa: SLF001
    assert isinstance(policy, DockerExecutionPolicy)
    assert policy.network_enabled is False
    assert policy.remove_container_on_exit is True


def test_host_policy_refused():
    with pytest.raises(PermissionError):
        build_shell_middleware(ExecutionPolicy.HOST)
