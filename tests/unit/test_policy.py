import pytest

from security_agent.sandbox import ExecutionPolicy, assert_allowed, resolve_policy


def test_prod_policy_is_docker():
    assert resolve_policy() == ExecutionPolicy.DOCKER


def test_host_policy_rejected():
    with pytest.raises(PermissionError):
        assert_allowed(ExecutionPolicy.HOST)
