from unittest import mock

import pytest

from security_agent.sandbox import tools


@pytest.fixture(autouse=True)
def _pin_host_backend(monkeypatch):
    """Tool-mechanic tests run below backend resolution: pin host.

    Real settings use SANDBOX_BACKEND=auto, which would probe `docker
    image inspect` through the mocked subprocess and pollute the
    per-process auto cache across tests.
    """
    import security_agent.sandbox as sandbox_mod

    settings = mock.Mock(
        is_prod=False,
        sandbox_backend="host",
        sandbox_image="img:test",
        sandbox_work_root="",
        sandbox_network="none",
    )
    monkeypatch.setattr("security_agent.config.get_settings", lambda: settings)
    monkeypatch.setattr(sandbox_mod, "_AUTO_BACKEND_CACHE", {})


def test_unknown_tool_fails_closed():
    with pytest.raises(PermissionError, match="outside the manifest"):
        tools.run_allowlisted("rm", ["-rf", "/"])


def test_search_rejects_flag_injection():
    with pytest.raises(ValueError, match="suspicious"):
        tools.code_search.func("-e", "/tmp")


def test_argv_preview_is_quoted():
    assert "osv-scanner" in tools.argv_preview("osv-scanner", ["--lockfile", "x"])


def _spooled_run(*, stdout: str = "", stderr: str = "", returncode: int = 0):
    """Fake subprocess.run that writes through the spooled stream files."""

    def fake(_argv, **kwargs):
        kwargs["stdout"].write(stdout.encode())
        kwargs["stderr"].write(stderr.encode())
        return mock.Mock(returncode=returncode)

    return fake


def test_success_codes_return_stdout():
    fake = _spooled_run(stdout='{"results": []}')
    with mock.patch.object(tools.subprocess, "run", side_effect=fake):
        assert (
            tools.run_allowlisted("osv-scanner", ["x"], success_codes=(0, 1)) == '{"results": []}'
        )
    failing = _spooled_run(stdout='{"results": []}', returncode=1)
    with (
        mock.patch.object(tools.subprocess, "run", side_effect=failing),
        pytest.raises(RuntimeError, match="failed"),
    ):
        tools.run_allowlisted("osv-scanner", ["x"])


def test_output_cap_truncates_by_default_but_allows_override():
    big = "x" * (tools.MAX_OUTPUT_CHARS + 100)
    fake = _spooled_run(stdout=big)
    with mock.patch.object(tools.subprocess, "run", side_effect=fake):
        assert len(tools.run_allowlisted("npm", ["x"])) == tools.MAX_OUTPUT_CHARS
        assert tools.run_allowlisted("npm", ["x"], max_output=tools.MAX_SCANNER_OUTPUT_CHARS) == big


def test_child_env_allowlist_drops_secrets(monkeypatch):
    monkeypatch.setenv("MASTER_KEY", "s3cr3t")
    monkeypatch.setenv("DATABASE_URL", "postgres://secret/db")
    monkeypatch.setenv("MY_API_TOKEN", "tok")
    completed = mock.Mock(returncode=0)
    with mock.patch.object(tools.subprocess, "run", return_value=completed) as fake_run:
        tools.run_allowlisted("git", ["--version"])
    child = fake_run.call_args[1]["env"]
    assert "MASTER_KEY" not in child
    assert "DATABASE_URL" not in child
    assert "MY_API_TOKEN" not in child
    assert "PATH" in child and "HOME" in child


def test_child_env_rejects_secret_pattern_keys():
    with pytest.raises(ValueError, match="secret-pattern"):
        tools.run_allowlisted("git", ["--version"], env={"API_TOKEN": "x"})


def test_missing_tool_binary_fails_actionable():
    with (
        mock.patch.object(tools.subprocess, "run", side_effect=FileNotFoundError("git")),
        pytest.raises(RuntimeError, match="binary not found.*SANDBOX_BACKEND=docker"),
    ):
        tools.run_allowlisted("git", ["clone", "x"])
