"""Docker sandbox backend (follow-up #1): fresh container per tool call."""

from unittest import mock

import pytest

from security_agent.sandbox import tools as tools_mod


def _fake_proc(returncode=0):
    proc = mock.Mock()
    proc.returncode = returncode
    return proc


def _run_capturing(monkeypatch, settings=None, **kwargs):
    captured = {}

    def fake_run(argv, **run_kwargs):
        captured["argv"] = argv
        captured["kwargs"] = run_kwargs
        # Emulate spool files: subprocess.run with file stdout writes nothing
        # via return; run_allowlisted reads the spool, so write via stdout handle.
        run_kwargs["stdout"].write(b"sandbox-ok")
        return _fake_proc(0)

    monkeypatch.setattr(tools_mod.subprocess, "run", fake_run)
    settings = settings or mock.Mock(
        is_prod=True,
        sandbox_backend="docker",
        sandbox_image="security-agent-sandbox:test",
        sandbox_work_root="",
        sandbox_network="none",
    )
    with (
        mock.patch("security_agent.config.get_settings", return_value=settings),
        mock.patch("shutil.which", return_value="/usr/bin/docker"),
    ):
        kwargs.setdefault("cwd", "/tmp/work-xyz")
        out = tools_mod.run_allowlisted("git", ["status"], **kwargs)
    return out, captured


def test_docker_backend_wraps_in_fresh_container(monkeypatch, tmp_path):
    work = tmp_path / "repo"
    work.mkdir()
    captured = {}

    def fake_run(argv, **run_kwargs):
        captured["argv"] = argv
        run_kwargs["stdout"].write(b"clean")
        return _fake_proc(0)

    monkeypatch.setattr(tools_mod.subprocess, "run", fake_run)
    settings = mock.Mock(
        is_prod=True,
        sandbox_backend="docker",
        sandbox_image="img:test",
        sandbox_work_root="",
        sandbox_network="none",
    )
    with (
        mock.patch("security_agent.config.get_settings", return_value=settings),
        mock.patch("shutil.which", return_value="/usr/bin/docker"),
    ):
        out = tools_mod.run_allowlisted(
            "osv-scanner",
            ["--lockfile", "package-lock.json", "--format", "json"],
            cwd=str(work),
            success_codes=(0, 1),
        )
    assert out == "clean"
    argv = captured["argv"]
    assert argv[:2] == ["docker", "run"]
    assert "--rm" in argv and "--network" in argv and "none" in argv
    assert "--memory" in argv and "--pids-limit" in argv
    assert f"{work}:/work" in argv
    assert "img:test" in argv
    # Tool argv follows the image, with the manifest prefix intact.
    assert argv[argv.index("img:test") + 1 :] == [
        "osv-scanner",
        "scan",
        "--lockfile",
        "package-lock.json",
        "--format",
        "json",
    ]


def test_docker_backend_rewrites_workdir_paths(monkeypatch, tmp_path):
    work = tmp_path / "repo"
    work.mkdir()
    captured = {}

    def fake_run(argv, **run_kwargs):
        captured["argv"] = argv
        return _fake_proc(0)

    monkeypatch.setattr(tools_mod.subprocess, "run", fake_run)
    settings = mock.Mock(
        is_prod=False,
        sandbox_backend="docker",
        sandbox_image="img:test",
        sandbox_work_root="",
        sandbox_network="none",
    )
    with (
        mock.patch("security_agent.config.get_settings", return_value=settings),
        mock.patch("shutil.which", return_value="/usr/bin/docker"),
    ):
        tools_mod.run_allowlisted("betterleaks", ["fs", str(work), "--validate"], cwd=str(work))
    argv = captured["argv"]
    assert "/work" in argv
    assert str(work) not in argv


def test_docker_backend_fails_closed_without_docker(monkeypatch):
    settings = mock.Mock(
        is_prod=True,
        sandbox_backend="docker",
        sandbox_image="img:test",
        sandbox_work_root="",
        sandbox_network="none",
    )
    with (
        mock.patch("security_agent.config.get_settings", return_value=settings),
        mock.patch("shutil.which", return_value=None),
    ):
        with pytest.raises(PermissionError, match="docker CLI"):
            tools_mod.run_allowlisted("git", ["status"], cwd="/tmp/x")


def test_docker_backend_network_only_when_allowed(monkeypatch, tmp_path):
    work = tmp_path / "r"
    work.mkdir()
    captured = {}

    def fake_run(argv, **run_kwargs):
        captured["argv"] = argv
        return _fake_proc(0)

    monkeypatch.setattr(tools_mod.subprocess, "run", fake_run)
    settings = mock.Mock(
        is_prod=True,
        sandbox_backend="docker",
        sandbox_image="img:test",
        sandbox_work_root="",
        sandbox_network="none",
    )
    with (
        mock.patch("security_agent.config.get_settings", return_value=settings),
        mock.patch("shutil.which", return_value="/usr/bin/docker"),
    ):
        tools_mod.run_allowlisted(
            "git", ["clone", "https://x", "dest"], cwd=str(work), allow_network=True
        )
    argv = captured["argv"]
    assert argv[argv.index("--network") + 1] == "bridge"


def _sandbox_settings(backend: str):
    return mock.Mock(
        is_prod=(backend == "docker"),
        sandbox_backend=backend,
        sandbox_image="security-agent-sandbox:test",
        sandbox_work_root="",
        sandbox_network="none",
    )


def test_assert_sandbox_image_passes_when_present(monkeypatch):
    import security_agent.sandbox as sandbox_mod

    monkeypatch.setattr(sandbox_mod.subprocess, "run", lambda *a, **k: _fake_proc(0))
    with mock.patch("security_agent.config.get_settings", return_value=_sandbox_settings("docker")):
        sandbox_mod.assert_sandbox_image()  # must not raise


def test_assert_sandbox_image_fails_loud_with_build_command(monkeypatch):
    import subprocess as stdlib_subprocess

    import security_agent.sandbox as sandbox_mod

    def missing(*args, **kwargs):
        raise stdlib_subprocess.CalledProcessError(1, args[0])

    monkeypatch.setattr(sandbox_mod.subprocess, "run", missing)
    with (
        mock.patch("security_agent.config.get_settings", return_value=_sandbox_settings("docker")),
        pytest.raises(RuntimeError, match="docker compose build sandbox-runner"),
    ):
        sandbox_mod.assert_sandbox_image()


def test_assert_sandbox_image_skipped_on_host_backend(monkeypatch):
    import security_agent.sandbox as sandbox_mod

    run = mock.Mock(side_effect=AssertionError("must not shell out"))
    monkeypatch.setattr(sandbox_mod.subprocess, "run", run)
    with mock.patch("security_agent.config.get_settings", return_value=_sandbox_settings("host")):
        sandbox_mod.assert_sandbox_image()
    run.assert_not_called()


def _volume_settings():
    return mock.Mock(
        is_prod=True,
        sandbox_backend="docker",
        sandbox_image="security-agent-sandbox:test",
        sandbox_work_root="/sandbox-work",
        sandbox_work_volume="sandbox-work",
        sandbox_network="none",
    )


def test_shared_workdir_mounts_named_volume_not_host_bind(monkeypatch):
    """The daemon resolves bind sources on ITS host, where container paths
    like /sandbox-work do not exist (Docker Desktop: "mounts denied";
    Linux: a silently empty dir). Workdirs under the shared root must
    mount the shared volume by name instead."""
    _, captured = _run_capturing(monkeypatch, _volume_settings(), cwd="/sandbox-work/run-1")
    argv = captured["argv"]
    assert "-v" not in argv
    mount = argv[argv.index("--mount") + 1]
    assert mount == "type=volume,src=sandbox-work,dst=/work,volume-subpath=run-1"
    assert argv[argv.index("-w") + 1] == "/work"


def test_workdir_escape_falls_back_to_bind(monkeypatch):
    """A cwd that lexically escapes the shared root (.. traversal) must
    not become a volume subpath; it keeps the legacy bind behavior."""
    _, captured = _run_capturing(monkeypatch, _volume_settings(), cwd="/sandbox-work/../etc")
    argv = captured["argv"]
    assert "--mount" not in argv
    assert argv[argv.index("-v") + 1] == "/sandbox-work/../etc:/work"


def test_scratch_workdir_lands_in_shared_volume(monkeypatch, tmp_path):
    """cwd=None tool calls get a scratch dir; under the docker backend it
    must live in the shared volume or the container cannot see it."""
    root = tmp_path / "shared"
    root.mkdir()
    settings = _volume_settings()
    settings.sandbox_work_root = str(root)
    _, captured = _run_capturing(monkeypatch, settings, cwd=None)
    argv = captured["argv"]
    assert "-v" not in argv
    mount = argv[argv.index("--mount") + 1]
    assert mount.startswith("type=volume,src=sandbox-work,dst=/work,volume-subpath=")
    assert "sandbox-cwd-" in mount


def test_sandbox_image_carries_scanners_not_worker_image():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    sandbox = (root / "Dockerfile.sandbox").read_text()
    worker = (root / "Dockerfile").read_text()
    assert "betterleaks" in sandbox and "osv-scanner" in sandbox
    assert 'install -m 0755 "$BL_BIN" /usr/local/bin/betterleaks' not in worker
    assert "BETTERLEAKS_VERSION" not in worker
