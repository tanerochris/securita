"""Docker sandbox backend (follow-up #1): fresh container per tool call."""

from unittest import mock

import pytest

from security_agent.sandbox import tools as tools_mod


def _fake_proc(returncode=0):
    proc = mock.Mock()
    proc.returncode = returncode
    return proc


def _run_capturing(monkeypatch, **kwargs):
    captured = {}

    def fake_run(argv, **run_kwargs):
        captured["argv"] = argv
        captured["kwargs"] = run_kwargs
        # Emulate spool files: subprocess.run with file stdout writes nothing
        # via return; run_allowlisted reads the spool, so write via stdout handle.
        run_kwargs["stdout"].write(b"sandbox-ok")
        return _fake_proc(0)

    monkeypatch.setattr(tools_mod.subprocess, "run", fake_run)
    settings = mock.Mock(
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
        out = tools_mod.run_allowlisted("git", ["status"], cwd="/tmp/work-xyz", **kwargs)
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


def test_sandbox_image_carries_scanners_not_worker_image():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    sandbox = (root / "Dockerfile.sandbox").read_text()
    worker = (root / "Dockerfile").read_text()
    assert "betterleaks" in sandbox and "osv-scanner" in sandbox
    assert 'install -m 0755 "$BL_BIN" /usr/local/bin/betterleaks' not in worker
    assert "BETTERLEAKS_VERSION" not in worker
