"""Host tool installer: pinned scanner downloads + package managers."""

import hashlib
import io
import sys
import tarfile
from pathlib import Path
from unittest import mock

import pytest

from security_agent.ops import install_tools as inst


def test_asset_specs_match_upstream_names():
    url, kind = inst.asset_spec("osv-scanner", "linux", "amd64")
    assert url.endswith("osv-scanner_linux_amd64") and kind == "file"
    url, kind = inst.asset_spec("osv-scanner", "darwin", "arm64")
    assert url.endswith("osv-scanner_darwin_arm64") and kind == "file"
    url, kind = inst.asset_spec("betterleaks", "linux", "amd64")
    assert url.endswith("betterleaks_2.0.0-rc.1_linux_x64.tar.gz") and kind == "tarball"
    url, kind = inst.asset_spec("betterleaks", "darwin", "arm64")
    assert url.endswith("betterleaks_2.0.0-rc.1_darwin_arm64.tar.gz") and kind == "tarball"


def test_asset_spec_rejects_unknown_platform_or_arch():
    with pytest.raises(inst.UnsupportedPlatform):
        inst.asset_spec("osv-scanner", "windows", "amd64")
    with pytest.raises(inst.UnsupportedPlatform):
        inst.asset_spec("osv-scanner", "linux", "mips")
    with pytest.raises(inst.UnsupportedPlatform):
        inst.asset_spec("nope", "linux", "amd64")


def test_verify_checksums_text():
    payload = b"fake-binary"
    digest = hashlib.sha256(payload).hexdigest()
    body = f"{digest}  osv-scanner_linux_amd64\n"
    assert inst.verify_payload(payload, "osv-scanner_linux_amd64", body) is None
    with pytest.raises(inst.InstallError):
        inst.verify_payload(b"tampered", "osv-scanner_linux_amd64", body)
    with pytest.raises(inst.InstallError):
        inst.verify_payload(payload, "other-file", body)


def _make_tarball(path: Path, member: str = "dist/betterleaks") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = b"#!/bin/sh\necho hi\n"
        info = tarfile.TarInfo(member)
        info.size = len(data)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(data))
    buf.seek(0)
    path.write_bytes(buf.read())
    return path.read_bytes()


def test_extract_finds_binary_in_tarball(tmp_path):
    archive = tmp_path / "bl.tar.gz"
    _make_tarball(archive)
    found = inst.extract_binary(archive, "betterleaks", tmp_path / "out")
    assert found.read_bytes().startswith(b"#!/bin/sh")


def test_extract_rejects_missing_binary(tmp_path):
    archive = tmp_path / "bl.tar.gz"
    _make_tarball(archive, member="dist/something-else")
    with pytest.raises(inst.InstallError):
        inst.extract_binary(archive, "betterleaks", tmp_path / "out")


def _run_main(argv: list[str]) -> int:
    """Run the entry point; SystemExit code (0 when it returns cleanly)."""
    with mock.patch.object(sys, "argv", ["install-tools", *argv]):
        try:
            inst.install_tools_main()
        except SystemExit as exc:
            code = exc.code
            return code if isinstance(code, int) else 1
    return 0


def test_install_skips_tools_already_on_path(tmp_path, capsys):
    with (
        mock.patch.object(inst.shutil, "which", return_value="/usr/bin/x"),
        mock.patch.object(inst, "_download", side_effect=AssertionError("no download")),
    ):
        assert _run_main(["--dir", str(tmp_path)]) == 0
    assert "already on PATH" in capsys.readouterr().out


def test_install_downloads_missing_scanner(tmp_path, capsys):
    payload = b"scanner-bytes"
    digest = hashlib.sha256(payload).hexdigest()

    def fake_download(url: str, dest: Path) -> None:
        if url.endswith("SHA256SUMS") or url.endswith("checksums.txt"):
            dest.write_text(f"{digest}  osv-scanner_linux_amd64\n")
        else:
            dest.write_bytes(payload)

    def fake_which(binary: str):
        return None if binary in ("osv-scanner", "betterleaks") else f"/usr/bin/{binary}"

    with (
        mock.patch.object(inst.platform, "system", return_value="Linux"),
        mock.patch.object(inst.platform, "machine", return_value="x86_64"),
        mock.patch.object(inst.shutil, "which", side_effect=fake_which),
        mock.patch.object(inst, "_download", side_effect=fake_download),
        mock.patch.object(inst.subprocess, "run") as run_mock,
    ):
        # betterleaks tarball path needs a real archive; limit to osv + present tools.
        code = _run_main(["--dir", str(tmp_path), "--tools", "osv-scanner,git"])
    assert code == 0
    installed = tmp_path / "osv-scanner"
    assert installed.read_bytes() == payload
    run_mock.assert_not_called()  # git present, no manager needed
    assert "installed" in capsys.readouterr().out


def test_install_uses_package_manager_for_missing_git(tmp_path):
    available = {"git": False}

    def fake_which(binary: str):
        if binary == "git":
            return "/usr/bin/git" if available["git"] else None
        return f"/usr/bin/{binary}"

    def fake_run(cmd, **kwargs):
        available["git"] = True
        return mock.Mock(returncode=0)

    with (
        mock.patch.object(inst.platform, "system", return_value="Linux"),
        mock.patch.object(inst.shutil, "which", side_effect=fake_which),
        mock.patch.object(inst, "_manager", return_value=("apt", ["apt-get"])),
        mock.patch.object(inst.subprocess, "run", side_effect=fake_run) as run_mock,
        mock.patch.object(inst.os, "geteuid", return_value=0, create=True),
    ):
        assert _run_main(["--dir", str(tmp_path), "--tools", "git"]) == 0
    assert run_mock.called


def test_windows_directs_to_wsl(capsys):
    with mock.patch.object(inst.platform, "system", return_value="Windows"):
        assert _run_main([]) == 2
    out = capsys.readouterr().out
    assert "WSL" in out


def test_manager_failure_reports_manual_command(tmp_path, capsys):
    with (
        mock.patch.object(inst.platform, "system", return_value="Linux"),
        mock.patch.object(inst.shutil, "which", return_value=None),
        mock.patch.object(inst, "_manager", return_value=None),
        mock.patch.object(inst, "_download", side_effect=AssertionError("no download")),
    ):
        assert _run_main(["--dir", str(tmp_path), "--tools", "git"]) == 1
    assert "manually" in capsys.readouterr().out.lower()
