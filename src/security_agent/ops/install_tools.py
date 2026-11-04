"""Install the host tools the doctor requires (macOS + Linux).

Scanners (osv-scanner, betterleaks) download pinned GitHub release
assets into ~/.local/bin, verified against the release's published
checksums. Everyday tools (git, ripgrep, node, npm) go through the
system package manager. Windows is not installed directly: the
command prints WSL2 setup steps and exits 2.
"""

import hashlib
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

# Keep in sync with Dockerfile.sandbox (same pins the sandbox image uses).
OSV_SCANNER_VERSION = "v2.7.0"
BETTERLEAKS_VERSION = "v2.0.0-rc.1"

_DOWNLOAD_TIMEOUT_SECONDS = 120

# binary -> {manager: [packages]}. brew formulas match binary names
# (node ships npm); apt splits node from npm.
_MANAGER_PACKAGES = {
    "git": {"brew": ["git"], "apt": ["git"], "dnf": ["git"], "pacman": ["git"], "apk": ["git"]},
    "rg": {
        "brew": ["ripgrep"],
        "apt": ["ripgrep"],
        "dnf": ["ripgrep"],
        "pacman": ["ripgrep"],
        "apk": ["ripgrep"],
    },
    "node": {
        "brew": ["node"],
        "apt": ["nodejs"],
        "dnf": ["nodejs"],
        "pacman": ["nodejs"],
        "apk": ["nodejs"],
    },
    "npm": {
        "brew": ["node"],
        "apt": ["npm"],
        "dnf": ["npm"],
        "pacman": ["npm"],
        "apk": ["npm"],
    },
}

# manager -> (probe binary, update argv or None, install argv prefix).
_MANAGERS = {
    "brew": ("brew", None, ["brew", "install"]),
    "apt": ("apt-get", ["apt-get", "update"], ["apt-get", "install", "-y"]),
    "dnf": ("dnf", None, ["dnf", "install", "-y"]),
    "pacman": ("pacman", None, ["pacman", "-S", "--noconfirm", "--needed"]),
    "apk": ("apk", ["apk", "update"], ["apk", "add"]),
}

# --tools names. ripgrep/node/npm ride the package manager; the two
# scanners download pinned release assets.
MANAGER_TOOLS = ("git", "ripgrep", "node", "npm")
DOWNLOAD_TOOLS = ("osv-scanner", "betterleaks")
ALL_TOOLS = (*MANAGER_TOOLS, *DOWNLOAD_TOOLS)

_BINARY = {
    "ripgrep": "rg",
    "git": "git",
    "node": "node",
    "npm": "npm",
    "osv-scanner": "osv-scanner",
    "betterleaks": "betterleaks",
}


class InstallError(RuntimeError):
    """Expected install failure: reported, never a traceback."""


class UnsupportedPlatform(InstallError):
    """OS/arch combo with no known install path."""


def _normalize_arch(machine: str) -> str:
    arch = machine.lower()
    if arch in ("x86_64", "amd64"):
        return "amd64"
    if arch in ("aarch64", "arm64"):
        return "arm64"
    raise UnsupportedPlatform(f"unsupported CPU architecture: {machine}")


def asset_spec(tool: str, system: str, arch: str) -> tuple[str, str]:
    """(download URL, kind) for a scanner; kind is 'file' or 'tarball'.

    Upstream naming quirks live here: betterleaks uses x64 (not
    amd64) and strips the leading v from the version in filenames.
    """
    sysname = system.lower()
    if sysname not in ("linux", "darwin"):
        raise UnsupportedPlatform(f"{tool} has no direct {sysname} asset; use WSL2/Docker")
    if arch not in ("amd64", "arm64"):
        raise UnsupportedPlatform(f"unsupported CPU architecture: {arch}")
    if tool == "osv-scanner":
        name = f"osv-scanner_{sysname}_{arch}"
        base = f"https://github.com/google/osv-scanner/releases/download/{OSV_SCANNER_VERSION}"
        return f"{base}/{name}", "file"
    if tool == "betterleaks":
        bl_arch = "x64" if arch == "amd64" else "arm64"
        bare = BETTERLEAKS_VERSION.lstrip("v")
        name = f"betterleaks_{bare}_{sysname}_{bl_arch}.tar.gz"
        base = f"https://github.com/betterleaks/betterleaks/releases/download/{BETTERLEAKS_VERSION}"
        return f"{base}/{name}", "tarball"
    raise UnsupportedPlatform(f"unknown downloadable tool: {tool}")


def _checksums_url(tool: str, system: str, arch: str) -> tuple[str, str]:
    """(checksums URL, asset filename entry to look up)."""
    url, _ = asset_spec(tool, system, arch)
    asset = url.rsplit("/", 1)[-1]
    base = url.rsplit("/", 1)[0]
    if tool == "osv-scanner":
        return f"{base}/osv-scanner_SHA256SUMS", asset
    return f"{base}/checksums.txt", asset


def verify_payload(payload: bytes, asset: str, checksums_body: str) -> None:
    """Raise unless the published checksums pin this exact asset bytes."""
    want = None
    for line in checksums_body.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == asset:
            want = parts[0]
            break
    if want is None:
        raise InstallError(f"checksums list has no entry for {asset}")
    got = hashlib.sha256(payload).hexdigest()
    if got != want.lower():
        raise InstallError(f"checksum mismatch for {asset}: refusing to install")


def _download(url: str, dest: Path) -> None:
    try:
        with urllib.request.urlopen(  # noqa: S310 - https-only github.com release URLs
            url, timeout=_DOWNLOAD_TIMEOUT_SECONDS
        ) as resp:
            with open(dest, "wb") as fh:
                shutil.copyfileobj(resp, fh)
    except Exception as exc:
        raise InstallError(f"download failed ({url}): {exc}") from exc


def extract_binary(archive: Path, binary: str, dest_dir: Path) -> Path:
    """Find `binary` inside a tarball (mirrors Dockerfile.sandbox's find)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(path=dest_dir, filter="data")
    except (tarfile.TarError, OSError) as exc:
        raise InstallError(f"cannot unpack {archive.name}: {exc}") from exc
    for candidate in sorted(dest_dir.rglob(binary)):
        if candidate.is_file():
            return candidate
    raise InstallError(f"{archive.name} contains no {binary} binary")


def _install_file(source: Path, binary: str, bindir: Path, system: str) -> Path:
    bindir.mkdir(parents=True, exist_ok=True)
    target = bindir / binary
    shutil.copy2(source, target)
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    if system == "darwin" and shutil.which("xattr") is not None:
        # Clear Gatekeeper quarantine on user-downloaded binaries.
        subprocess.run(  # noqa: S603 - fixed argv, presence pre-checked
            ["xattr", "-d", "com.apple.quarantine", str(target)],  # noqa: S607 - same
            capture_output=True,
            check=False,
        )
    return target


def install_downloadable(tool: str, bindir: Path, system: str, arch: str) -> Path:
    """Download, verify, and install one scanner binary."""
    url, kind = asset_spec(tool, system, arch)
    sums_url, asset = _checksums_url(tool, system, arch)
    with tempfile.TemporaryDirectory(prefix="agent-tools-") as tmp:
        tmpdir = Path(tmp)
        asset_path = tmpdir / asset
        sums_path = tmpdir / "checksums"
        print(f"  downloading {asset} ...")
        _download(sums_url, sums_path)
        _download(url, asset_path)
        verify_payload(asset_path.read_bytes(), asset, sums_path.read_text())
        if kind == "tarball":
            source = extract_binary(asset_path, _BINARY[tool], tmpdir / "unpacked")
        else:
            source = asset_path
        return _install_file(source, _BINARY[tool], bindir, system)


def _manager() -> tuple[str, list[str]] | None:
    """First usable package manager: (name, sudo-aware base argv)."""
    for name, (probe, _, _) in _MANAGERS.items():
        if shutil.which(probe) is None:
            continue
        base = [probe] if name == "brew" else [probe]
        return name, base
    return None


def _as_root(argv: list[str], manager: str) -> list[str]:
    if manager == "brew":
        return argv  # brew refuses to run as root
    try:
        rooted = os.geteuid() == 0
    except AttributeError:  # pragma: no cover - non-POSIX
        rooted = False
    if rooted:
        return argv
    if shutil.which("sudo") is None:
        raise InstallError(
            f"need root for {argv[0]} but sudo is missing; "
            f"re-run as root or install manually: {' '.join(argv)}"
        )
    return ["sudo", *argv]


def install_via_manager(tool: str) -> None:
    """Install one everyday tool; raises InstallError with a manual fallback."""
    binary = _BINARY[tool]
    found = _manager()
    if found is None:
        raise InstallError(
            f"no supported package manager (brew/apt/dnf/pacman/apk) for {tool}; "
            f"install {binary} manually, then re-run the doctor"
        )
    name, _ = found
    packages = _MANAGER_PACKAGES[binary].get(name)
    if packages is None:
        raise InstallError(f"no {name} package mapping for {tool}; install {binary} manually")
    _, update, prefix = _MANAGERS[name]
    try:
        if update is not None:
            subprocess.run(  # noqa: S603 - fixed argv from the manager table
                _as_root([*update], name), check=True
            )
        subprocess.run(  # noqa: S603 - fixed argv from the manager table
            _as_root([*prefix, *packages], name), check=True
        )
    except subprocess.CalledProcessError as exc:
        raise InstallError(
            f"{name} failed for {tool}; install manually: {' '.join(prefix)} {' '.join(packages)}"
        ) from exc
    if shutil.which(binary) is None:
        raise InstallError(
            f"{name} reported success but {binary} is still missing; "
            f"install it manually and ensure it is on PATH"
        )


def _print_wsl_guide() -> None:
    print(
        "Windows installs run inside WSL2 (a Unix shell), not natively:\n"
        "  1. In PowerShell (admin): wsl --install -d Ubuntu\n"
        "  2. Reboot, open the Ubuntu shell, then inside the repo:\n"
        "       sudo apt-get update && sudo apt-get install -y git curl\n"
        "       curl -LsSf https://astral.sh/uv/install.sh | sh\n"
        "       uv sync\n"
        "       uv run security-agent-install-tools\n"
        "       uv run security-agent-doctor\n"
        "Native Windows binaries are a deliberate non-goal: the sandbox\n"
        "and scanner paths assume a Unix userspace."
    )


def install_tools_main() -> None:
    """Entry point: install missing host tools, exit 1 on any failure."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Install host tools for Docker-free runs (macOS/Linux; WSL2 on Windows)."
    )
    parser.add_argument(
        "--dir",
        default=str(Path.home() / ".local" / "bin"),
        help="Install dir for downloaded scanners (default: ~/.local/bin).",
    )
    parser.add_argument(
        "--tools",
        default=",".join(ALL_TOOLS),
        help=f"Comma-separated subset of: {','.join(ALL_TOOLS)}.",
    )
    args = parser.parse_args()

    system = platform.system()
    if system == "Windows":
        _print_wsl_guide()
        raise SystemExit(2)
    if system not in ("Linux", "Darwin"):
        print(f"unsupported OS: {system}; macOS and Linux only", file=sys.stderr)
        raise SystemExit(2)
    sysname = system.lower()
    try:
        arch = _normalize_arch(platform.machine())
    except UnsupportedPlatform as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc

    wanted = [t.strip() for t in args.tools.split(",") if t.strip()]
    unknown = [t for t in wanted if t not in ALL_TOOLS]
    if unknown:
        print(f"unknown --tools: {', '.join(unknown)}", file=sys.stderr)
        raise SystemExit(2)

    bindir = Path(args.dir).expanduser()
    failures: list[str] = []
    for tool in wanted:
        binary = _BINARY[tool]
        if shutil.which(binary) is not None:
            print(f"ok   {tool:<12} already on PATH ({shutil.which(binary)})")
            continue
        try:
            if tool in DOWNLOAD_TOOLS:
                target = install_downloadable(tool, bindir, sysname, arch)
                print(f"done {tool:<12} installed to {target}")
            else:
                print(f"  installing {tool} via package manager ...")
                install_via_manager(tool)
                print(f"done {tool:<12} installed ({shutil.which(binary)})")
        except InstallError as exc:
            print(f"FAIL {tool:<12} {exc}")
            failures.append(tool)
    if str(bindir) not in os.environ.get("PATH", "").split(os.pathsep):
        print(f'\nnote: {bindir} is not on PATH; add it (export PATH="{bindir}:$PATH")')
    if failures:
        print(f"\n{len(failures)} tool(s) failed: {', '.join(failures)}")
        raise SystemExit(1)
    print("\nall requested tools present; re-run security-agent-doctor to confirm")
