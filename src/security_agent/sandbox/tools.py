"""Narrow @tool wrappers with allowlisted argv (FR-14, NFR-5 D6).

Every scanner is a structured tool: schema-checked args, fixed argv prefix,
subprocess with shell=False, every invocation audit-logged. Anything outside
the manifest fails closed.
"""

import os
import re
import shlex
import subprocess
import tempfile
import threading

from langchain_core.tools import tool

from security_agent.audit import get_shared_log

audit = get_shared_log()

MANIFEST: dict[str, list[str]] = {
    "osv-scanner": ["osv-scanner", "scan"],
    # Betterleaks v2 CLI: subcommand per call (fs/git/stdin/validate);
    # there is no `scan` subcommand. Callers pass the full argv tail.
    "betterleaks": ["betterleaks"],
    "ripgrep": ["rg", "--no-heading", "--line-number"],
    "git": ["git"],
    "npm": ["npm"],
    # Dependency freshness (D4/D12): native PM CLIs only — no registry
    # HTTP from the host/worker. Binaries ship in the sandbox image
    # (corepack shims for yarn/pnpm, pinned pip installs for the Python
    # managers); every call needs allow_network.
    "yarn": ["yarn"],
    "pnpm": ["pnpm"],
    "uv": ["uv"],
    # Python lockfile refresh (D8/D12): re-lock only, never installs
    # into the repo. Callers pass the narrow argv per lock kind.
    "poetry": ["poetry"],
    "pdm": ["pdm"],
    "pipenv": ["pipenv"],
    # `pip index versions <pkg>` — metadata read only, never installs.
    "pip-index": ["python3", "-m", "pip", "index", "versions"],
    # Test-dep installs only (FR-7 D4). Wheels-only (no sdist setup.py ever
    # runs), no prompts, no version-check phone-home, no shared cache.
    "pip-install": [
        "python3",
        "-m",
        "pip",
        "install",
        "--no-input",
        "--disable-pip-version-check",
        "--only-binary",
        ":all:",
        "--no-cache-dir",
    ],
    "pytest": ["python3", "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"],
}


TOOL_TIMEOUT_SECONDS = 120
MAX_OUTPUT_CHARS = 1_000_000
MAX_SCANNER_OUTPUT_CHARS = 25_000_000  # real OSV JSON runs ~2MB per 100 vuln pkgs
MAX_CONCURRENT_TOOLS = 4

_tools_sem = threading.BoundedSemaphore(MAX_CONCURRENT_TOOLS)

# Tools run hostile repo code (pytest suites, npm scripts), so children get
# an allowlisted environment: safe operational vars only. Secrets such as
# MASTER_KEY and DATABASE_URL never reach the child, even by accident.
_CHILD_ENV_KEYS = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "TMPDIR",
        "TEMP",
        "TMP",
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
        "LC_NUMERIC",
        "LC_TIME",
        "TZ",
        "TERM",
        "NO_COLOR",
        "CI",
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "SSH_CONNECTION",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_TERMINAL_PROMPT",
        "GIT_ASKPASS",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "SYSTEMROOT",  # Windows toolchains resolve system DLLs through this
    }
)
_CHILD_ENV_PREFIXES = ("LC_", "GIT_", "SSH_", "NPM_CONFIG_", "UV_", "PIP_", "PYTHON", "XDG_")
_SECRET_ENV_RE = re.compile(r"KEY|TOKEN|SECRET|PASSW|CRED|PRIVATE|AUTH")


def _sanitize_child_env(env: dict[str, str] | None) -> dict[str, str]:
    """Allowlisted child environment: safe inherited vars plus caller keys.

    Caller keys matching secret-name patterns are refused loudly; the
    explicit allowlist above wins for operational names such as GIT_ASKPASS.
    """
    child = {
        key: value
        for key, value in os.environ.items()
        if key in _CHILD_ENV_KEYS or key.startswith(_CHILD_ENV_PREFIXES)
    }
    if env:
        for key in env:
            if _SECRET_ENV_RE.search(key.upper()):
                raise ValueError(f"Refusing secret-pattern env key {key!r}.")
        child.update(env)
    return child


def _read_head(stream, limit: int) -> str:
    """First limit chars of a spooled tool stream (bounded, lossy decode)."""
    try:
        stream.seek(0)
        chunk = stream.read(limit + 1)
    except OSError:
        return ""
    return chunk.decode("utf-8", "replace")[:limit]


def _docker_command(
    argv: list[str],
    *,
    cwd: str | None,
    child_env: dict[str, str],
    stdin_data: str | None,
    allow_network: bool,
) -> tuple[list[str], str | None]:
    """Fresh disposable container per tool call (follow-up #1).

    The workdir is shared at /work and paths under it in argv and env are
    rewritten, so callers keep using worker paths. No worker secrets are
    forwarded: child_env is already allowlist-sanitized.
    Network is off unless the caller explicitly needs egress (git clone).

    Sharing goes through the named work volume, never a host bind: the
    daemon resolves bind sources on ITS host, where worker-container
    paths like /sandbox-work do not exist (Docker Desktop refuses with
    "mounts denied"; Linux would mount a silently empty dir). Only
    workdirs under SANDBOX_WORK_ROOT take the volume path; anything
    else keeps the legacy bind mount.
    """
    import os
    import shutil

    from security_agent.config import get_settings
    from security_agent.sandbox import resolve_backend

    if resolve_backend() != "docker":
        return argv, None
    if shutil.which("docker") is None:
        raise PermissionError("Docker sandbox backend selected but docker CLI is unavailable.")
    settings = get_settings()
    image = getattr(settings, "sandbox_image", "security-agent-sandbox:latest")
    network = getattr(settings, "sandbox_network", "none") or "none"
    if allow_network and network == "none":
        network = "bridge"
    root = getattr(settings, "sandbox_work_root", "") or ""
    root = root.strip() if isinstance(root, str) else ""
    volume = getattr(settings, "sandbox_work_volume", "") or ""
    volume = volume.strip() if isinstance(volume, str) else ""
    work = cwd
    scratch: str | None = None
    if work is None:
        scratch = tempfile.mkdtemp(prefix="sandbox-cwd-", dir=root or None)
        work = scratch

    def rewrite(value: str) -> str:
        if cwd and (value == cwd or value.startswith(cwd.rstrip("/") + "/")):
            return "/work" + value[len(cwd) :]
        return value

    # Volume share only when the workdir is really contained in the shared
    # root (normalized, so /sandbox-work/../etc cannot become a subpath).
    subpath: str | None = None
    if root and volume and work:
        norm_root, norm_work = os.path.normpath(root), os.path.normpath(work)
        if norm_work == norm_root:
            subpath = ""
        elif norm_work.startswith(norm_root.rstrip("/") + "/"):
            subpath = os.path.relpath(norm_work, norm_root)
    if subpath is None:
        mount_argv = ["-v", f"{work}:/work"]
    elif subpath in ("", "."):
        mount_argv = ["--mount", f"type=volume,src={volume},dst=/work"]
    else:
        mount_argv = ["--mount", f"type=volume,src={volume},dst=/work,volume-subpath={subpath}"]

    docker_argv = [
        "docker",
        "run",
        "--rm",
        "--network",
        network,
        "--memory",
        "1g",
        "--cpus",
        "1",
        "--pids-limit",
        "256",
        *mount_argv,
        "-w",
        "/work",
    ]
    if stdin_data is not None:
        docker_argv.append("-i")
    for key in sorted(child_env):
        if key in ("PATH", "HOME"):
            continue
        docker_argv += ["-e", f"{key}={rewrite(child_env[key])}"]
    docker_argv.append(image)
    docker_argv += [rewrite(a) for a in argv]
    return docker_argv, scratch


def run_allowlisted(
    name: str,
    args: list[str],
    *,
    cwd: str | None = None,
    timeout: int = TOOL_TIMEOUT_SECONDS,
    redact: tuple[str, ...] = (),
    check: bool = True,
    success_codes: tuple[int, ...] = (0,),
    max_output: int = MAX_OUTPUT_CHARS,
    env: dict[str, str] | None = None,
    stdin_data: str | None = None,
    allow_network: bool = False,
) -> str:
    """Run a manifest tool. Unknown tools fail closed; timeouts fail loud.

    With check=False, non-zero exits return combined output instead of
    raising, so callers can compare baseline vs post-change test runs.
    success_codes declares meaningful non-zero exits (e.g. osv-scanner's
    1-for-findings) whose stdout returns normally. max_output raises the
    truncation cap for known-large tools (scanner JSON). Streams spool to
    temp files and only the head is read back, so a chatty tool cannot spike
    worker memory. env merges over the allowlisted child environment;
    callers build it from internal paths only, never from repo content,
    and only key names are audit-logged. stdin_data pipes text to the
    child (data, never argv); only its byte length is audit-logged.
    """
    if name not in MANIFEST:
        raise PermissionError(f"Tool {name!r} is outside the manifest; failing closed.")
    argv = MANIFEST[name] + [a for a in args if a]
    line = " ".join(argv)
    for secret in redact:
        if secret:
            line = line.replace(secret, "***")
    if env:
        line += f" [env {','.join(sorted(env))}]"
    stdin_bytes = stdin_data.encode() if stdin_data is not None else None
    if stdin_bytes is not None:
        line += f" [stdin {len(stdin_bytes)}b]"
    audit.append(action_class="tool", decision="allow", line=line)
    child_env = _sanitize_child_env(env)  # before acquire: never leaks a slot
    exec_argv, scratch_cwd = _docker_command(
        argv, cwd=cwd, child_env=child_env, stdin_data=stdin_data, allow_network=allow_network
    )
    exec_cwd = None if exec_argv is not argv else cwd
    if not _tools_sem.acquire(timeout=timeout):
        raise TimeoutError(f"{name} queued too long; worker slots are full.")
    try:
        with (
            tempfile.TemporaryFile(mode="w+b") as out_file,
            tempfile.TemporaryFile(mode="w+b") as err_file,
        ):
            try:
                proc = subprocess.run(  # noqa: S603 manifest-allowlisted argv, shell=False
                    exec_argv,
                    shell=False,
                    input=stdin_bytes,
                    stdout=out_file,
                    stderr=err_file,
                    cwd=exec_cwd,
                    timeout=timeout,
                    env=child_env if exec_cwd is not None or exec_argv is argv else None,
                )
            except subprocess.TimeoutExpired as exc:
                raise TimeoutError(f"{name} timed out after {timeout}s") from exc
            stdout = _read_head(out_file, max_output)
            if proc.returncode not in success_codes:
                if not check:
                    stderr = _read_head(err_file, max_output)
                    return f"[exit {proc.returncode}]\n{stderr}\n{stdout}"[:max_output]
                raise RuntimeError(
                    f"{name} failed ({proc.returncode}): {_read_head(err_file, 500)}"
                )
            return stdout
    finally:
        _tools_sem.release()
        if scratch_cwd:
            import shutil

            shutil.rmtree(scratch_cwd, ignore_errors=True)


@tool
def osv_scan(lockfile_dir: str) -> str:
    """Scan a lockfile directory with osv-scanner; returns JSON (FR-2)."""
    return run_allowlisted(
        "osv-scanner",
        ["--lockfile", f"{lockfile_dir}/package-lock.json", "--format", "json"],
        success_codes=(0, 1),
        max_output=MAX_SCANNER_OUTPUT_CHARS,
    )


@tool
def secrets_scan(repo_dir: str) -> str:
    """Scan a workdir for leaked secrets with Betterleaks (FR-8)."""
    return run_allowlisted(
        "betterleaks",
        ["fs", repo_dir, "--validate", "--output", "-"],
        success_codes=(0, 1),
        max_output=MAX_SCANNER_OUTPUT_CHARS,
    )


@tool
def code_search(pattern: str, repo_dir: str) -> str:
    """Search first-party code (reachability helper, FR-3)."""
    if not pattern or pattern.startswith("-"):
        raise ValueError("Refusing suspicious search pattern.")
    return run_allowlisted("ripgrep", [pattern, repo_dir])


def argv_preview(name: str, args: list[str]) -> str:
    """Quoted argv preview for audit display (never executed from here)."""
    return shlex.join(MANIFEST[name] + args)
