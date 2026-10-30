"""Sandbox image entrypoint (follow-up #1).

The disposable sandbox image runs this as its smoke check: it verifies
the pinned scanner binaries are present and executable, then exits.
Per-tool execution happens via fresh `docker run` containers started
by sandbox.tools.run_allowlisted, not via a long-lived daemon, so no
Docker socket is ever mounted into a service.
"""

import shutil
import subprocess  # noqa: S404 - fixed argv, no shell
import sys


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "--exec":
        # Execute one allowlisted tool inside this sandbox container.
        if len(args) < 2:
            print("usage: runner --exec <tool> [args...]", file=sys.stderr)
            return 2
        from security_agent.sandbox.tools import run_allowlisted

        name, rest = args[1], args[2:]
        sys.stdout.write(run_allowlisted(name, rest, check=False))
        return 0
    missing = [b for b in ("betterleaks", "osv-scanner", "git") if shutil.which(b) is None]
    if missing:
        print(f"sandbox image missing binaries: {', '.join(missing)}", file=sys.stderr)
        return 1
    for binary in ("betterleaks", "osv-scanner"):
        proc = subprocess.run(  # noqa: S603 - fixed argv
            [binary, "--version"], capture_output=True, text=True, timeout=30, check=False
        )
        print(f"{binary}: {(proc.stdout or proc.stderr).strip()}")
        if proc.returncode != 0:
            return 1
    print("sandbox-runner ready (fresh disposable container per tool call; see NFR-1/NFR-2)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
