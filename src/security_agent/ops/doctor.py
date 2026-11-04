"""Local-run preflight: what a Docker-free install needs.

Side-effect-free by design: binary probes, one SELECT 1, settings
reads. No network, no model downloads, no schema writes. Exit 0 when
every required check passes, 1 otherwise.
"""

import shutil
import sys
from dataclasses import dataclass


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    required: bool
    hint: str


def _binary(binary: str, *, name: str = "", required: bool, hint: str) -> Check:
    label = name or binary
    found = shutil.which(binary)
    if found:
        return Check(label, True, found, required, "")
    return Check(label, False, "not on PATH", required, hint)


def _python() -> Check:
    ok = sys.version_info >= (3, 12)
    detail = ".".join(map(str, sys.version_info[:3]))
    return Check("python", ok, detail, True, "install Python 3.12+ (uv python install 3.12)")


def _database() -> Check:
    from sqlalchemy import text

    from security_agent.config import get_settings
    from security_agent.db.session import get_engine

    url = get_settings().database_url
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - detail is the report
        return Check("database", False, f"{url} unreachable: {exc}", True, "")
    dialect = url.split(":", 1)[0]
    return Check("database", True, f"{dialect} reachable ({url})", True, "")


def _model_key() -> Check:
    from security_agent.config import get_settings

    if get_settings().model_api_key:
        return Check("model-api-key", True, "set", False, "")
    return Check(
        "model-api-key",
        False,
        "unset: AI-written patches/summaries fall back to templates",
        False,
        "set MODEL_API_KEY in .env for full AI function",
    )


def _sandbox() -> Check:
    from security_agent.config import get_settings

    raw = get_settings().sandbox_backend
    if shutil.which("docker") and raw.strip().lower() in ("auto", "docker"):
        return Check("sandbox", True, "docker backend available", False, "")
    return Check("sandbox", True, "host execution (no docker CLI/image)", False, "")


def run_checks() -> list[Check]:
    """Ordered preflight checks; required failures block a local run."""
    return [
        _python(),
        _database(),
        _binary(
            "git",
            required=True,
            hint="install git (xcode-select --install / apt install git)",
        ),
        _binary(
            "rg",
            name="ripgrep",
            required=True,
            hint="install ripgrep (brew install ripgrep / apt install ripgrep)",
        ),
        _binary(
            "osv-scanner",
            required=True,
            hint="download from github.com/google/osv-scanner/releases (vuln findings need it)",
        ),
        _binary(
            "betterleaks",
            required=True,
            hint="download the v2 release from github.com/betterleaks/betterleaks/releases",
        ),
        _binary(
            "node",
            required=False,
            hint="install node for JS lockfile generation (nodejs.org / brew install node)",
        ),
        _binary(
            "npm",
            required=False,
            hint="ships with node; needed to generate missing package-lock.json files",
        ),
        _model_key(),
        _sandbox(),
    ]


def doctor_main() -> None:
    checks = run_checks()
    width = max(len(c.name) for c in checks)
    for check in checks:
        status = "ok  " if check.ok else ("MISS" if check.required else "warn")
        line = f"{status} {check.name:<{width}}  {check.detail}"
        if not check.ok and check.hint:
            line += f" — {check.hint}"
        print(line)
    missing = [c.name for c in checks if c.required and not c.ok]
    if missing:
        print(f"\nlocal run blocked: install {', '.join(missing)} (or run with Docker)")
        raise SystemExit(1)
    print("\nlocal run ready")
