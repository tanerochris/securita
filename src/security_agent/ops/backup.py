"""Backup + restore (NFR-9 D1/D3): Postgres dumps or SQLite copies + manifest.

Scope: the database (findings, approvals, encrypted fields as-stored)
plus a non-secret config snapshot, written to the operator-provided
BACKUP_DIR bind mount. Key material is NEVER in the backup (D1/D2).
Restore verifies manifest sha256 first and fails closed on mismatch.

Entry points: `security-agent-backup`, `security-agent-restore`.
"""

import hashlib
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger(__name__)

MANIFEST_NAME = "manifest.json"

# Explicitly non-secret settings snapshot. Anything credential-shaped
# stays out by construction: this list can only name safe fields.
_CONFIG_FIELDS = (
    "app_env",
    "app_port",
    "public_url",
    "model_base_url",
    "model_name",
    "bot_name",
    "bot_email",
    "news_hn_query",
    "news_poll_hours",
    "news_classify_enabled",
    "news_classify_max_items",
    "news_mint_enabled",
    "news_relevance_enabled",
    "news_relevance_max_pairs",
    "run_token_cap",
    "run_spend_cap_usd",
    "spend_warn_daily_usd",
    "spend_critical_daily_usd",
    "spend_cap_monthly_usd",
)


class BackupError(RuntimeError):
    """Expected backup/restore failure: loud, no partial state kept."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sqlite_path(db_url: str) -> Path | None:
    if not db_url.startswith("sqlite:///"):
        return None
    return Path(db_url.removeprefix("sqlite:///"))


def _pg_parts(db_url: str) -> dict:
    parsed = urlparse(db_url)
    if parsed.scheme.split("+")[0] != "postgresql":
        raise BackupError(f"Unsupported database scheme for backup: {parsed.scheme}")
    return {
        "host": parsed.hostname or "localhost",
        "port": str(parsed.port or 5432),
        "user": parsed.username or "",
        "password": parsed.password or "",
        "dbname": (parsed.path or "").lstrip("/") or "agent",
    }


def _select_db_file(dest: Path, *, pg: bool) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return dest / f"agent-{stamp}.{'dump' if pg else 'db'}"


def backup(*, dest_dir: str | None = None, db_url: str | None = None) -> dict:
    """Write a timestamped backup; returns the manifest dict."""
    from security_agent.config import get_settings

    settings = get_settings()
    dest = Path(dest_dir or settings.backup_dir or "./backups")
    dest.mkdir(parents=True, exist_ok=True)
    url = db_url or settings.database_url
    sqlite_src = _sqlite_path(url)
    db_file = _select_db_file(dest, pg=sqlite_src is None)
    if sqlite_src is not None:
        if not sqlite_src.exists():
            raise BackupError(f"SQLite source missing: {sqlite_src}")
        try:
            src = sqlite3.connect(f"file:{sqlite_src}?mode=ro", uri=True)
            dst = sqlite3.connect(str(db_file))
            try:
                src.backup(dst)  # online-safe copy, no lock games
            finally:
                dst.close()
                src.close()
        except sqlite3.Error as exc:
            db_file.unlink(missing_ok=True)
            raise BackupError(f"SQLite backup failed: {exc}") from exc
    else:
        pg_dump = shutil.which("pg_dump")
        if pg_dump is None:
            raise BackupError("pg_dump not on PATH; install postgresql-client to back up.")
        parts = _pg_parts(url)
        env = {
            "PATH": os.environ.get("PATH", ""),
            "PGHOST": parts["host"],
            "PGPORT": parts["port"],
            "PGUSER": parts["user"],
            "PGPASSWORD": parts["password"],
            "PGDATABASE": parts["dbname"],
        }
        try:
            subprocess.run(  # noqa: S603 argv list, shell=False, sealed env
                [pg_dump, "-F", "c", "-f", str(db_file)],
                shell=False,
                env=env,
                timeout=3600,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            db_file.unlink(missing_ok=True)
            raise BackupError(f"pg_dump failed: {exc}") from exc
    os.chmod(db_file, 0o600)
    snapshot = {name: getattr(settings, name, "") for name in _CONFIG_FIELDS}
    settings_file = db_file.with_suffix(".settings.json")
    settings_file.write_text(json.dumps(snapshot, indent=2, sort_keys=True))
    os.chmod(settings_file, 0o600)
    manifest = {
        "created_at": datetime.now(UTC).isoformat(),
        "db_file": db_file.name,
        "db_sha256": _sha256(db_file),
        "settings_file": settings_file.name,
        "settings_sha256": _sha256(settings_file),
        "key_note": "master key NOT included: restore needs the operator-held key (NFR-9 D2).",
    }
    manifest_file = db_file.with_suffix(".manifest.json")
    manifest_file.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    os.chmod(manifest_file, 0o600)
    prune(dest)
    log.warning("backup written: %s", manifest_file)
    return {"manifest": str(manifest_file), **manifest}


def prune(dest_dir: str | Path | None = None, *, keep: int | None = None) -> int:
    """Keep the newest `keep` backups; returns manifests removed."""
    from security_agent.config import get_settings

    if keep is None:
        keep = max(1, get_settings().backup_retention_count)
    dest = Path(dest_dir or get_settings().backup_dir or "./backups")
    if not dest.is_dir():
        return 0
    manifests = sorted(dest.glob("*.manifest.json"), key=lambda p: p.stat().st_mtime)
    removed = 0
    for stale in manifests[: max(0, len(manifests) - keep)]:
        stem = stale.name.removesuffix(".manifest.json")
        siblings = (stale, dest / f"{stem}.dump", dest / f"{stem}.db")
        for sibling in (*siblings, dest / f"{stem}.settings.json"):
            try:
                sibling.unlink(missing_ok=True)
            except OSError:
                pass
        removed += 1
    return removed


def _load_manifest(path: Path) -> tuple[dict, Path]:
    try:
        manifest = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise BackupError(f"Cannot read manifest {path}: {exc}") from exc
    if not isinstance(manifest, dict) or "db_sha256" not in manifest or "db_file" not in manifest:
        raise BackupError(f"Manifest {path} is not a security-agent backup.")
    return manifest, path.parent


def restore(manifest_path: str | Path, *, dest: str | Path | None = None) -> dict:
    """Verify + restore a backup. SQLite restores to `dest` (required).

    Postgres restores into the configured database (pg_restore --clean);
    the operator stops the app/worker first (see the runbook).
    """
    from security_agent.config import get_settings

    settings = get_settings()
    manifest, parent = _load_manifest(Path(manifest_path))
    db_file = parent / manifest["db_file"]
    if not db_file.exists() or _sha256(db_file) != manifest["db_sha256"]:
        raise BackupError("Backup failed verification: db sha256 mismatch.")
    settings_name = manifest.get("settings_file")
    settings_digest = manifest.get("settings_sha256")
    if not settings_name or not settings_digest:
        raise BackupError("Backup failed verification: settings manifest missing.")
    settings_path = parent / settings_name
    if not settings_path.exists() or _sha256(settings_path) != settings_digest:
        raise BackupError("Backup failed verification: settings sha256 mismatch.")
    if manifest["db_file"].endswith(".db"):
        if dest is None:
            raise BackupError("SQLite restore needs an explicit destination path.")
        target = Path(dest)
        if target.resolve() == db_file.resolve():
            raise BackupError("Refusing to restore a backup onto itself.")
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=f"{target.name}.", suffix=".tmp", dir=str(target.parent)
        )
        os.close(fd)
        tmp_path = Path(tmp_name)
        try:
            shutil.copyfile(db_file, tmp_path)
            os.replace(tmp_path, target)
        except Exception:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        log.warning("sqlite restored to %s", target)
        return {"status": "restored", "dest": str(target)}
    pg_restore = shutil.which("pg_restore")
    if pg_restore is None:
        raise BackupError("pg_restore not on PATH; install postgresql-client to restore.")
    parts = _pg_parts(settings.database_url)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PGHOST": parts["host"],
        "PGPORT": parts["port"],
        "PGUSER": parts["user"],
        "PGPASSWORD": parts["password"],
        "PGDATABASE": parts["dbname"],
    }
    try:
        subprocess.run(  # noqa: S603 argv list, shell=False, sealed env
            [pg_restore, "--clean", "--if-exists", "--no-owner", str(db_file)],
            shell=False,
            env=env,
            timeout=3600,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        raise BackupError(f"pg_restore failed: {exc}") from exc
    log.warning("postgres restored from %s", db_file)
    return {"status": "restored", "dest": settings.database_url.split("@")[-1]}


def backup_main() -> None:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Write a timestamped agent backup.")
    parser.add_argument("--dest", default=None, help="Backup dir (default: BACKUP_DIR).")
    args = parser.parse_args()
    try:
        outcome = backup(dest_dir=args.dest)
    except BackupError as exc:
        print(f"backup failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(outcome["manifest"])


def restore_main() -> None:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Verify + restore an agent backup.")
    parser.add_argument("manifest", help="Path to *.manifest.json.")
    parser.add_argument("--dest", default=None, help="SQLite destination path.")
    args = parser.parse_args()
    try:
        outcome = restore(args.manifest, dest=args.dest)
    except BackupError as exc:
        print(f"restore failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(json.dumps(outcome))
