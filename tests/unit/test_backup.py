"""H6 Slice D: backup/restore proof + key ceremony (NFR-9 D1/D2/D3)."""

import json
from datetime import UTC, datetime
from unittest import mock

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from security_agent.app.accounts import hash_password, verify_password
from security_agent.crypto import decrypt_field, encrypt_field
from security_agent.db.models import (
    Approval,
    Base,
    EncryptedToken,
    Finding,
    FindingStatus,
    GateAction,
    Repo,
    RepoKind,
    Role,
    User,
)
from security_agent.ops.backup import BackupError, backup, prune, restore


def _seed(path) -> str:
    """Scratch-stack source DB: owner login + finding + approval + token."""
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    key = __import__("security_agent.db.keys", fromlist=["get_encryption_key"]).get_encryption_key()
    with factory() as db:
        db.add(
            User(
                email="owner@example.com",
                password_hash=hash_password("owner-password-12"),
                role=Role.OWNER,
            )
        )
        db.add(Repo(name="r", kind=RepoKind.GIT, url="https://example.com/r.git"))
        db.flush()
        repo_id = db.scalar(select(Repo.id))
        db.add(
            Finding(
                repo_id=repo_id,
                package="left-pad",
                installed_version="1.0.0",
                advisory_id="CVE-PROOF",
                status=FindingStatus.OPEN,
            )
        )
        db.add(
            Approval(
                repo_id=repo_id,
                action=GateAction.MERGE,
                target="https://example.com/pr/1",
                expires_at=datetime.now(UTC),
            )
        )
        db.add(EncryptedToken(owner="repo-token:1", ciphertext=encrypt_field("tok-value", key)))
        db.commit()
    engine.dispose()
    return url


def test_scratch_stack_restore_proof(tmp_path):
    """D3: seed → backup → wipe → restore → login + findings + decrypt audit."""
    src = tmp_path / "src.db"
    url = _seed(src)
    dest = tmp_path / "backups"
    outcome = backup(dest_dir=str(dest), db_url=url)
    manifest_file = dest / f"{outcome['db_file'].removesuffix('.db')}.manifest.json"
    assert manifest_file.exists()
    manifest = json.loads(manifest_file.read_text())
    assert "master key NOT included" in manifest["key_note"]
    settings = json.loads((dest / manifest["settings_file"]).read_text())
    blob = json.dumps(settings)
    for leaked in ("MASTER_KEY", "MODEL_API_KEY", "PASSWORD", "SECRET", "BEGIN "):
        assert leaked not in blob.upper()
    src.unlink()  # the disaster
    restored = tmp_path / "restored.db"
    assert restore(manifest_file, dest=restored)["status"] == "restored"

    engine = create_engine(f"sqlite:///{restored}")
    factory = sessionmaker(bind=engine)
    from security_agent.audit import get_shared_log

    before = len(get_shared_log().query(action_class="crypto"))
    with factory() as db:
        user = db.scalar(select(User).where(User.email == "owner@example.com"))
        assert user is not None and verify_password(user.password_hash, "owner-password-12")
        assert db.scalar(select(Finding).where(Finding.advisory_id == "CVE-PROOF")) is not None
        assert db.scalar(select(Approval)) is not None
        token = db.scalar(select(EncryptedToken).where(EncryptedToken.owner == "repo-token:1"))
        key = __import__(
            "security_agent.db.keys", fromlist=["get_encryption_key"]
        ).get_encryption_key()
        assert decrypt_field(token.ciphertext, key, purpose="proof") == "tok-value"
    engine.dispose()
    assert len(get_shared_log().query(action_class="crypto")) == before + 1


def test_restore_refuses_tampered_backup(tmp_path):
    src = tmp_path / "src.db"
    url = _seed(src)
    dest = tmp_path / "backups"
    outcome = backup(dest_dir=str(dest), db_url=url)
    manifest_file = dest / f"{outcome['db_file'].removesuffix('.db')}.manifest.json"
    with open(dest / outcome["db_file"], "r+b") as fh:
        fh.seek(100)
        fh.write(b"tampered")
    with pytest.raises(BackupError, match="sha256 mismatch"):
        restore(manifest_file, dest=tmp_path / "x.db")


def test_restore_refuses_self_and_missing_source(tmp_path):
    with pytest.raises(BackupError, match="Cannot read manifest"):
        restore(tmp_path / "nope.json", dest=tmp_path / "x.db")
    with pytest.raises(BackupError, match="SQLite source missing"):
        backup(dest_dir=str(tmp_path), db_url="sqlite:///nonexistent-dir/x.db")


def test_prune_keeps_newest_n(tmp_path):
    import time

    dest = tmp_path / "b"
    dest.mkdir()
    for i in range(4):
        (dest / f"agent-{i}.manifest.json").write_text("{}")
        (dest / f"agent-{i}.db").write_text("x")
        time.sleep(0.01)
    assert prune(dest, keep=2) == 2
    assert len(list(dest.glob("*.manifest.json"))) == 2
    assert len(list(dest.glob("*.db"))) == 2


def test_pg_path_fails_loud_without_binaries():
    pg_url = "postgresql+psycopg://u:p@db:5432/agent"
    with mock.patch("shutil.which", return_value=None):
        with pytest.raises(BackupError, match="pg_dump not on PATH"):
            backup(dest_dir="/tmp", db_url=pg_url)


def test_pg_dump_argv_never_carries_credentials(tmp_path):
    """Password travels via env (sealed), never argv or logs."""
    pg_url = "postgresql+psycopg://u:s3cret@db:5432/agent"
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["env"] = kwargs.get("env", {})
        (tmp_path / "agent-x.dump").write_text("dump")
        return mock.Mock()

    with (
        mock.patch("shutil.which", return_value="/usr/bin/pg_dump"),
        mock.patch("subprocess.run", side_effect=fake_run),
        mock.patch(
            "security_agent.ops.backup._select_db_file", return_value=tmp_path / "agent-x.dump"
        ),
    ):
        with mock.patch("security_agent.ops.backup.prune", return_value=0):
            backup(dest_dir=str(tmp_path), db_url=pg_url)
    assert "s3cret" not in json.dumps(seen["argv"])
    assert seen["env"]["PGPASSWORD"] == "s3cret"
    assert set(seen["env"]) <= {"PATH", "PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE"}
