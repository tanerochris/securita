# Backup / Key Ceremony / Restore Runbook (NFR-9)

## What lives where

- Database dumps (+ non-secret config snapshot) go to `BACKUP_DIR`
  (default `./backups`, a Compose bind mount shared container↔host).
- The per-install master key is NEVER in a backup. It lives only in
  the operator's outside-the-install storage (password manager, HSM,
  sealed envelope). Loss means encrypted fields are unrecoverable and
  every token must be re-entered (NFR-9 D2).

## First boot: key ceremony

1. Start the stack with `MASTER_KEY` unset.
2. The app generates a 32-byte key and shows it **once**:
   - with an operator console attached: printed to `/dev/tty`
     (never to the log stream);
   - headless (Compose): written once to `MASTER_KEY_FILE`
     (default `./master.key`, mode 0600).
3. Copy the key into outside-the-install storage, set `MASTER_KEY` in
   `.env`, delete the `./master.key` copy, restart.
4. Verify: no key bytes in `docker compose logs app` (regression test:
   `tests/unit/test_key_ceremony.py`).

## Backup

```bash
docker compose exec app security-agent-backup            # → prints the manifest path
docker compose exec app security-agent-backup --dest /app/backups
```

- Postgres: `pg_dump --format=custom` (needs `postgresql-client` in
  the image when you run it outside Compose).
- SQLite (dev): online-safe copy via the sqlite backup API.
- Each backup is `agent-<utc>.dump|.db` + `.settings.json` +
  `.manifest.json` (sha256 of each member). Oldest manifests prune
  past `BACKUP_RETENTION_COUNT` (default 14).

## Restore (scratch-stack proof, D3)

Proven pre-launch and re-proven on every release touching storage,
encryption, or backup code. Pass = boots, Owner login works, sample
findings/approvals read, a secret decrypt fires its audit entry.

```bash
# 1. Stop the stack, keep the backup dir + operator-held MASTER_KEY.
docker compose down

# 2. Fresh volumes (scratch stack), same MASTER_KEY in .env.
docker volume rm meta_pgdata
docker compose up -d db
sleep 8

# 3. Restore the manifest (Postgres path shown; SQLite takes --dest).
docker compose run --rm app security-agent-restore \
  /app/backups/agent-<utc>.manifest.json

# 4. Boot and verify.
docker compose up -d app orchestrator executor
# - log in as Owner at $PUBLIC_URL/dashboard
# - open a repo: findings + approvals read correctly
# - rotate/check any repo token view: decrypt fires a `crypto/decrypt`
#   audit entry (query the audit log)
```

Automated SQLite proof: `tests/unit/test_backup.py::test_scratch_stack_restore_proof`
(seed → backup → wipe → restore → login + findings + decrypt audit).

## Release gate (NFR-5 D7)

`pytest tests/security` is the injection fixture suite: hostile repo
content, malicious tool output, poisoned feeds/news, exfil attempts,
and approval-bypass lures must all stay inert. Red blocks the release.
