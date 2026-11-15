# Agent Key Rotation Runbook

Agent provider keys are org-level, Owner-managed in Settings → Agent.
One key per configured provider; scans, workers, and chat all use it.

## What lives where

- Selection (strategy, model, base URL, price override) lives in the
  `notify_state` table under `agent.*` keys (plaintext-safe).
- Keys live in `encrypted_tokens` under `agent:<strategy>`, AES-256-GCM
  under the per-install master key — the same pattern as git PATs and
  notify secrets. Keys are pasted once and never re-viewed: not in the
  UI, API, logs, or the backup config snapshot.
- Backups include the database as-stored (selection + ciphertext), so a
  restore brings the agent config back; it never includes the master
  key (see `backup-restore.md`).

## Rotate a provider key

1. Create the new key at the provider (OpenRouter, Vercel, Google,
   Anthropic, …). Do not revoke the old one yet.
2. As Owner, open Settings → Agent, paste the new key, Save. Saving a
   key replaces the stored one (audit-logged as `rotated`).
3. Click **Test saved agent**: a pass proves auth + chat + native tool
   calls on the new key.
4. Revoke the old key at the provider.

Saves store as-is with no probe, so a bad paste surfaces as a loud
agent error at runtime (runs park, chat/news show it) — never silently.

## Delete a provider key

Settings → Agent → **Delete key** (Owner-only, confirm-guarded,
audit-logged). AI steps fail loud until a new key is pasted; non-AI
scanning is unaffected.

## Lost master key

Encrypted fields are unrecoverable: every agent key must be re-pasted
after a fresh key ceremony (see `backup-restore.md`, NFR-9 D2).
Selection (`agent.*`) survives — only the keys need re-entry.

## Upgrade note

Legacy `MODEL_*` env vars import once into Settings on upgrade (strategy
is guessed from the old base URL), then env is ignored. After the
import, rotate the key through Settings so the old env value is dead.
