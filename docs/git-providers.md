# Connecting GitHub / GitLab (PAT-only)

This agent is self-hosted by professionals; it is not a hosted service.
There is therefore **no OAuth app to register, no callback URL to operate,
and nothing needed from GitHub/GitLab beyond a personal access token**.

A user connects a provider account once on the Repositories page
(provider + host URL + PAT), then picks repositories from it — no
per-repo token pasting. Existing per-repo tokens keep working and win
over a linked connection.

## What you need from GitHub

Create one PAT per connecting user (no operator setup):

1. GitHub → Settings → Developer settings → Personal access tokens.
2. Either:
   - **Classic:** scope `repo` (private clone, branch push, PR/issue
     create and merge), or
   - **Fine-grained (preferred):** only the target repos, with
     Contents + Pull requests read/write. Set an expiry you are
     comfortable rotating.
3. Paste it in Repositories → Connected accounts. Host stays
   `https://github.com`; for GitHub Enterprise use
   `https://<your-ghe-host>`.

Tip: a dedicated bot/machine account with a fine-grained token scoped to
the repos under scan is the cleanest setup — its PRs and merges are
clearly attributed and revoking it touches nothing else.

## What you need from GitLab

Create one PAT per connecting user (no operator setup):

1. GitLab → Preferences → Access Tokens.
2. Scope: `api` (merge-request create/merge needs it;
   `read_api` + `write_repository` cannot open MRs).
3. Paste it in Repositories → Connected accounts. Host stays
   `https://gitlab.com`; for self-hosted use `https://<your-gitlab-host>`.

## How it behaves

- Connections belong to the user who created them. Only Owners and
  Maintainers can connect accounts or link them to repos.
- The PAT is validated against the provider (`GET /user`) before it is
  stored, then kept AES-256-GCM encrypted in `encrypted_tokens`
  (`provider-conn:{id}:access`) and never shown again.
- Repo token resolution: per-repo token → linked connection PAT.
- Repo listing shows the first 100 repos, most recently active first.
- **Rotation:** create a fresh PAT and reconnect the same account — the
  stored token is replaced. Then delete the old PAT at the provider.
- **Expiry:** PATs do not refresh. When one expires, provider calls fail
  with 401 until the user reconnects with a fresh token.
- **Disconnect** deletes the stored token locally and unlinks repos
  (their per-repo tokens, if any, keep them scanning). Also delete the
  PAT at the provider — Disconnect here cannot revoke it there.
