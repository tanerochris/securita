"""PAT-only git-provider connect: service behaviour."""

from datetime import UTC, datetime
from unittest import mock

import pytest
from sqlalchemy import select

from security_agent.app import accounts as accounts_svc
from security_agent.control import git_providers as svc
from security_agent.control import repos as repo_svc
from security_agent.db.models import (
    ConnectionAuth,
    EncryptedToken,
    GitProvider,
    RepoKind,
    Role,
)
from security_agent.db.session import session_scope


def _user() -> int:
    email = f"prov-{datetime.now(UTC).timestamp()}@example.com"
    return accounts_svc.create_user(email, None, Role.OWNER).id


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http error")

    def json(self):
        return self._payload


def _mock_user_get(payload=None):
    return mock.patch.object(
        svc.httpx, "get", return_value=_Resp(payload or {"id": 42, "login": "octo"})
    )


def test_normalize_and_api_base():
    assert svc.normalize_base_url("https://gitlab.example.com/") == "https://gitlab.example.com"
    with pytest.raises(svc.ProviderError):
        svc.normalize_base_url("http://gitlab.example.com")
    with pytest.raises(svc.ProviderError):
        svc.normalize_base_url("notaurl")
    assert svc.api_base(GitProvider.GITHUB, "https://github.com") == "https://api.github.com"
    assert svc.api_base(GitProvider.GITHUB, "https://ghe.example.com") == (
        "https://ghe.example.com/api/v3"
    )
    assert svc.api_base(GitProvider.GITLAB, "https://gitlab.com") == "https://gitlab.com/api/v4"


def test_no_oauth_surface():
    for name in ("authorize_url", "complete_oauth", "make_state", "oauth_configured"):
        assert not hasattr(svc, name), name


def test_reconnect_rotates_stored_token():
    user_id = _user()
    with _mock_user_get():
        conn = svc.connect_pat(user_id, GitProvider.GITHUB, "", "old-token")
    with _mock_user_get():
        again = svc.connect_pat(user_id, GitProvider.GITHUB, "", "new-token")
    assert again.id == conn.id
    assert svc.get_valid_token(conn.id) == "new-token"
    assert len(svc.list_connections(user_id)) == 1


def test_connect_pat_validates_and_stores_encrypted():
    user_id = _user()
    with _mock_user_get():
        conn = svc.connect_pat(user_id, GitProvider.GITHUB, "", "ghp_test_token")
    assert conn.auth_type == ConnectionAuth.PAT and conn.username == "octo"
    with session_scope() as db:
        rows = list(
            db.scalars(
                select(EncryptedToken).where(
                    EncryptedToken.owner.like(f"provider-conn:{conn.id}:%")
                )
            )
        )
        assert rows and all(r.ciphertext != "ghp_test_token" for r in rows)
    assert svc.get_valid_token(conn.id) == "ghp_test_token"
    assert [c.id for c in svc.list_connections(user_id)] == [conn.id]


def test_connect_pat_rejects_bad_token():
    user_id = _user()
    with mock.patch.object(svc.httpx, "get", return_value=_Resp({}, status=401)):
        with pytest.raises(svc.ProviderError):
            svc.connect_pat(user_id, GitProvider.GITLAB, "", "bad-token")
    assert svc.list_connections(user_id) == []


def test_list_provider_repos_github():
    user_id = _user()
    with _mock_user_get():
        conn = svc.connect_pat(user_id, GitProvider.GITHUB, "", "tok")
    payload = [
        {
            "full_name": "octo/api",
            "clone_url": "https://github.com/octo/api.git",
            "private": True,
            "default_branch": "main",
        }
    ]
    with mock.patch.object(svc.httpx, "get", return_value=_Resp(payload)):
        found = svc.list_provider_repos(conn.id, user_id)
    assert found[0]["full_name"] == "octo/api" and found[0]["private"] is True
    with pytest.raises(svc.ProviderError):
        svc.list_provider_repos(conn.id, user_id + 999)


def test_repo_token_falls_back_to_connection():
    user_id = _user()
    with _mock_user_get():
        conn = svc.connect_pat(user_id, GitProvider.GITHUB, "", "conn-token")
    repo = repo_svc.connect_repo(
        f"linked-{datetime.now(UTC).timestamp()}",
        RepoKind.GIT,
        url="https://github.com/octo/api.git",
        connection_id=conn.id,
    )
    assert repo_svc.get_repo_token(repo.id) == "conn-token"
    repo_svc.store_repo_token(repo.id, "per-repo-token")
    assert repo_svc.get_repo_token(repo.id) == "per-repo-token"

    assert svc.disconnect(conn.id, user_id) is True
    assert svc.get_connection(conn.id) is None
    # Disconnect clears the link; the per-repo token keeps the repo working.
    assert repo_svc.get_repo_token(repo.id) == "per-repo-token"
    with session_scope() as db:
        from security_agent.db.models import Repo

        assert db.get(Repo, repo.id).connection_id is None


def test_connect_repo_rejects_unknown_connection():
    with pytest.raises(ValueError, match="Unknown provider connection"):
        repo_svc.connect_repo(
            "bad-link", RepoKind.GIT, url="https://example.com/x.git", connection_id=999999
        )
