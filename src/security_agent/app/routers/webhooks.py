"""Provider webhook receiver: scan triggers + PR-state reconcile (FR-2 D3, FR-5 D5)."""

from fastapi import APIRouter, Header, HTTPException, Request, status

from security_agent.control import repos
from security_agent.db.models import Repo, RepoKind, RunTrigger
from security_agent.db.session import session_scope
from security_agent.worker.deliver import json_loads_maybe, reconcile_pr
from security_agent.worker.scheduler import enqueue_scan

router = APIRouter(prefix="/hooks")

_GITHUB_SCAN_EVENTS = {"push", "pull_request"}
_GITLAB_SCAN_EVENTS = {"Push Hook", "Merge Request Hook"}


def _get_repo(repo_id: int) -> Repo:
    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        if repo is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown repo.")
        db.expunge(repo)
        return repo


@router.post("/github/{repo_id}", status_code=202)
async def github_hook(
    repo_id: int,
    request: Request,
    x_hub_signature_256: str = Header(default=""),
    x_github_event: str = Header(default=""),
):
    if _get_repo(repo_id).kind == RepoKind.LOCAL:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Local repos are poll-only.")
    body = await request.body()
    if not repos.verify_github_signature(repo_id, body, x_hub_signature_256):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bad signature.")
    if x_github_event == "pull_request":
        payload = json_loads_maybe(body)
        pr = payload.get("pull_request", {})
        if payload.get("action") == "closed":
            reconcile_pr(pr.get("html_url", ""), bool(pr.get("merged")), True)
    queued = x_github_event in _GITHUB_SCAN_EVENTS
    if queued:
        enqueue_scan(repo_id, RunTrigger.WEBHOOK, notes=f"github:{x_github_event}")
    return {"queued": queued}


@router.post("/gitlab/{repo_id}", status_code=202)
async def gitlab_hook(
    repo_id: int,
    request: Request,
    x_gitlab_token: str = Header(default=""),
    x_gitlab_event: str = Header(default=""),
):
    if _get_repo(repo_id).kind == RepoKind.LOCAL:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Local repos are poll-only.")
    body = await request.body()
    if not body or not repos.verify_gitlab_token(repo_id, x_gitlab_token):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bad token.")
    if x_gitlab_event == "Merge Request Hook":
        attrs = json_loads_maybe(body).get("object_attributes", {})
        action, state = attrs.get("action"), attrs.get("state")
        if action in ("close", "merge") or state in ("closed", "merged"):
            reconcile_pr(attrs.get("url", ""), action == "merge" or state == "merged", True)
    queued = x_gitlab_event in _GITLAB_SCAN_EVENTS
    if queued:
        enqueue_scan(repo_id, RunTrigger.WEBHOOK, notes=f"gitlab:{x_gitlab_event}")
    return {"queued": queued}
