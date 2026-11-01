"""Standalone security-news feed (FR-6 intel)."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from security_agent.app.dependencies import get_current_user, make_csrf
from security_agent.db.models import User
from security_agent.worker.news_intel import (
    list_feed,
    relevance_repo_tags,
    repo_relevance_map,
    repo_tags,
)

router = APIRouter()

_FEED_LIMIT = 100


@router.get("/news", response_class=HTMLResponse)
def news_feed(request: Request, repo: int | None = None, user: User = Depends(get_current_user)):
    """Classified security stories, tagged by the repos they matter to.

    The global feed is major-impact only. `?repo=<id>` localizes it:
    only stories assessed relevant to that repository (directly to its
    code, or to a platform it can be deployed to), most relevant first.
    """
    from security_agent.app.main import templates

    items = list_feed(repo_id=repo)
    tags = repo_tags([i.id for i in items])
    relevance_tags = relevance_repo_tags([i.id for i in items])
    relevance = repo_relevance_map([i.id for i in items], repo) if repo is not None else {}
    repo_name = None
    if repo is not None:
        from security_agent.db.models import Repo
        from security_agent.db.session import session_scope

        with session_scope() as db:
            found = db.get(Repo, repo)
            repo_name = found.name if found is not None else f"repo#{repo}"
    return templates.TemplateResponse(
        request,
        "news.html",
        {
            "user": user,
            "csrf": make_csrf(),
            "items": items,
            "tags": tags,
            "relevance_tags": relevance_tags,
            "relevance": relevance,
            "repo_filter": repo,
            "repo_name": repo_name,
        },
    )
