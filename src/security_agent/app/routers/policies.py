"""Policy dashboard: platform/repo docs, guardrail queue, preview (D9).

Reads are open to every signed-in role (Developers/Reporters see what
governs them); every write needs Owner/Maintainer via require_approver.
"""

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse

from security_agent.app.dependencies import (
    get_current_user,
    make_csrf,
    require_approver,
    require_csrf,
)
from security_agent.db.models import Role, User
from security_agent.policy.constants import EFFECTS, POLICY_TASKS

router = APIRouter()

_ALLOWED_SUFFIXES = {".md", ".markdown", ".txt", ".rst", ".pdf"}


def _redirect(target: str, notice: str) -> RedirectResponse:
    from urllib.parse import quote

    return RedirectResponse(f"{target}?notice={quote(notice)}", status_code=303)


def _back_to(scope: str, repo_id: int | None) -> str:
    if scope == "repo" and repo_id:
        return f"/repos/{repo_id}/policies"
    return "/policies"


def _redirect_back(scope: str, repo_id: int | None, next: str, notice: str) -> RedirectResponse:
    if next == "/policies":
        return _redirect("/policies", notice)
    return _redirect(_back_to(scope, repo_id), notice)


def _tasks_form(tasks: list[str]) -> list[str] | None:
    picked = [t for t in tasks if t in POLICY_TASKS]
    return picked or None


def _match_form(package: str, advisory: str, ecosystem: str, max_severity: str) -> dict:
    match: dict = {}
    if package.strip():
        match["package"] = package.strip()
    if advisory.strip():
        match["advisory"] = advisory.strip()
    if ecosystem.strip():
        match["ecosystem"] = ecosystem.strip()
    if max_severity.strip():
        try:
            match["max_severity"] = float(max_severity.strip())
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "Max severity must be a number 0-10."
            ) from exc
    return match


def _page_context(request: Request, user: User, *, notice: str = "") -> dict:
    from types import SimpleNamespace

    from security_agent.control.repos import list_repos
    from security_agent.policy.rules import list_rules
    from security_agent.policy.service import list_documents

    all_rules = list_rules()
    rules = [r for r in all_rules if r.scope == "platform"]
    repo_rules = [r for r in all_rules if r.scope == "repo"]
    all_docs = list_documents()
    docs = [d for d in all_docs if d.scope == "platform"]
    repo_docs = [d for d in all_docs if d.scope == "repo"]
    repos = list_repos()
    repo_by_id = {r.id: r for r in repos}
    repo_groups: list[dict] = []
    for repo in repos:
        pending = [r for r in repo_rules if r.repo_id == repo.id and r.status == "pending"]
        confirmed = [r for r in repo_rules if r.repo_id == repo.id and r.status == "confirmed"]
        rdocs = [d for d in repo_docs if d.repo_id == repo.id]
        if pending or confirmed or rdocs:
            repo_groups.append(
                {
                    "repo": repo,
                    "missing": False,
                    "pending": pending,
                    "confirmed": confirmed,
                    "docs": rdocs,
                }
            )
    orphan_ids = sorted(
        {r.repo_id for r in repo_rules if r.repo_id is not None and r.repo_id not in repo_by_id}
        | {d.repo_id for d in repo_docs if d.repo_id is not None and d.repo_id not in repo_by_id}
    )
    for rid in orphan_ids:
        repo_groups.append(
            {
                "repo": SimpleNamespace(id=rid, name=f"Repo #{rid} (removed)"),
                "missing": True,
                "pending": [r for r in repo_rules if r.repo_id == rid and r.status == "pending"],
                "confirmed": [
                    r for r in repo_rules if r.repo_id == rid and r.status == "confirmed"
                ],
                "docs": [d for d in repo_docs if d.repo_id == rid],
            }
        )
    return {
        "docs": docs,
        "rules": rules,
        "pending": [r for r in rules if r.status == "pending"],
        "confirmed": [r for r in rules if r.status == "confirmed"],
        "disabled_rules": [r for r in rules if r.status == "disabled"],
        "repo_groups": repo_groups,
        "repo_pending_total": len([r for r in repo_rules if r.status == "pending"]),
        "effects": [e for e in EFFECTS if e != "allow"],
        "tasks": POLICY_TASKS,
        "notice": notice,
        "can_manage": user.role in (Role.OWNER, Role.MAINTAINER),
        "csrf": make_csrf(),
    }


@router.get("/policies", response_class=HTMLResponse)
def platform_policies(request: Request, user: User = Depends(get_current_user)):
    from security_agent.app.main import templates

    return templates.TemplateResponse(
        request,
        "policies.html",
        _page_context(request, user, notice=request.query_params.get("notice", "")),
    )


@router.get("/repos/{repo_id}/policies", response_class=HTMLResponse)
def repo_policies(request: Request, repo_id: int, user: User = Depends(get_current_user)):
    from security_agent.app.main import templates
    from security_agent.db.models import Repo
    from security_agent.db.session import session_scope
    from security_agent.policy.rules import list_rules
    from security_agent.policy.service import list_documents

    with session_scope() as db:
        repo = db.get(Repo, repo_id)
        if repo is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown repo.")
        db.expunge(repo)
    docs = list_documents(scope="repo", repo_id=repo_id)
    platform_docs = list_documents(scope="platform")
    rules = [r for r in list_rules() if r.scope == "repo" and r.repo_id == repo_id]
    platform_rules = [r for r in list_rules(status="confirmed") if r.scope == "platform"]
    return templates.TemplateResponse(
        request,
        "repo_policies.html",
        {
            "repo": repo,
            "docs": docs,
            "platform_docs": platform_docs,
            "rules": rules,
            "pending": [r for r in rules if r.status == "pending"],
            "confirmed": [r for r in rules if r.status == "confirmed"],
            "platform_rules": platform_rules,
            "effects": [e for e in EFFECTS if e != "allow"],
            "tasks": POLICY_TASKS,
            "notice": request.query_params.get("notice", ""),
            "can_manage": user.role in (Role.OWNER, Role.MAINTAINER),
            "csrf": make_csrf(),
        },
    )


@router.post("/policies/upload", dependencies=[Depends(require_csrf)])
async def upload(
    scope: str = Form(...),
    repo_id: str = Form(""),
    title: str = Form(""),
    tasks: list[str] = Form(default=[]),
    file: UploadFile = File(...),
    next: str = Form(""),
    manager: User = Depends(require_approver),
):
    from security_agent.config import get_settings
    from security_agent.policy.pdf import PdfError, extract_pdf_text
    from security_agent.policy.service import PolicyError, create_document

    rid = int(repo_id) if repo_id.strip() else None
    name = (file.filename or "").lower()
    if not any(name.endswith(suffix) for suffix in _ALLOWED_SUFFIXES):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Upload .md, .txt, .rst, or .pdf (got {file.filename!r}).",
        )
    cap = max(1024, get_settings().policy_upload_max_bytes)
    data = await file.read(cap + 1)
    if len(data) > cap:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"File exceeds the {cap}-byte upload cap.")
    if not data.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Uploaded file is empty.")
    pages: list[tuple[str, str]] | None = None
    if name.endswith(".pdf"):
        try:
            pages = extract_pdf_text(data)
        except PdfError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        text = "\n\n".join(t for _, t in pages)
    else:
        text = data.decode("utf-8", errors="replace")
    try:
        doc = create_document(
            scope=scope,
            title=title.strip() or (file.filename or "uploaded policy"),
            text=text,
            repo_id=rid,
            tasks=_tasks_form(tasks),
            source="upload",
            file_name=file.filename,
            created_by=manager.id,
            pages=pages,
        )
    except (PolicyError, ValueError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect_back(
        scope, rid, next, f"Policy {doc.title!r} ingested; draft guardrails when ready."
    )


@router.post("/policies/editor", dependencies=[Depends(require_csrf)])
def editor(
    scope: str = Form(...),
    repo_id: str = Form(""),
    title: str = Form(...),
    text: str = Form(...),
    tasks: list[str] = Form(default=[]),
    next: str = Form(""),
    manager: User = Depends(require_approver),
):
    from security_agent.policy.service import PolicyError, create_document

    rid = int(repo_id) if repo_id.strip() else None
    try:
        doc = create_document(
            scope=scope,
            title=title,
            text=text,
            repo_id=rid,
            tasks=_tasks_form(tasks),
            source="editor",
            created_by=manager.id,
        )
    except (PolicyError, ValueError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect_back(scope, rid, next, f"Policy {doc.title!r} saved.")


@router.post("/policies/docs/{doc_key}/edit", dependencies=[Depends(require_csrf)])
def edit_doc(
    doc_key: str,
    title: str = Form(""),
    text: str = Form(""),
    tasks: list[str] = Form(default=[]),
    next: str = Form(""),
    manager: User = Depends(require_approver),
):
    from security_agent.policy.service import PolicyError, get_document, update_document

    doc = get_document(doc_key)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown policy document.")
    if doc.source == "readme":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "README documents are scan-managed.")
    try:
        update_document(
            doc_key,
            title=title.strip() or None,
            text=text if text.strip() else None,
            tasks=_tasks_form(tasks),
            created_by=manager.id,
        )
    except (PolicyError, ValueError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect_back(doc.scope, doc.repo_id, next, "Policy updated (new version).")


@router.post("/policies/docs/{doc_key}/disable", dependencies=[Depends(require_csrf)])
def disable_doc(
    doc_key: str, next: str = Form(""), _manager: User = Depends(require_approver)
):
    from security_agent.policy.service import PolicyError, get_document, set_document_status

    doc = get_document(doc_key)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown policy document.")
    try:
        set_document_status(doc_key, disabled=True)
    except PolicyError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect_back(doc.scope, doc.repo_id, next, "Policy disabled.")


@router.post("/policies/docs/{doc_key}/enable", dependencies=[Depends(require_csrf)])
def enable_doc(
    doc_key: str, next: str = Form(""), _manager: User = Depends(require_approver)
):
    from security_agent.policy.service import PolicyError, get_document, set_document_status

    doc = get_document(doc_key)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown policy document.")
    try:
        set_document_status(doc_key, disabled=False)
    except PolicyError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect_back(doc.scope, doc.repo_id, next, "Policy enabled.")


@router.post("/policies/docs/{doc_key}/extract", dependencies=[Depends(require_csrf)])
def extract(doc_key: str, next: str = Form(""), _manager: User = Depends(require_approver)):
    from security_agent.policy.extract import draft_candidates
    from security_agent.policy.service import PolicyError, get_document

    doc = get_document(doc_key)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown policy document.")
    try:
        outcome = draft_candidates(doc_key)
    except PolicyError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if outcome["status"] == "done":
        notice = f"Drafted {outcome['created']} guardrail candidate(s) for review."
    elif outcome["status"] == "unparseable":
        notice = "The model returned unusable output; retry extraction."
    else:
        notice = "Extraction unavailable (model unreachable); retry later."
    return _redirect_back(doc.scope, doc.repo_id, next, notice)


@router.post("/policies/rules", dependencies=[Depends(require_csrf)])
def create_rule(
    scope: str = Form(...),
    repo_id: str = Form(""),
    effect: str = Form(...),
    package: str = Form(""),
    advisory: str = Form(""),
    ecosystem: str = Form(""),
    max_severity: str = Form(""),
    reason: str = Form(...),
    tasks: list[str] = Form(default=[]),
    overridable: str = Form(""),
    override_of: str = Form(""),
    next: str = Form(""),
    manager: User = Depends(require_approver),
):
    from security_agent.policy.rules import create_rule as _create
    from security_agent.policy.service import PolicyError

    rid = int(repo_id) if repo_id.strip() else None
    try:
        rule = _create(
            scope=scope,
            effect=effect,
            match=_match_form(package, advisory, ecosystem, max_severity),
            reason=reason,
            repo_id=rid,
            tasks=_tasks_form(tasks),
            overridable=overridable == "on",
            override_of=override_of.strip() or None,
            created_by=manager.id,
        )
    except (PolicyError, ValueError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect_back(scope, rid, next, f"Rule {rule.rule_key} drafted; confirm to enforce.")


@router.post("/policies/rules/{rule_key}/confirm", dependencies=[Depends(require_csrf)])
def confirm(rule_key: str, next: str = Form(""), manager: User = Depends(require_approver)):
    from security_agent.policy.rules import confirm_rule, get_rule
    from security_agent.policy.service import PolicyError

    rule = get_rule(rule_key)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown rule.")
    try:
        confirm_rule(rule_key, user_id=manager.id)
    except (PolicyError, ValueError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect_back(rule.scope, rule.repo_id, next, f"Rule {rule_key} confirmed.")


@router.post("/policies/rules/{rule_key}/disable", dependencies=[Depends(require_csrf)])
def disable_rule(
    rule_key: str, next: str = Form(""), _manager: User = Depends(require_approver)
):
    from security_agent.policy.rules import get_rule, set_rule_status
    from security_agent.policy.service import PolicyError

    rule = get_rule(rule_key)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown rule.")
    try:
        set_rule_status(rule_key, disabled=True)
    except PolicyError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect_back(rule.scope, rule.repo_id, next, f"Rule {rule_key} disabled.")


@router.post("/policies/rules/{rule_key}/enable", dependencies=[Depends(require_csrf)])
def enable_rule(
    rule_key: str, next: str = Form(""), _manager: User = Depends(require_approver)
):
    from security_agent.policy.rules import get_rule, set_rule_status
    from security_agent.policy.service import PolicyError

    rule = get_rule(rule_key)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown rule.")
    try:
        set_rule_status(rule_key, disabled=False)
    except PolicyError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect_back(rule.scope, rule.repo_id, next, f"Rule {rule_key} enabled.")


@router.post("/policies/rules/{rule_key}/edit", dependencies=[Depends(require_csrf)])
def edit_rule(
    rule_key: str,
    effect: str = Form(""),
    package: str = Form(""),
    advisory: str = Form(""),
    ecosystem: str = Form(""),
    max_severity: str = Form(""),
    reason: str = Form(""),
    tasks: list[str] = Form(default=[]),
    overridable: str = Form(""),
    full_match: str = Form(""),
    next: str = Form(""),
    manager: User = Depends(require_approver),
):
    from security_agent.policy.rules import edit_rule as _edit
    from security_agent.policy.rules import get_rule
    from security_agent.policy.service import PolicyError

    rule = get_rule(rule_key)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown rule.")
    current_match = dict(rule.match or {})
    if full_match == "on":
        # Dashboard form: all fields submitted, empty means dropped.
        match = _match_form(package, advisory, ecosystem, max_severity)
        if not match:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Rules need a non-empty match.")
    else:
        match = {
            "package": package.strip() or current_match.get("package"),
            "advisory": advisory.strip() or current_match.get("advisory"),
            "ecosystem": ecosystem.strip() or current_match.get("ecosystem"),
        }
        if max_severity.strip():
            try:
                match["max_severity"] = float(max_severity.strip())
            except ValueError as exc:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST, "Max severity must be a number 0-10."
                ) from exc
        elif current_match.get("max_severity") is not None:
            match["max_severity"] = current_match["max_severity"]
        match = {k: v for k, v in match.items() if v is not None}
    try:
        _edit(
            rule_key,
            effect=effect.strip() or None,
            match=match,
            reason=reason.strip() or None,
            tasks=_tasks_form(tasks),
            overridable=True if overridable == "on" else None,
            user_id=manager.id,
        )
    except (PolicyError, ValueError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _redirect_back(rule.scope, rule.repo_id, next, f"Rule {rule_key} updated.")


@router.get("/policies/preview", response_class=HTMLResponse)
def preview(
    request: Request,
    q: str = "",
    repo_id: str = "",
    task: str = "",
    user: User = Depends(get_current_user),
):
    from security_agent.app.main import templates
    from security_agent.control.repos import list_repos
    from security_agent.policy.retrieve import retrieve_chunks

    chunks: list[dict] = []
    if q.strip():
        chunks = retrieve_chunks(
            int(repo_id) if repo_id.strip() else None,
            task.strip() or None,
            q.strip(),
            limit=10,
        )
    return templates.TemplateResponse(
        request,
        "policy_preview.html",
        {
            "q": q,
            "repo_id": repo_id,
            "task": task,
            "tasks": POLICY_TASKS,
            "repos": list_repos(),
            "chunks": chunks,
            "searched": bool(q.strip()),
            "notice": request.query_params.get("notice", ""),
            "csrf": make_csrf(),
        },
    )


@router.post("/repos/{repo_id}/policies/readme-toggle", dependencies=[Depends(require_csrf)])
def readme_toggle(
    repo_id: int, enabled: str = Form(""), _manager: User = Depends(require_approver)
):
    from security_agent.policy.service import PolicyError, set_repo_readme_policy

    try:
        set_repo_readme_policy(repo_id, enabled=enabled == "on")
    except PolicyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    state = "enabled" if enabled == "on" else "disabled"
    return _redirect(f"/repos/{repo_id}/policies", f"README guidance {state}.")
