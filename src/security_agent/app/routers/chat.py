"""Chat agent routes: page, widget, turns, gate + confirm execution."""

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from security_agent.app.dependencies import get_current_user, make_csrf, require_csrf
from security_agent.chat import cards
from security_agent.db.models import ChatMessage, User

router = APIRouter(prefix="/chat")


def _present(messages: list[ChatMessage]) -> list[dict]:
    from security_agent.chat.attachments import filenames_for_messages

    presented = []
    chips = filenames_for_messages([m.id for m in messages if m.id])
    for msg in messages:
        card = msg.card or None
        card_text = ""
        if card and card.get("kind") == "confirm":
            try:
                card_text = cards.render_confirm(card)
            except ValueError:
                card_text = "Unknown action (refused)."
        presented.append(
            {
                "id": msg.id,
                "role": msg.role.value,
                "content": msg.content,
                "card": card,
                "card_text": card_text,
                "created_at": msg.created_at,
                "attachments": chips.get(msg.id, []),
            }
        )
    return presented


@router.get("/widget", response_class=HTMLResponse)
def chat_widget(request: Request, user: User = Depends(get_current_user)):
    from security_agent.app.main import templates
    from security_agent.chat import get_conversation, history
    from security_agent.control import repos as repo_svc

    conv = get_conversation(user.id)
    return templates.TemplateResponse(
        request,
        "chat_widget.html",
        {
            "conversation": conv,
            "messages": _present(history(conv.id, limit=20)),
            "repos": repo_svc.list_repos(),
            "csrf": make_csrf(),
            "user": user,
        },
    )


@router.get("/mentions")
def chat_mentions(
    q: str = "",
    kind: str = "all",
    repo_id: int | None = None,
    user: User = Depends(get_current_user),
):
    from security_agent.chat.render import search_mentions
    from security_agent.db.models import Role

    if kind not in ("all", "@", "#"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Bad kind.")
    return JSONResponse(
        search_mentions(q[:80], kind, repo_id, viewer_is_owner=user.role == Role.OWNER)
    )


@router.post("/new", dependencies=[Depends(require_csrf)])
def chat_new(request: Request, user: User = Depends(get_current_user)):
    from security_agent.app.main import templates
    from security_agent.chat import new_conversation

    new_conversation(user.id)
    if request.headers.get("hx-request"):
        return templates.TemplateResponse(
            request,
            "_chat_messages.html",
            {"messages": [], "csrf": make_csrf(), "user": user},
        )
    return RedirectResponse("/dashboard", status_code=303)


@router.post("/switch/{conversation_id}", dependencies=[Depends(require_csrf)])
def chat_switch(request: Request, conversation_id: int, user: User = Depends(get_current_user)):
    from security_agent.app.main import templates
    from security_agent.chat import history, switch_conversation

    try:
        conv = switch_conversation(user.id, conversation_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    if "text/html" in request.headers.get("accept", "") and request.headers.get("hx-request"):
        return templates.TemplateResponse(
            request,
            "_chat_messages.html",
            {"messages": _present(history(conv.id)), "csrf": make_csrf(), "user": user},
        )
    return RedirectResponse("/dashboard", status_code=303)


@router.get("/threads", response_class=HTMLResponse)
def chat_threads(request: Request, user: User = Depends(get_current_user)):
    from security_agent.app.main import templates
    from security_agent.chat import get_conversation, list_conversations

    conv = get_conversation(user.id)
    return templates.TemplateResponse(
        request,
        "_chat_threads.html",
        {
            "threads": list_conversations(user.id),
            "active_id": conv.id,
            "csrf": make_csrf(),
            "user": user,
        },
    )


@router.post("/scope", dependencies=[Depends(require_csrf)])
def chat_scope(request: Request, repo_id: str = Form(""), user: User = Depends(get_current_user)):
    from security_agent.chat import set_repo_scope

    rid = int(repo_id) if repo_id.strip() else None
    set_repo_scope(user.id, rid)
    if request.headers.get("hx-request"):
        return HTMLResponse("")
    return RedirectResponse("/dashboard", status_code=303)


@router.post("/message", response_class=HTMLResponse, dependencies=[Depends(require_csrf)])
def chat_message(
    request: Request,
    text: str = Form(...),
    thread: str = Form("thread"),
    user: User = Depends(get_current_user),
    files: list[UploadFile] = File(default=[]),
):
    from security_agent.app.main import templates
    from security_agent.chat import get_conversation
    from security_agent.chat.agent import answer_turn
    from security_agent.chat.attachments import MAX_FILES_PER_MESSAGE
    from security_agent.db.models import ChatRole

    conv = get_conversation(user.id)
    text = text.strip()[:4000]
    uploads = []
    for upload in files or []:
        if not upload.filename:
            continue
        uploads.append((upload.filename, upload.file.read()))
    if len(uploads) > MAX_FILES_PER_MESSAGE:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"At most {MAX_FILES_PER_MESSAGE} files per message.",
        )
    if not text and not uploads:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty message.")
    try:
        reply = answer_turn(user, conv, text, repo_scope=conv.repo_id, uploads=uploads)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    user_msg = {
        "id": 0,
        "role": ChatRole.USER.value,
        "content": text,
        "card": None,
        "card_text": "",
        "created_at": reply.created_at,
        "attachments": [name for name, _data in uploads],
    }
    return templates.TemplateResponse(
        request,
        "_chat_messages.html",
        {
            "messages": [user_msg, *_present([reply])],
            "csrf": make_csrf(),
            "user": user,
            "thread_id": thread if thread in ("thread", "widget-thread") else "thread",
        },
    )


@router.post(
    "/gates/{gate_id}/request",
    response_class=HTMLResponse,
    dependencies=[Depends(require_csrf)],
)
def gate_request(
    request: Request,
    gate_id: int,
    approved: str = Form(...),
    reason: str = Form(""),
    thread: str = Form("thread"),
    user: User = Depends(get_current_user),
):
    from security_agent.app.main import templates
    from security_agent.chat import append_message, get_conversation
    from security_agent.chat.tools import want_gate_decision
    from security_agent.db.models import ChatRole

    conv = get_conversation(user.id)
    try:
        out = want_gate_decision(user, gate_id, approved == "yes", reason.strip()[:500])
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    msg = append_message(
        conv.id, ChatRole.ASSISTANT, "Please confirm this gate decision.", out["card"]
    )
    return templates.TemplateResponse(
        request,
        "_chat_messages.html",
        {
            "messages": _present([msg]),
            "csrf": make_csrf(),
            "user": user,
            "thread_id": thread if thread in ("thread", "widget-thread") else "thread",
        },
    )


@router.post(
    "/confirm/{message_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_csrf)],
)
def chat_confirm(request: Request, message_id: int, user: User = Depends(get_current_user)):
    from security_agent.app.main import templates
    from security_agent.chat import (
        append_message,
        get_conversation,
        get_message,
        set_card_state,
    )
    from security_agent.chat.tools import execute_confirmed
    from security_agent.db.models import ChatRole

    conv = get_conversation(user.id)
    msg = get_message(message_id)
    if msg is None or msg.conversation_id != conv.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown message.")
    card = msg.card or {}
    if card.get("kind") != "confirm" or card.get("state") != "pending":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Nothing to confirm.")
    try:
        out = execute_confirmed(user, card["action"], dict(card.get("args", {})))
    except PermissionError as exc:
        set_card_state(message_id, "failed")
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except (ValueError, RuntimeError, TimeoutError) as exc:
        set_card_state(message_id, "failed")
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    set_card_state(message_id, "confirmed")
    result_card = None
    if "run_id" in out:
        result_card = {
            "kind": "run",
            "run_id": out["run_id"],
            "repo_id": out["repo_id"],
            "events_url": out["events_url"],
            "run_url": out["run_url"],
            "state": "watching",
        }
    reply = append_message(conv.id, ChatRole.ASSISTANT, out["text"], result_card)
    return templates.TemplateResponse(
        request,
        "_chat_messages.html",
        {"messages": _present([reply]), "csrf": make_csrf(), "user": user},
    )


@router.post(
    "/dismiss/{message_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_csrf)],
)
def chat_dismiss(request: Request, message_id: int, user: User = Depends(get_current_user)):
    from security_agent.chat import get_conversation, get_message, set_card_state

    conv = get_conversation(user.id)
    msg = get_message(message_id)
    if msg is None or msg.conversation_id != conv.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown message.")
    set_card_state(message_id, "dismissed")
    return HTMLResponse('<div class="chat-sys">Dismissed.</div>')
