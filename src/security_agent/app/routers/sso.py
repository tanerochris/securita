"""Google / Microsoft login via standard OIDC auth-code flow (FR-11)."""

import secrets

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, HTTPException, Request

from security_agent.app import accounts as svc
from security_agent.config import get_settings

router = APIRouter(prefix="/auth")

METADATA = {
    "google": "https://accounts.google.com/.well-known/openid-configuration",
    "microsoft": "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
}

_oauth: OAuth | None = None


def oauth() -> OAuth:
    global _oauth
    if _oauth is None:
        s = get_settings()
        _oauth = OAuth()
        _oauth.register(
            "google",
            client_id=s.google_client_id,
            client_secret=s.google_client_secret,
            server_metadata_url=METADATA["google"],
            client_kwargs={"scope": "openid email profile"},
        )
        _oauth.register(
            "microsoft",
            client_id=s.microsoft_client_id,
            client_secret=s.microsoft_client_secret,
            server_metadata_url=METADATA["microsoft"],
            client_kwargs={"scope": "openid email profile"},
        )
    return _oauth


def _client_id(provider: str) -> str:
    s = get_settings()
    return s.google_client_id if provider == "google" else s.microsoft_client_id


@router.get("/{provider}/start")
async def start(request: Request, provider: str, token: str = ""):
    if provider not in METADATA or not _client_id(provider):
        raise HTTPException(501, "SSO not configured for this install.")
    redirect_uri = f"{get_settings().public_url}/auth/{provider}/callback"
    client = oauth().create_client(provider)
    if client is None:
        raise HTTPException(501, "SSO not configured for this install.")
    # Random OAuth state (CSRF); the invite token never leaves the server.
    request.session["sso_invite"] = token
    state = secrets.token_urlsafe(32)
    return await client.authorize_redirect(request, redirect_uri, state=state)


@router.get("/{provider}/callback")
async def callback(request: Request, provider: str):
    if provider not in METADATA:
        raise HTTPException(404, "Unknown provider.")
    client = oauth().create_client(provider)
    if client is None:
        raise HTTPException(501, "SSO not configured for this install.")
    token = await client.authorize_access_token(request)
    info = await client.userinfo(token=token)
    email = info.get("email", "")
    subject = info.get("sub", "")
    if not email or not subject:
        raise HTTPException(400, "Provider did not return email/subject.")
    if info.get("email_verified") is False:
        raise HTTPException(403, "Provider email is not verified.")
    invite_token = request.session.pop("sso_invite", "") or ""
    try:
        user = svc.resolve_sso_user(email, subject, provider, invite_token)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    from security_agent.app.routers.auth import _session_response

    return _session_response(user.id)
