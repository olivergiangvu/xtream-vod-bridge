"""Private admin control-plane with LAN-restricted HTTPS reverse-proxy option.

Backend stays bound to 127.0.0.1:18768 on the HomeDocker host.
A narrowly scoped nginx /admin/ route on the existing 18450 listener may
allow only verified LAN clients; the backend port stays off router NAT.
Every API call requires the independent ADMIN_TOKEN in an Authorization header.
Secrets never appear in API responses, URLs, browser storage, or server logs.
"""
import hmac
import json
import urllib.error
import urllib.request
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

import app as bridge
import ops
import admin_auth
import admin_users

ROOT = Path(__file__).resolve().parent / "admin"
BRIDGE_HEALTH = "http://xtream-vod-bridge:8767/health"


@asynccontextmanager
async def lifespan(_app):
    ops.init()
    admin_auth.init()
    admin_users.init()
    yield


console = FastAPI(
    title="HomeDocker Xtream Bridge Admin", docs_url=None, redoc_url=None,
    openapi_url=None, lifespan=lifespan,
)
console.mount("/assets", StaticFiles(directory=ROOT / "assets"), name="assets")


@console.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "img-src 'self'; connect-src 'self'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    )
    return response


def authorize(request: Request, authorization: str = Header(default="")):
    # Bearer compatibility exists for SSH/admin automation, but the browser
    # uses a separate password-verified HttpOnly session.
    token = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else ""
    if bridge.ADMIN_TOKEN and hmac.compare_digest(token, bridge.ADMIN_TOKEN):
        return {"username": "owner", "role": "owner"}
    session = admin_auth.session_info(request.cookies.get(admin_auth.COOKIE))
    if session:
        if request.method in ("PUT", "POST", "PATCH", "DELETE"):
            csrf = request.headers.get("x-csrf-token", "")
            if not admin_auth.same_origin(request) or not hmac.compare_digest(
                csrf, session["csrf"]
            ):
                raise HTTPException(status_code=403, detail="CSRF validation failed")
        return {"username": session["username"], "role": session["role"]}
    raise HTTPException(status_code=401, detail="Unauthorized",
                        headers={"WWW-Authenticate": "Bearer"})


def require_writer(principal=Depends(authorize)):
    if principal["role"] not in ("owner", "admin"):
        raise HTTPException(403, "Read-only account")
    return principal


def require_owner(principal=Depends(authorize)):
    if principal["role"] != "owner":
        raise HTTPException(403, "Only Owner may manage Admin accounts")
    return principal


@console.get("/")
@console.get("/console")
def index():
    return FileResponse(ROOT / "index.html", media_type="text/html")


def main_health():
    try:
        with urllib.request.urlopen(BRIDGE_HEALTH, timeout=4) as resp:
            data = resp.read(32768)
        return json.loads(data)
    except (urllib.error.URLError, ValueError, TimeoutError, OSError):
        return {"status": "offline", "version": None}


@console.get("/api/auth/session")
def auth_status(request: Request):
    session = admin_auth.session_info(request.cookies.get(admin_auth.COOKIE))
    return {
        "authenticated": bool(session),
        "csrf_token": session["csrf"] if session else None,
        "password_ready": admin_auth.configured() and admin_auth.origin_configured(),
        "username": session["username"] if session else None,
        "role": session["role"] if session else None,
    }


@console.post("/api/auth/login")
def auth_login(request: Request, response: Response, payload: dict[str, Any]):
    if not admin_auth.same_origin(request):
        raise HTTPException(status_code=403, detail="Secure origin required")
    if set(payload) not in ({"password"}, {"username", "password"}):
        raise HTTPException(status_code=422, detail="Expected username and password")
    try:
        session, csrf = admin_auth.login(payload["password"], payload.get("username", "owner"))
    except admin_auth.LoginThrottled:
        raise HTTPException(status_code=429, detail="Too many attempts; try later") from None
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid credentials") from None
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Admin password not configured") from None
    response.set_cookie(
        key=admin_auth.COOKIE,
        value=session,
        httponly=True, secure=True, samesite="strict",
        path=admin_auth.COOKIE_PATH,
        max_age=admin_auth.SESSION_SECONDS,
    )
    return {"authenticated": True, "csrf_token": csrf, "expires_in": admin_auth.SESSION_SECONDS,
            "username": payload.get("username", "owner")}


@console.post("/api/auth/logout", dependencies=[Depends(authorize)])
def auth_logout(request: Request, response: Response):
    admin_auth.delete_session(request.cookies.get(admin_auth.COOKIE))
    response.delete_cookie(admin_auth.COOKIE, path=admin_auth.COOKIE_PATH)
    return {"authenticated": False}


@console.get("/api/overview", dependencies=[Depends(authorize)])
def overview():
    status = main_health()
    return {
        "bridge": status,
        "settings": ops.all_settings(),
        "effective_env": {
            "movies_only": bridge.MOVIES_ONLY,
            "bootstrap_batch": bridge.SERIES_BOOTSTRAP_BATCH,
            "bootstrap_interval_minutes": bridge.SERIES_BOOTSTRAP_INTERVAL_MINUTES,
            "max_enrich_per_sync": bridge.MAX_ENRICH,
            "sync_hours": bridge.SYNC_HOURS,
            "redirect_mode": bridge.HTTP_REDIRECT_MODE,
            "public_https_enabled": bridge.PUBLIC.startswith("https://"),
            "credentials_configured": all((bridge.USER, bridge.PASSWORD, bridge.TMDB_KEY)),
        },
        "events": ops.events(limit=40),
    }


@console.put("/api/settings", dependencies=[Depends(require_writer)])
def settings(payload: dict[str, Any]):
    try:
        updated = ops.update(payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return {"settings": updated}


@console.get("/api/manifest", dependencies=[Depends(authorize)])
def private_manifest_url():
    # The ADDON_TOKEN is a credential. This endpoint is strictly authenticated
    # and must not be logged, cached, embedded in HTML or sent to analytics.
    from urllib.parse import quote
    if not bridge.PUBLIC.startswith("https://") or not bridge.ADDON_TOKEN:
        raise HTTPException(503, "Manifest is not configured")
    return {
        "url": bridge.PUBLIC + "/a/" + quote(bridge.ADDON_TOKEN, safe="") + "/manifest.json",
        "types": ["movie", "series"] if not bridge.MOVIES_ONLY else ["movie"],
    }


@console.get("/api/admin-users", dependencies=[Depends(require_owner)])
def list_admin_accounts():
    return {"users": admin_users.list_users()}


@console.post("/api/admin-users", dependencies=[Depends(require_owner)], status_code=201)
def create_admin_account(payload: dict[str, Any]):
    if set(payload) != {"username", "password", "role"}:
        raise HTTPException(422, "Expected username, password and role")
    try:
        return admin_users.add_user(payload["username"], payload["password"], payload["role"])
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@console.patch("/api/admin-users/{username}", dependencies=[Depends(require_owner)])
def edit_admin_account(username: str, payload: dict[str, Any]):
    if not payload or set(payload) - {"role", "enabled", "password"}:
        raise HTTPException(422, "Invalid account changes")
    try:
        return admin_users.modify_user(username, **payload)
    except KeyError:
        raise HTTPException(404, "Account not found") from None
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, "Invalid account change") from None


@console.delete("/api/admin-users/{username}", dependencies=[Depends(require_owner)])
def remove_admin_account(username: str):
    try:
        admin_users.delete_user(username)
        return {"status": "deleted"}
    except KeyError:
        raise HTTPException(404, "Account not found") from None
    except ValueError:
        raise HTTPException(422, "Owner cannot be deleted") from None


@console.get("/api/events", dependencies=[Depends(authorize)])
def events():
    return {"events": ops.events(limit=100)}
