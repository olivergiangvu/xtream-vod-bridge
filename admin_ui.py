"""Private admin control-plane with LAN-restricted HTTPS reverse-proxy option.

Backend stays bound to 127.0.0.1:18768 on the HomeDocker host.
A narrowly scoped nginx /admin/ route on the existing 18450 listener may
allow only verified LAN clients; the backend port stays off router NAT.
Every API call requires the independent ADMIN_TOKEN in an Authorization header.
Secrets never appear in API responses, URLs, browser storage, or server logs.
"""
import hmac
import json
import secrets
from urllib.parse import parse_qs
from html import escape
import urllib.error
import urllib.request
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles

import app as bridge
import ops
import admin_auth

ROOT = Path(__file__).resolve().parent / "admin"
BRIDGE_HEALTH = "http://xtream-vod-bridge:8767/health"


@asynccontextmanager
async def lifespan(_app):
    ops.init()
    admin_auth.init()
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
    if request.url.path.startswith("/gateway/"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
    else:
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
        return
    session = admin_auth.session_info(request.cookies.get(admin_auth.COOKIE))
    if session:
        if request.method in ("PUT", "POST", "PATCH", "DELETE"):
            csrf = request.headers.get("x-csrf-token", "")
            if not admin_auth.same_origin(request) or not hmac.compare_digest(
                csrf, session["csrf"]
            ):
                raise HTTPException(status_code=403, detail="CSRF validation failed")
        return
    raise HTTPException(status_code=401, detail="Unauthorized",
                        headers={"WWW-Authenticate": "Bearer"})



# Browser-safe, no-HTTP-Basic gateway: the same Owner password authenticates
# the nginx auth_request gate AND the FastAPI Admin session. Gateway pages
# MUST be exposed only at /admin-signin/ through the reviewed nginx route.
# /api/auth/gate-check MUST remain nginx-internal, NEVER directly public.
GATE_LOGIN_COOKIE = "xtream_admin_login_nonce"


def _gate_page(message: str, nonce: str):
    message = escape(message)
    nonce = escape(nonce, quote=True)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>HomeDocker Admin — Sign in</title>
<style>
:root{{color-scheme:dark}}body{{font:16px system-ui,sans-serif;background:#091522;color:#eaf2fc;
display:grid;min-height:100vh;place-items:center;margin:0;padding:20px;box-sizing:border-box}}
main{{max-width:430px;width:100%;padding:28px;border:1px solid #34506b;border-radius:16px;
background:#102338;box-sizing:border-box}}h1{{font-size:24px;margin:0 0 12px}}
p{{color:#b9cadc;line-height:1.5}}label{{display:block;margin:16px 0 8px}}
input{{width:100%;box-sizing:border-box;padding:13px;color:#f7fbff;background:#071626;
border:1px solid #4a6479;border-radius:8px;font-size:17px}}
button{{margin-top:20px;width:100%;background:#2776c1;color:white;padding:13px;
border:0;border-radius:8px;font-weight:650;font-size:16px}}
.small{{font-size:13px}}.notice{{color:#ffd48c}}
</style></head><body><main>
<h1>HomeDocker Admin</h1>
<p>Sign in with your existing Admin password. No separate nginx Gateway
password or browser HTTP Basic prompt is needed.</p>
<p class="notice" role="alert">{message}</p>
<form method="post" action="/admin-signin/" autocomplete="on">
<input type="hidden" name="nonce" value="{nonce}">
<label for="pw">Admin password</label>
<input id="pw" type="password" name="password" required minlength="14"
autocomplete="current-password" autofocus>
<button type="submit">Sign in securely</button>
</form>
<p class="small">HTTPS · HttpOnly session · 12-hour expiry. This form never stores your password.</p>
</main></body></html>"""


@console.get("/gateway/", response_class=HTMLResponse)
def gateway_login_page(request: Request):
    existing = admin_auth.session_info(request.cookies.get(admin_auth.COOKIE))
    if existing:
        return RedirectResponse("/admin/", status_code=303)
    nonce = secrets.token_urlsafe(32)
    result = HTMLResponse(_gate_page("", nonce))
    result.set_cookie(GATE_LOGIN_COOKIE, nonce, secure=True, httponly=True,
                      samesite="strict", path="/admin-signin/", max_age=600)
    return result


@console.post("/gateway/", response_class=HTMLResponse)
async def gateway_login_submit(request: Request):
    if not admin_auth.same_origin(request):
        raise HTTPException(403, "Invalid HTTPS origin")
    body = await request.body()
    if len(body) > 2048:
        raise HTTPException(413)
    try:
        fields = parse_qs(body.decode("utf-8"), strict_parsing=True,
                          max_num_fields=3)
        if set(fields) != {"password", "nonce"} or any(len(v) != 1 for v in fields.values()):
            raise ValueError("Invalid form")
        nonce = fields["nonce"][0]
        password = fields["password"][0]
    except (UnicodeError, ValueError):
        raise HTTPException(400, "Invalid login form") from None
    cookie_nonce = request.cookies.get(GATE_LOGIN_COOKIE, "")
    if (len(nonce) < 32 or len(nonce) > 100 or
            not hmac.compare_digest(nonce, cookie_nonce)):
        raise HTTPException(403, "Login page expired; reload and try again")
    try:
        session, _csrf = admin_auth.login(password)
    except admin_auth.LoginThrottled:
        raise HTTPException(429, "Too many attempts; try later") from None
    except ValueError:
        # Never return the password, even on failed login. Users can
        # retry using a new anti-CSRF nonce.
        new_nonce = secrets.token_urlsafe(32)
        response = HTMLResponse(_gate_page("Incorrect password.", new_nonce),
                                status_code=401)
        response.set_cookie(GATE_LOGIN_COOKIE, new_nonce,
                            secure=True, httponly=True, samesite="strict",
                            path="/admin-signin/", max_age=600)
        return response
    except RuntimeError:
        raise HTTPException(503, "Admin password not provisioned") from None
    response = RedirectResponse("/admin/", status_code=303)
    response.set_cookie(admin_auth.COOKIE, session, httponly=True,
                        secure=True, samesite="strict",
                        path=admin_auth.COOKIE_PATH,
                        max_age=admin_auth.SESSION_SECONDS)
    response.delete_cookie(GATE_LOGIN_COOKIE, path="/admin-signin/")
    return response


@console.get("/api/auth/gate-check")
def gateway_session_check(request: Request):
    session = admin_auth.session_info(request.cookies.get(admin_auth.COOKIE))
    if not session:
        return Response(status_code=401)
    return Response(status_code=204)


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
    }


@console.post("/api/auth/login")
def auth_login(request: Request, response: Response, payload: dict[str, Any]):
    if not admin_auth.same_origin(request):
        raise HTTPException(status_code=403, detail="Secure origin required")
    if set(payload) != {"password"}:
        raise HTTPException(status_code=422, detail="Expected password only")
    try:
        session, csrf = admin_auth.login(payload["password"])
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
    return {"authenticated": True, "csrf_token": csrf, "expires_in": admin_auth.SESSION_SECONDS}


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


@console.put("/api/settings", dependencies=[Depends(authorize)])
def settings(payload: dict[str, Any]):
    try:
        updated = ops.update(payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return {"settings": updated}


@console.get("/api/events", dependencies=[Depends(authorize)])
def events():
    return {"events": ops.events(limit=100)}
