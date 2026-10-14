"""Private admin control-plane with LAN-restricted HTTPS reverse-proxy option.

Backend stays bound to 127.0.0.1:18768 on the HomeDocker host.
A narrowly scoped nginx /admin/ route on the existing 18450 listener may
allow only verified LAN clients; the backend port stays off router NAT.
Every API call requires the independent ADMIN_TOKEN in an Authorization header.
Secrets never appear in API responses, URLs, browser storage, or server logs.
"""
import hmac
import json
import os
import re
import socket
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
import admin_users
import user_sources
import personal_index
import personal_manifests
import route_paths

ROOT = Path(__file__).resolve().parent / "admin"
BRIDGE_HEALTH = "http://xtream-vod-bridge:8767/health"

# Safari's native HTML POST is already proven on HomeDocker with same-origin.
# Keep the repo default behavior; opt into the reviewed policy for Canary.
GATEWAY_REFERRER_POLICY = os.getenv(
    "XTREAM_GATEWAY_REFERRER_POLICY", "strict-origin-when-cross-origin"
)
if GATEWAY_REFERRER_POLICY not in ("same-origin", "strict-origin-when-cross-origin"):
    raise RuntimeError("Invalid XTREAM_GATEWAY_REFERRER_POLICY")


@asynccontextmanager
async def lifespan(_app):
    ops.init()
    admin_auth.init()
    admin_users.init()
    user_sources.init()
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
    # Native HTML POST needs a real Origin (no-referrer sets it to "null").
    # Keep the restrictive policy on every other Admin response.
    response.headers["Referrer-Policy"] = (
        GATEWAY_REFERRER_POLICY if request.url.path.startswith("/gateway/")
        else "no-referrer"
    )
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
        return {"username": "owner", "role": "admin"}
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



# Browser-safe, no-HTTP-Basic gateway: the same Owner password authenticates
# the nginx auth_request gate AND the FastAPI Admin session. Gateway pages
# MUST be exposed only at /admin-signin/ through the reviewed nginx route.
# /api/auth/gate-check MUST remain nginx-internal, NEVER directly public.
def require_admin(identity=Depends(authorize)):
    if identity["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin permission required")
    return identity


# The gateway nonce also needs a distinct name on the same hostname,
# because cookies are not scoped by TCP port.
GATE_LOGIN_COOKIE = os.getenv(
    "XTREAM_LOGIN_NONCE_COOKIE", "xtream_admin_login_nonce"
)
if not re.fullmatch(r"xtream_[a-z0-9_]{3,48}", GATE_LOGIN_COOKIE):
    raise RuntimeError("Invalid XTREAM_LOGIN_NONCE_COOKIE")
if GATE_LOGIN_COOKIE == admin_auth.COOKIE:
    raise RuntimeError("Login nonce and session cookie must be distinct")



def _gate_page(message: str, nonce: str, username: str = "owner"):
    message = escape(message)
    nonce = escape(nonce, quote=True)
    # Never echo a password or an unbounded username into the login page.
    username = escape(username[:32], quote=True)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0b1625">
<meta name="referrer" content="{GATEWAY_REFERRER_POLICY}">
<title>Sign in · Xtream VOD Bridge</title>
<style>
:root{{color-scheme:dark;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
*{{box-sizing:border-box}}
body{{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;
background:radial-gradient(ellipse at 80% -20%,#164d5d 0%,transparent 48%),
radial-gradient(ellipse at 0% 0%,#173254 0%,transparent 42%),#0a111b;color:#eaf1f8}}
main{{width:100%;max-width:420px;border:1px solid #314253;border-radius:18px;
background:#121e2bf5;padding:32px;box-shadow:0 26px 90px #0005}}
.brand{{display:flex;align-items:center;gap:13px;margin-bottom:30px}}
.mark{{width:46px;height:46px;border-radius:13px;display:grid;place-items:center;
background:linear-gradient(135deg,#37cec7,#437add);color:#041a27;font-size:24px;font-weight:800}}
.product{{font-weight:750;font-size:16px}}.subtitle{{display:block;color:#93a6b9;font-size:12px;margin-top:3px}}
h1{{font-size:28px;letter-spacing:-.03em;margin:0 0 9px}}
p{{color:#9dacba;line-height:1.55;margin:0 0 22px;font-size:14px}}
label{{display:block;font-size:13px;font-weight:650;margin:17px 0 8px}}
input{{width:100%;border:1px solid #415365;background:#0c1723;color:#f0f7ff;
border-radius:9px;padding:13px 14px;font:inherit;font-size:16px}}
input:focus{{outline:2px solid #38afa8;outline-offset:2px}}
button{{width:100%;border:0;border-radius:9px;margin-top:24px;padding:13px;
background:linear-gradient(120deg,#138779,#1079aa);color:#fff;font:inherit;
font-weight:700;font-size:15px;cursor:pointer}}
button:hover{{filter:brightness(1.12)}}button:focus-visible{{outline:2px solid #8ad6cf;outline-offset:3px}}
.notice{{color:#ffd49e;margin:0;font-size:13px}}.notice:empty{{display:none}}
.footnote{{margin:23px 0 0;color:#92a8bb;font-size:12px}}
@media(max-width:480px){{main{{padding:25px}}}}
</style>
</head>
<body>
<main>
<div class="brand"><span class="mark" aria-hidden="true">X</span>
<div><span class="product">Xtream VOD Bridge</span>
<span class="subtitle">HomeDocker · Private Console</span></div></div>
<h1>Welcome back</h1>
<p>Sign in with your HomeDocker account to manage the VOD bridge.
No separate nginx Gateway password is needed.</p>
<p class="notice" role="alert">{message}</p>
<form method="post" action="{route_paths.LOGIN_PATH}" autocomplete="on">
<input type="hidden" name="nonce" value="{nonce}">
<label for="username">Username</label>
<input id="username" name="username" type="text" value="{username}" required maxlength="32"
autocomplete="username" autocapitalize="none" spellcheck="false" inputmode="text">
<label for="password">Password</label>
<input id="password" name="password" type="password" required minlength="14" maxlength="128"
autocomplete="current-password">
<button type="submit">Sign in</button>
</form>
<p class="footnote">Secure HTTPS · 12-hour session · Works with Safari Passwords and password managers.</p>
</main>
</body>
</html>"""


@console.get("/gateway/", response_class=HTMLResponse)
def gateway_login_page(request: Request):
    existing = admin_auth.session_info(request.cookies.get(admin_auth.COOKIE))
    if existing:
        return RedirectResponse(route_paths.ADMIN_PATH, status_code=303)
    nonce = secrets.token_urlsafe(32)
    result = HTMLResponse(_gate_page("", nonce))
    result.set_cookie(GATE_LOGIN_COOKIE, nonce, secure=True, httponly=True,
                      samesite="strict", path=route_paths.NONCE_COOKIE_PATH, max_age=600)
    return result


def _gateway_post_origin_allowed(request: Request) -> bool:
    """Conservative fallback for Safari native HTML form POST.

    Safari can omit Origin for a native form submission (not fetch). Explicit
    Origin or Referer, when present, MUST match an approved HTTPS origin.
    Missing Origin is accepted only on the configured HTTPS vhost and when
    Fetch Metadata does not indicate a cross-origin request. The independent
    random double-submit nonce remains mandatory in gateway_login_submit.
    This exception does NOT weaken same_origin() for JSON/CSRF APIs.
    """
    if not admin_auth.origin_configured():
        return False
    origin = request.headers.get("origin")
    if origin is not None:
        if origin not in admin_auth.allowed_origins():
            return False
    else:
        # Nginx overwrites these headers to known values before proxying.
        if request.headers.get("x-forwarded-proto") != "https":
            return False
        hostname = request.headers.get("host", "").split(":", 1)[0].lower()
        from urllib.parse import urlsplit
        if hostname not in {
            urlsplit(item).hostname for item in admin_auth.allowed_origins()
        }:
            return False
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site and fetch_site not in ("same-origin", "none"):
        return False
    referer = request.headers.get("referer")
    if referer and not any(referer.startswith(item + "/")
                           for item in admin_auth.allowed_origins()):
        return False
    return True


@console.post("/gateway/", response_class=HTMLResponse)
async def gateway_login_submit(request: Request):
    if not _gateway_post_origin_allowed(request):
        raise HTTPException(403, "Invalid HTTPS origin")
    body = await request.body()
    if len(body) > 2048:
        raise HTTPException(413)
    try:
        fields = parse_qs(body.decode("utf-8"), strict_parsing=True,
                          keep_blank_values=True, max_num_fields=3)
        if set(fields) not in ({"password", "nonce"}, {"password", "nonce", "username"}) or any(len(v) != 1 for v in fields.values()):
            raise ValueError("Invalid form")
        nonce = fields["nonce"][0]
        password = fields["password"][0]
        # Backwards-compatible with an already-open, password-only form.
        username = fields.get("username", ["owner"])[0]
        if not nonce or not password:
            raise ValueError("Invalid form")
    except (UnicodeError, ValueError):
        raise HTTPException(400, "Invalid login form") from None
    cookie_nonce = request.cookies.get(GATE_LOGIN_COOKIE, "")
    if (len(nonce) < 32 or len(nonce) > 100 or
            not hmac.compare_digest(nonce, cookie_nonce)):
        raise HTTPException(403, "Login page expired; reload and try again")
    try:
        session, _csrf = admin_auth.login(password, username=username)
    except admin_auth.LoginThrottled:
        raise HTTPException(429, "Too many attempts; try later") from None
    except ValueError:
        # Never return the password, even on failed login. Users can
        # retry using a new anti-CSRF nonce.
        new_nonce = secrets.token_urlsafe(32)
        response = HTMLResponse(_gate_page("Incorrect username or password.", new_nonce, username),
                                status_code=401)
        response.set_cookie(GATE_LOGIN_COOKIE, new_nonce,
                            secure=True, httponly=True, samesite="strict",
                            path=route_paths.NONCE_COOKIE_PATH, max_age=600)
        return response
    except RuntimeError:
        raise HTTPException(503, "Admin password not provisioned") from None
    response = RedirectResponse(route_paths.ADMIN_PATH, status_code=303)
    response.set_cookie(admin_auth.COOKIE, session, httponly=True,
                        secure=True, samesite="strict",
                        path=admin_auth.COOKIE_PATH,
                        max_age=admin_auth.SESSION_SECONDS)
    response.delete_cookie(GATE_LOGIN_COOKIE, path=route_paths.NONCE_COOKIE_PATH)
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
        "username": session["username"] if session else None,
        "role": session["role"] if session else None,
    }


@console.post("/api/auth/login")
def auth_login(request: Request, response: Response, payload: dict[str, Any]):
    if not admin_auth.same_origin(request):
        raise HTTPException(status_code=403, detail="Secure origin required")
    if set(payload) not in ({"password"}, {"password", "username"}):
        raise HTTPException(status_code=422, detail="Expected password and optional username")
    try:
        session, csrf = admin_auth.login(payload["password"], username=payload.get("username", "owner"))
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


@console.get("/api/overview", dependencies=[Depends(require_admin)])
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


@console.put("/api/settings", dependencies=[Depends(require_admin)])
def settings(payload: dict[str, Any]):
    try:
        updated = ops.update(payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return {"settings": updated}


@console.get("/api/manifest", dependencies=[Depends(require_admin)])
def private_manifest_url():
    """Return the configured addon manifest URL only to authenticated Admins.

    The URL contains ADDON_TOKEN, an addon credential. Never put it into HTML,
    server logs, analytics, or an unauthenticated endpoint.
    """
    from urllib.parse import quote, urlsplit

    try:
        public = urlsplit(bridge.PUBLIC)
    except ValueError:
        public = None
    if (not public or public.scheme != "https" or not public.hostname
            or public.username or public.password or public.query or public.fragment
            or not bridge.ADDON_TOKEN):
        raise HTTPException(503, "Private manifest is not configured")
    return {
        "url": bridge.PUBLIC.rstrip("/") + "/a/"
               + quote(bridge.ADDON_TOKEN, safe="") + "/manifest.json",
        "types": ["movie"] if bridge.MOVIES_ONLY else ["movie", "series"],
    }


# v0.5a source/configuration endpoints. The existing single-provider
# /a/ and /play/ routes remain unchanged until the scoped playback stage.


@console.get("/api/my/overview")
def personal_overview(identity=Depends(authorize)):
    return {
        "username": identity["username"],
        "role": identity["role"],
        "sources": user_sources.list_owned(identity["username"]),
        "manifest_ready": False,  # v0.5c, not yet exposed to clients
    }


@console.get("/api/my/sources")
def personal_sources(identity=Depends(authorize)):
    return {"sources": user_sources.list_owned(identity["username"])}


@console.post("/api/my/sources", status_code=201)
def create_personal_source(payload: dict[str, Any], identity=Depends(authorize)):
    if set(payload) != {"kind", "name", "config"}:
        raise HTTPException(422, "Expected kind, name and config")
    try:
        source = user_sources.add_source(
            identity["username"], payload["kind"], payload["name"], payload["config"]
        )
    except RuntimeError:
        raise HTTPException(503, "Source vault unavailable") from None
    except (ValueError, TypeError):
        raise HTTPException(422, "Invalid source configuration") from None
    return {"source": source}


@console.patch("/api/my/sources/{source_id}")
def update_personal_source(source_id: str, payload: dict[str, Any],
                           identity=Depends(authorize)):
    if not payload or set(payload) - {"name", "enabled", "config"}:
        raise HTTPException(422, "Invalid source update")
    try:
        source = user_sources.change_owned(identity["username"], source_id, **payload)
    except KeyError:
        raise HTTPException(404, "Source not found") from None
    except RuntimeError:
        raise HTTPException(503, "Source vault unavailable") from None
    except (TypeError, ValueError):
        raise HTTPException(422, "Invalid source configuration") from None
    return {"source": source}


@console.delete("/api/my/sources/{source_id}")
def delete_personal_source(source_id: str, identity=Depends(authorize)):
    try:
        user_sources.remove_owned(identity["username"], source_id)
    except KeyError:
        raise HTTPException(404, "Source not found") from None
    return {"deleted": True}


@console.post("/api/my/sources/{source_id}/test")
async def test_personal_source(source_id: str, identity=Depends(authorize)):
    try:
        result = await user_sources.test_owned(identity["username"], source_id)
    except KeyError:
        raise HTTPException(404, "Source not found") from None
    except RuntimeError:
        raise HTTPException(503, "Source vault unavailable") from None
    except (ValueError, OSError, TimeoutError):
        raise HTTPException(422, "Source connection test failed") from None
    except Exception as exc:
        # Never expose URL, credentials or upstream error detail in responses.
        # HTTPX may include the password-bearing URL in its exception string.
        if isinstance(exc, (urllib.error.URLError,)):
            raise HTTPException(422, "Source connection test failed") from None
        import httpx
        if isinstance(exc, (httpx.HTTPError, socket.gaierror)):
            raise HTTPException(422, "Source connection test failed") from None
        raise
    return {"test": result}


@console.post("/api/my/sources/{source_id}/sync")
async def sync_personal_source(source_id: str, identity=Depends(authorize)):
    try:
        return {"sync": await personal_index.sync_owned(identity["username"], source_id)}
    except KeyError:
        raise HTTPException(404, "Source not found") from None
    except RuntimeError:
        raise HTTPException(503, "Source vault unavailable") from None
    except ValueError:
        raise HTTPException(422, "Sync unavailable or rate-limited") from None
    except Exception:
        # Never expose upstream exceptions: HTTPX URLs can include credentials.
        raise HTTPException(502, "Source sync failed") from None


@console.get("/api/my/manifests")
def personal_manifest_list(identity=Depends(authorize)):
    return {"manifests": personal_manifests.list_owned(identity["username"])}


@console.post("/api/my/manifests", status_code=201)
def personal_manifest_create(payload: dict[str, Any], identity=Depends(authorize)):
    if set(payload) != {"name", "sources"}:
        raise HTTPException(422, "Expected name and source IDs")
    try:
        return {"manifest": personal_manifests.create(
            identity["username"], payload["name"], payload["sources"]
        )}
    except RuntimeError:
        raise HTTPException(503, "Manifest service unavailable") from None
    except (ValueError, TypeError):
        raise HTTPException(422, "Invalid manifest configuration") from None


@console.patch("/api/my/manifests/{manifest_id}")
def personal_manifest_update(manifest_id: str, payload: dict[str, Any],
                             identity=Depends(authorize)):
    if not payload or set(payload) - {"name", "enabled", "source_ids"}:
        raise HTTPException(422, "Invalid manifest update")
    try:
        return {"manifest": personal_manifests.update(
            identity["username"], manifest_id, **payload
        )}
    except KeyError:
        raise HTTPException(404, "Manifest not found") from None
    except (ValueError, TypeError):
        raise HTTPException(422, "Invalid manifest update") from None


@console.post("/api/my/manifests/{manifest_id}/rotate")
def personal_manifest_rotate(manifest_id: str, identity=Depends(authorize)):
    try:
        return {"manifest": personal_manifests.rotate(
            identity["username"], manifest_id
        )}
    except KeyError:
        raise HTTPException(404, "Manifest not found") from None
    except RuntimeError:
        raise HTTPException(503, "Manifest service unavailable") from None


@console.delete("/api/my/manifests/{manifest_id}")
def personal_manifest_delete(manifest_id: str, identity=Depends(authorize)):
    try:
        personal_manifests.delete(identity["username"], manifest_id)
    except KeyError:
        raise HTTPException(404, "Manifest not found") from None
    return {"deleted": True}


@console.get("/api/system/users")
def system_users(identity=Depends(require_admin)):
    return {"users": admin_users.list_users()}


@console.post("/api/system/users", status_code=201)
def system_create_user(payload: dict[str, Any],
                       identity=Depends(require_admin)):
    if set(payload) != {"username", "password"}:
        raise HTTPException(422, "Expected username and password")
    try:
        return {"user": admin_users.create_user(payload["username"], payload["password"])}
    except (ValueError, TypeError):
        raise HTTPException(422, "Invalid user configuration") from None


@console.patch("/api/system/users/{username}")
def system_update_user(username: str, payload: dict[str, Any],
                       identity=Depends(require_admin)):
    if not payload or set(payload) - {"enabled", "password"}:
        raise HTTPException(422, "Invalid account changes")
    try:
        return {"user": admin_users.change_user(username, **payload)}
    except KeyError:
        raise HTTPException(404, "User not found") from None
    except (ValueError, TypeError):
        raise HTTPException(422, "Invalid account changes") from None


@console.delete("/api/system/users/{username}")
def system_delete_user(username: str, identity=Depends(require_admin)):
    try:
        admin_users.delete_user(username)
    except KeyError:
        raise HTTPException(404, "User not found") from None
    except ValueError:
        raise HTTPException(422, "Delete personal sources first; owner is protected") from None
    return {"deleted": True}


@console.get("/api/events", dependencies=[Depends(require_admin)])
def events():
    return {"events": ops.events(limit=100)}
