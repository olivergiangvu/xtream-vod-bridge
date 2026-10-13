"""Private admin control-plane: separate Docker port, never proxied publicly.

Accessible only via SSH tunnel to 127.0.0.1:18768 on the HomeDocker host.
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

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

import app as bridge
import ops
import provider_store

ROOT = Path(__file__).resolve().parent / "admin"
BRIDGE_HEALTH = "http://xtream-vod-bridge:8767/health"


@asynccontextmanager
async def lifespan(_app):
    ops.init()
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


def authorize(authorization: str = Header(default="")):
    token = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else ""
    if not bridge.ADMIN_TOKEN or not hmac.compare_digest(token, bridge.ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Bearer"})


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


# Provider entries are intentionally STAGED. They cannot appear in Stremio
# until the isolated provider-aware playback router passes its own tests.
@console.get("/api/providers", dependencies=[Depends(authorize)])
def providers():
    if not provider_store.installed():
        return {"key_configured": False, "providers": [],
                "streaming_activation": False}
    try:
        return {"key_configured": True, "providers": provider_store.list_profiles(),
                "streaming_activation": False}
    except provider_store.RegistryUnavailable:
        raise HTTPException(503, "Provider decryption key is unavailable") from None


@console.post("/api/providers", dependencies=[Depends(authorize)], status_code=201)
def provider_add(payload: dict[str, Any]):
    try:
        return provider_store.create_profile(payload)
    except provider_store.RegistryUnavailable:
        raise HTTPException(503, "Provider encryption key is not configured") from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@console.patch("/api/providers/{provider_id}", dependencies=[Depends(authorize)])
def provider_edit(provider_id: str, payload: dict[str, Any]):
    try:
        return provider_store.update_profile(provider_id, payload)
    except provider_store.RegistryUnavailable:
        raise HTTPException(503, "Provider encryption key is not configured") from None
    except KeyError:
        raise HTTPException(404, "Provider not found") from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@console.delete("/api/providers/{provider_id}", dependencies=[Depends(authorize)])
def provider_delete(provider_id: str):
    try:
        provider_store.delete_profile(provider_id)
        return {"status": "deleted"}
    except provider_store.RegistryUnavailable:
        raise HTTPException(503, "Provider encryption key is not configured") from None
    except KeyError:
        raise HTTPException(404, "Provider not found") from None
