"""Single-process Xtream application: playback and Admin without a second ASGI worker.

Nginx retains the established public route allowlist and strips Admin prefixes
before proxying to this application's sole internal :8767 listener.
The Admin sub-application is mounted last so all existing playback/manifest
routes keep their precedence. Its lifespan is started explicitly exactly once:
mounted FastAPI sub-app lifespans do NOT run automatically.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

import app as playback
import admin_ui


@asynccontextmanager
async def unified_lifespan(_application):
    async with playback.lifespan(playback.app):
        async with admin_ui.lifespan(admin_ui.console):
            yield


application = FastAPI(
    title="Xtream VOD Unified",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=unified_lifespan,
)


@application.get("/live", include_in_schema=False)
async def live():
    """O(1) liveness: no SQL, provider, filesystem or external network I/O."""
    return {"status": "ok"}


@application.get("/ready", include_in_schema=False)
async def ready():
    """Cheap, on-demand database readiness; never scan catalog tables."""
    try:
        with playback.db() as connection:
            connection.execute("SELECT 1").fetchone()
    except Exception:
        raise HTTPException(status_code=503, detail="Not ready") from None
    return {"status": "ready"}


# Preserve ALL existing playback routes including /health compatibility.
# There is no second Uvicorn instance, port or independent scheduler.
application.router.routes.extend(playback.app.router.routes)

# Keep every Admin API, security-header middleware, gate and static route
# unchanged. Production nginx prefixes are stripped before proxying.
# Mount order is important: playback routes above must have precedence.
application.mount("/", admin_ui.console)
