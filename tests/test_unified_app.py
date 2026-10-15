"""Offline one-process Xtream application routing, lifecycle and liveness tests."""
import asyncio
from contextlib import asynccontextmanager
import unittest
from unittest.mock import patch

import httpx
import unified_app as unified


class UnifiedAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def request(self, path, **kwargs):
        transport = httpx.ASGITransport(app=unified.application)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://localhost", follow_redirects=False
        ) as client:
            return await client.get(path, **kwargs)

    async def test_constant_time_liveness_without_sql(self):
        with patch.object(
            unified.playback, "db",
            side_effect=AssertionError("DB must not be called from /live")
        ):
            response = await self.request("/live")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    async def test_admin_and_playback_routes_resolve_on_same_app(self):
        paths = [route.path for route in unified.application.router.routes]
        self.assertIn("/a/{token}/manifest.json", paths)
        self.assertIn("/health", paths)
        # Starlette normalizes Mount("/") to an empty path string.
        self.assertEqual(paths[-1], "")

        page = await self.request("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn('id="adminWorkspace"', page.text)

        gateway = await self.request("/gateway/")
        self.assertEqual(gateway.status_code, 200)
        self.assertIn('action="/admin-signin/"', gateway.text)
        self.assertIn("httponly", gateway.headers["set-cookie"].lower())

        assets = await self.request("/assets/app.js")
        self.assertEqual(assets.status_code, 200)
        self.assertIn("javascript", assets.headers["content-type"])

        auth = await self.request("/api/auth/gate-check")
        self.assertEqual(auth.status_code, 401)

    async def test_readiness_only_does_select_one(self):
        class DB:
            def __init__(self):
                self.query = None
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return None
            def execute(self, query):
                self.query = query
                return self
            def fetchone(self):
                return (1,)
        db = DB()
        with patch.object(unified.playback, "db", return_value=db):
            response = await self.request("/ready")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(db.query, "SELECT 1")

    async def test_not_ready_does_not_leak_db_errors(self):
        with patch.object(unified.playback, "db",
                          side_effect=OSError("private-db-path")):
            response = await self.request("/ready")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("private-db-path", response.text)

    async def test_lifespans_started_once_and_orderly_shutdown(self):
        events = []

        @asynccontextmanager
        async def playback_lifespan(_):
            events.append("play-start")
            try:
                yield
            finally:
                events.append("play-stop")

        @asynccontextmanager
        async def admin_lifespan(_):
            events.append("admin-start")
            try:
                yield
            finally:
                events.append("admin-stop")

        with patch.object(unified.playback, "lifespan", playback_lifespan), \
             patch.object(unified.admin_ui, "lifespan", admin_lifespan):
            async with unified.unified_lifespan(unified.application):
                events.append("active")
        self.assertEqual(events, [
            "play-start", "admin-start", "active", "admin-stop", "play-stop"
        ])


if __name__ == "__main__":
    unittest.main()
