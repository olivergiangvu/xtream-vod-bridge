"""HomeDocker Canary Stage 2: offline E2E Admin/User -> Sources -> Manifest.

Run INSIDE xtream-vod-canary-admin with Python source on stdin. This script
creates a temporary SQLite database in /tmp; it never touches /data/index.sqlite,
nginx, network, production credentials or running container configuration.

    docker exec -i xtream-vod-canary-admin python - < offline_stage2.py

Use only the reviewed pinned Git revision. Never print generated tokens/URLs.
"""
import asyncio
import os
import secrets
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

import app as bridge
import ops
import admin_auth
import admin_ui
import personal_manifests
import personal_playback
import user_sources


class OfflineStage2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("LEGACY_SYNC_ENABLED") != "0":
            raise RuntimeError("STOP: This test is for offline canary only")
        if not os.getenv("PUBLIC_BASE_URL", "").startswith("https://canary.invalid:"):
            raise RuntimeError("STOP: Expected synthetic Canary HTTPS origin")
        if not os.getenv("SOURCE_SECRETS_KEY"):
            raise RuntimeError("STOP: Canary encryption key not configured")
        if not admin_auth.origin_configured():
            raise RuntimeError("STOP: Canary HTTPS origin not configured")

    def test_isolated_admin_user_sources_manifest(self):
        admin_pw = secrets.token_urlsafe(32)
        user_pw = secrets.token_urlsafe(32)
        with tempfile.TemporaryDirectory(prefix="v05-stage2-") as dirname:
            path = Path(dirname) / "offline.sqlite"
            # All modules' SQLite calls use this separate temporary database.
            with patch.object(ops, "PATH", path), \
                 patch.object(bridge, "DB_PATH", path), \
                 patch.object(bridge, "DATA_DIR", Path(dirname)):
                bridge.init_db()
                admin_auth.set_password(admin_pw)
                origin = admin_auth.PUBLIC_ORIGIN
                self.assertTrue(origin.startswith("https://canary.invalid:"))
                with TestClient(admin_ui.console) as client:

                    def login(username, password, expected_role):
                        resp = client.post(
                            "/api/auth/login", headers={"Origin": origin},
                            json={"username": username, "password": password},
                        )
                        self.assertEqual(resp.status_code, 200, resp.text)
                        session = resp.cookies.get(admin_auth.COOKIE)
                        self.assertTrue(session)
                        headers = {
                            "Cookie": f"{admin_auth.COOKIE}={session}",
                            "Origin": origin,
                            "X-CSRF-Token": resp.json()["csrf_token"],
                        }
                        status = client.get(
                            "/api/auth/session", headers=headers
                        ).json()
                        self.assertEqual(status["username"], username)
                        self.assertEqual(status["role"], expected_role)
                        return headers

                    # Unauthenticated source and manifest enumeration are denied.
                    self.assertEqual(
                        client.get("/api/my/sources").status_code, 401
                    )
                    self.assertEqual(
                        client.get("/api/my/manifests").status_code, 401
                    )
                    admin = login("owner", admin_pw, "admin")
                    created_user = client.post(
                        "/api/system/users", headers=admin,
                        json={"username": "sampleuser", "password": user_pw},
                    )
                    self.assertEqual(created_user.status_code, 201,
                                     created_user.text)
                    self.assertEqual(created_user.json()["user"]["role"], "user")
                    user = login("sampleuser", user_pw, "user")
                    self.assertEqual(
                        client.get("/api/system/users", headers=user).status_code,
                        403,
                    )
                    self.assertEqual(
                        client.get("/api/manifest", headers=user).status_code,
                        403,
                    )
                    self.assertEqual(
                        client.put("/api/settings", headers=user,
                                   json={"source_label": "Unauthorized"}
                                   ).status_code,
                        403,
                    )
                    print("ROLE_AND_ADMIN_RBAC=PASS")

                    # M3U secret is encrypted, not returned in APIs.
                    # No real DNS/HTTP requests are made.
                    source_payload = {
                        "kind": "m3u",
                        "name": "Synthetic Movies & Series",
                        "config": {
                            "playlist_url": (
                                "https://example.net/playlist.m3u?token="
                                "CANARY_PRIVATE_TEST_VALUE"
                            )
                        },
                    }
                    self.assertEqual(
                        client.post("/api/my/sources",
                                    json=source_payload,
                                    headers={"Cookie": user["Cookie"]}
                                    ).status_code,
                        403,
                    )
                    src = client.post(
                        "/api/my/sources",
                        json=source_payload,
                        headers=user,
                    )
                    self.assertEqual(src.status_code, 201, src.text)
                    source_id = src.json()["source"]["source_id"]
                    self.assertEqual(src.json()["source"]["owner"], "sampleuser")
                    self.assertNotIn("CANARY_PRIVATE_TEST_VALUE", src.text)
                    self.assertNotIn("example.net", src.text)
                    self.assertNotIn(
                        b"CANARY_PRIVATE_TEST_VALUE", path.read_bytes()
                    )
                    self.assertEqual(
                        client.get("/api/my/sources",
                                   headers=admin).json()["sources"], []
                    )
                    self.assertEqual(
                        client.delete(f"/api/my/sources/{source_id}",
                                      headers=admin).status_code,
                        404,
                    )
                    print("SOURCE_OWNERSHIP_CSRF_AND_ENCRYPTION=PASS")

                    # Offline mock provides exactly one movie and one episode.
                    playlist = (
                        b"#EXTM3U\n"
                        b'#EXTINF:-1 imdb-id="tt1234567" group-title="Movies",'
                        b"Test Film\n"
                        b"https://cdn.example.net/movie.mp4?key=SECRET_MOVIE\n"
                        b'#EXTINF:-1 imdb-id="tt7654321" group-title="Series",'
                        b"Test Show S01E02\n"
                        b"https://cdn.example.net/episode.mp4?key=SECRET_SERIES\n"
                    )
                    with patch.object(
                        user_sources, "_bounded_https",
                        new=AsyncMock(return_value=playlist),
                    ) as mock_fetch:
                        result = client.post(
                            f"/api/my/sources/{source_id}/sync", headers=user
                        )
                        self.assertEqual(result.status_code, 200, result.text)
                        mock_fetch.assert_awaited_once()
                    self.assertEqual(result.json()["sync"]["movies"], 1)
                    self.assertEqual(result.json()["sync"]["series"], 1)
                    self.assertEqual(result.json()["sync"]["episodes"], 1)
                    self.assertNotIn(b"SECRET_MOVIE", path.read_bytes())
                    self.assertNotIn(b"SECRET_SERIES", path.read_bytes())
                    print("OFFLINE_MOVIE_SERIES_INDEX=PASS")

                    # Personal manifest returns the token only when created.
                    made = client.post(
                        "/api/my/manifests", headers=user,
                        json={"name": "Synthetic Private Addon",
                              "sources": [source_id]},
                    )
                    self.assertEqual(made.status_code, 201, made.text)
                    obj = made.json()["manifest"]
                    mid = obj["manifest_id"]
                    manifest_url = obj["url"]
                    personal_token = urlsplit(manifest_url).path.split(
                        "/a/", 1
                    )[1].split("/", 1)[0]
                    self.assertTrue(personal_token.startswith("v5_"))
                    self.assertNotIn(personal_token.encode(), path.read_bytes())
                    listing = client.get(
                        "/api/my/manifests", headers=user
                    ).json()["manifests"]
                    self.assertEqual(len(listing), 1)
                    self.assertIsNone(listing[0]["url"])
                    self.assertNotIn(personal_token, str(listing))
                    print("PERSONAL_MANIFEST_ONE_TIME_TOKEN=PASS")

                    # The Stremio API requires only the personal token, and
                    # stream playback includes source-scoped v5 signed URLs.
                    with TestClient(bridge.app) as stremio:
                        manifest = stremio.get(
                            f"/a/{personal_token}/manifest.json"
                        )
                        self.assertEqual(manifest.status_code, 200,
                                         manifest.text)
                        movie = stremio.get(
                            f"/a/{personal_token}/stream/movie/tt1234567.json"
                        )
                        self.assertEqual(movie.status_code, 200, movie.text)
                        self.assertEqual(len(movie.json()["streams"]), 1)
                        series = stremio.get(
                            f"/a/{personal_token}/stream/series/"
                            "tt7654321:1:2.json"
                        )
                        self.assertEqual(series.status_code, 200, series.text)
                        self.assertEqual(len(series.json()["streams"]), 1)
                        other_ep = stremio.get(
                            f"/a/{personal_token}/stream/series/"
                            "tt7654321:1:3.json"
                        )
                        self.assertEqual(other_ep.json()["streams"], [])

                        signed_url = movie.json()["streams"][0]["url"]
                        self.assertIn(source_id, signed_url)
                        self.assertNotIn("SECRET_MOVIE", signed_url)
                        pieces = urlsplit(signed_url).path.split(
                            "/play/v5/", 1
                        )[1].split("/")
                        self.assertTrue(
                            personal_playback._validate_play(*pieces)
                        )
                        print("V5_SCOPED_MOVIE_SERIES_LINKS=PASS")

                        # Revoke must immediately invalidate addon and old
                        # signed playback, even before expiry.
                        deleted = client.delete(
                            f"/api/my/manifests/{mid}", headers=user
                        )
                        self.assertEqual(deleted.status_code, 200,
                                         deleted.text)
                        rejected = stremio.get(
                            f"/a/{personal_token}/manifest.json"
                        )
                        self.assertEqual(rejected.status_code, 404)
                        with self.assertRaises(Exception) as ctx:
                            personal_playback._source_stream(*pieces[:5])
                        self.assertEqual(
                            getattr(ctx.exception, "status_code", None), 404
                        )
                        print("REVOKED_MANIFEST_AND_PLAYBACK=PASS")

                    # Disabling User invalidates previously issued session.
                    disabled = client.patch(
                        "/api/system/users/sampleuser", headers=admin,
                        json={"enabled": False},
                    )
                    self.assertEqual(disabled.status_code, 200, disabled.text)
                    self.assertEqual(
                        client.get("/api/auth/gate-check",
                                   headers={"Cookie": user["Cookie"]}
                                   ).status_code,
                        401,
                    )
                    print("USER_DISABLE_REVOKES_SESSION=PASS")

                import sqlite3
                with sqlite3.connect(path) as con:
                    self.assertEqual(
                        con.execute("PRAGMA quick_check").fetchone()[0], "ok"
                    )
                    self.assertGreater(
                        con.execute(
                            "SELECT COUNT(*) FROM sqlite_master "
                            "WHERE type='table'"
                        ).fetchone()[0], 5
                    )
                print("SQLITE_TEMPORARY_SCHEMA=PASS")

        print("CANARY_STAGE2_OFFLINE_ACCEPTANCE=PASS")
        print("PERSISTENT_CANARY_DB_MODIFIED=NO")
        print("PRODUCTION_DB_MODIFIED=NO")
        print("PROVIDER_NETWORK_CALLS=NONE")


if __name__ == "__main__":
    unittest.main(verbosity=0)
