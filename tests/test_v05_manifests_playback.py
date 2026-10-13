"""No-network scoped-manifest and tenant-index regression tests for v0.5c."""
import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from fastapi import HTTPException
from fastapi.testclient import TestClient

import ops
import app as bridge
import admin_auth
import admin_ui
import personal_index
import personal_manifests
import personal_playback
import user_sources

ORIGIN = "https://admin.example.org:18450"
ADMIN_PASSWORD = "Long admin production-style password 2026"
USER_PASSWORD = "Long user sample password 2026"
TOKEN = {"Authorization": "Bearer " + "b" * 40}


class V05ScopeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        patches = [
            patch.object(ops, "PATH", Path(temp.name) / "index.sqlite"),
            patch.object(admin_auth, "PUBLIC_ORIGIN", ORIGIN),
            patch.object(admin_auth, "LAN_ORIGIN", ""),
            patch.object(bridge, "PUBLIC", "https://example.invalid:18450"),
            patch.dict(os.environ, {
                "SOURCE_SECRETS_KEY": Fernet.generate_key().decode(),
            }),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        ops.init()
        admin_auth.init()
        admin_auth.set_password(ADMIN_PASSWORD)
        user_sources.init()
        personal_index.init()
        personal_manifests.init()
        self.client = TestClient(admin_ui.console)
        self.addCleanup(self.client.close)
        self._create_user("alice")
        self._create_user("bobby")
        self.alice = self._login("alice")
        self.bobby = self._login("bobby")

    def _create_user(self, username):
        r = self.client.post(
            "/api/system/users", headers=TOKEN,
            json={"username": username, "password": USER_PASSWORD},
        )
        self.assertEqual(r.status_code, 201, r.text)

    def _login(self, username):
        r = self.client.post(
            "/api/auth/login",
            headers={"Origin": ORIGIN},
            json={"username": username, "password": USER_PASSWORD},
        )
        self.assertEqual(r.status_code, 200, r.text)
        return {
            "Cookie": admin_auth.COOKIE + "=" + r.cookies[admin_auth.COOKIE],
            "Origin": ORIGIN,
            "X-CSRF-Token": r.json()["csrf_token"],
        }

    def _source(self, headers, kind="m3u"):
        payload = (
            {"kind": "m3u", "name": "User Playlist",
             "config": {"playlist_url":
                        "https://provider.example/playlist.m3u?token=private"}}
            if kind == "m3u" else
            {"kind": "xtream", "name": "Xtream User",
             "config": {"base_url": "https://provider.example:8443",
                        "username": "hiddenuser", "password": "hiddenpassword"}}
        )
        r = self.client.post("/api/my/sources", headers=headers, json=payload)
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()["source"]["source_id"]

    def _manifest(self, headers, source_ids):
        r = self.client.post(
            "/api/my/manifests", headers=headers,
            json={"name": "My VOD Addon", "sources": source_ids},
        )
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()["manifest"]

    @staticmethod
    def _token(url):
        return urlsplit(url).path.split("/a/", 1)[1].split("/", 1)[0]

    def test_private_manifest_token_is_one_time_and_source_scoped(self):
        mine = self._source(self.alice)
        other = self._source(self.bobby)
        wrong = self.client.post(
            "/api/my/manifests", headers=self.alice,
            json={"name": "Wrong", "sources": [other]},
        )
        self.assertEqual(wrong.status_code, 422)
        created = self._manifest(self.alice, [mine])
        raw = self._token(created["url"])
        self.assertTrue(raw.startswith("v5_"))
        self.assertTrue(created["one_time_only"])
        self.assertEqual(
            personal_manifests.resolve_token(raw)["sources"], [mine]
        )
        listing = self.client.get(
            "/api/my/manifests", headers=self.alice
        ).json()["manifests"]
        self.assertIsNone(listing[0]["url"])
        self.assertNotIn(raw, str(listing))
        self.assertNotIn(raw.encode(), Path(ops.PATH).read_bytes())
        self.assertEqual(
            self.client.get("/api/my/manifests", headers=self.bobby).json()["manifests"],
            [],
        )
        self.assertEqual(
            self.client.post(
                "/api/my/manifests/" + created["manifest_id"] + "/rotate",
                headers=self.bobby,
            ).status_code, 404,
        )

        new = self.client.post(
            "/api/my/manifests/" + created["manifest_id"] + "/rotate",
            headers=self.alice,
        )
        self.assertEqual(new.status_code, 200)
        rotated = self._token(new.json()["manifest"]["url"])
        self.assertNotEqual(raw, rotated)
        self.assertIsNone(personal_manifests.resolve_token(raw))
        self.assertIsNotNone(personal_manifests.resolve_token(rotated))

        disabled = self.client.patch(
            "/api/my/manifests/" + created["manifest_id"],
            headers=self.alice, json={"enabled": False},
        )
        self.assertEqual(disabled.status_code, 200)
        self.assertIsNone(personal_manifests.resolve_token(rotated))

    def test_m3u_exact_ids_index_then_personal_stremio_movie_series(self):
        source = self._source(self.alice)
        payload = (
            b"#EXTM3U\n"
            b'#EXTINF:-1 imdb-id="tt1234567" group-title="Movies",Movie (2020)\n'
            b"https://cdn.example.org/movie.mp4?token=private123\n"
            b'#EXTINF:-1 imdb-id="tt7654321" group-title="Series",'
            b"Series S01E02\n"
            b"https://cdn.example.org/episode.mkv?token=private456\n"
            b'#EXTINF:-1 group-title="Live",TV News\n'
            b"https://cdn.example.org/channel.ts\n"
        )
        with patch.object(user_sources, "_bounded_https",
                          new=AsyncMock(return_value=payload)):
            sync = self.client.post(
                "/api/my/sources/" + source + "/sync", headers=self.alice,
            )
        self.assertEqual(sync.status_code, 200, sync.text)
        self.assertEqual(sync.json()["sync"]["movies"], 1)
        self.assertEqual(sync.json()["sync"]["series"], 1)
        self.assertEqual(sync.json()["sync"]["episodes"], 1)
        contents = Path(ops.PATH).read_bytes()
        self.assertNotIn(b"private123", contents)
        self.assertNotIn(b"private456", contents)
        self.assertNotIn(b"cdn.example.org", contents)

        token = self._token(self._manifest(self.alice, [source])["url"])
        metadata = asyncio.run(bridge.manifest(token))
        self.assertEqual(metadata["types"], ["movie", "series"])
        movie = asyncio.run(bridge.streams(token, "movie", "tt1234567"))
        self.assertEqual(len(movie["streams"]), 1)
        url = movie["streams"][0]["url"]
        self.assertIn("/play/v5/", url)
        self.assertIn("/" + source + "/", url)
        self.assertNotIn("private123", url)

        episode = asyncio.run(bridge.streams(token, "series", "tt7654321:1:2"))
        self.assertEqual(len(episode["streams"]), 1)
        self.assertIn("/play/v5/", episode["streams"][0]["url"])
        missing = asyncio.run(bridge.streams(token, "series", "tt7654321:1:3"))
        self.assertEqual(missing["streams"], [])
        # Forged token, incorrect media and absent metadata do not match.
        self.assertEqual(asyncio.run(
            bridge.streams(token, "movie", "tt0000000")
        )["streams"], [])
        with self.assertRaises(HTTPException):
            asyncio.run(bridge.manifest("v5_" + "x" * 48))

        parsed = urlsplit(url).path.split("/play/v5/", 1)[1].split("/")
        mid, sid, kind, item, stream, identity, expiry, sig, filename = parsed
        self.assertTrue(personal_playback._validate_play(
            mid, sid, kind, item, stream, identity, expiry, sig, filename
        ))
        self.assertFalse(personal_playback._validate_play(
            mid, sid, kind, item, "wrong", identity, expiry, sig, filename
        ))

        self.assertIsNotNone(
            personal_playback._source_stream(mid, sid, kind, item, stream)
        )
        self.client.delete(
            "/api/my/manifests/" + mid, headers=self.alice,
        )
        with self.assertRaises(HTTPException):
            personal_playback._source_stream(mid, sid, kind, item, stream)

    def test_xtream_indexes_explicit_metadata_without_cross_user_collision(self):
        source_a = self._source(self.alice, "xtream")
        source_b = self._source(self.bobby, "xtream")

        async def fake_xtream(url, *, params=None, limit=None):
            self.assertNotIn("hiddenpassword", url)
            action = params["action"]
            if action == "get_vod_streams":
                return b'[{"stream_id":123,"name":"Sample","imdb_id":"tt1234567","container_extension":"mkv"}]'
            if action == "get_series":
                return b'[{"series_id":55,"name":"Sample Show","imdb_id":"tt7654321"}]'
            if action == "get_series_info":
                return b'{"episodes":{"1":[{"id":202,"season":1,"episode_num":2,"title":"S01E02","container_extension":"mp4"}]}}'
            raise AssertionError("Unexpected Xtream action")

        with patch.object(user_sources, "_bounded_https", side_effect=fake_xtream):
            for src, user in ((source_a, self.alice), (source_b, self.bobby)):
                r = self.client.post(
                    "/api/my/sources/" + src + "/sync", headers=user
                )
                self.assertEqual(r.status_code, 200, r.text)

        cfg_a = self._manifest(self.alice, [source_a])
        cfg_b = self._manifest(self.bobby, [source_b])
        streams_a = asyncio.run(bridge.streams(
            self._token(cfg_a["url"]), "movie", "tt1234567"
        ))["streams"]
        streams_b = asyncio.run(bridge.streams(
            self._token(cfg_b["url"]), "movie", "tt1234567"
        ))["streams"]
        self.assertEqual(len(streams_a), 1)
        self.assertEqual(len(streams_b), 1)
        self.assertIn(source_a, streams_a[0]["url"])
        self.assertNotIn(source_b, streams_a[0]["url"])
        self.assertIn(source_b, streams_b[0]["url"])
        self.assertNotIn(source_a, streams_b[0]["url"])

        episode = asyncio.run(bridge.streams(
            self._token(cfg_a["url"]), "series", "tt7654321:1:2"
        ))
        self.assertEqual(len(episode["streams"]), 1)

    def test_manifest_api_cannot_be_read_without_browser_session(self):
        self.assertEqual(self.client.get("/api/my/manifests").status_code, 401)
        self.assertEqual(
            self.client.post("/api/my/manifests", json={}).status_code, 401
        )
        self.assertEqual(
            self.client.get("/api/my/sources").status_code, 401
        )
        self.assertEqual(
            self.client.get("/api/manifest", headers=self.alice).status_code, 403
        )


if __name__ == "__main__":
    unittest.main()
