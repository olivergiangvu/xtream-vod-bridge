"""Offline HMAC-v5 Range/206, HEAD, TLS-pin and revocation canary."""
import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

import httpx
from cryptography.fernet import Fernet
from fastapi import HTTPException
from starlette.requests import Request

import admin_auth
import admin_users
import app as bridge
import ops
import personal_index
import personal_manifests
import personal_playback
import user_sources


class FakeHTTPClient:
    instances = []
    status = 206
    bytes_data = b"TEST"
    def __init__(self, *args, **kwargs):
        self.options = kwargs
        self.request = None
        self.closed = False
        FakeHTTPClient.instances.append(self)

    def build_request(self, method, url, *, headers, extensions):
        self.request = SimpleNamespace(
            method=method, url=url, headers=headers, extensions=extensions
        )
        return self.request

    async def send(self, req, *, stream):
        self.request = req
        return httpx.Response(
            self.status,
            headers={"Content-Type": "video/mp4", "Content-Range": "bytes 0-3/1000",
                     "Content-Length": "4", "Accept-Ranges": "bytes"},
            stream=httpx.ByteStream(self.bytes_data),
        )

    async def aclose(self):
        self.closed = True


class Personal206Tests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.patches = [
            patch.object(ops, "PATH", Path(tmp.name) / "index.sqlite"),
            patch.object(admin_auth, "PUBLIC_ORIGIN", "https://admin.invalid:18450"),
            patch.object(bridge, "PUBLIC", "https://stream.example:18450"),
            patch.dict(os.environ, {
                "SOURCE_SECRETS_KEY": Fernet.generate_key().decode(),
            }),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        ops.init()
        admin_auth.init()
        admin_auth.set_password("Long test owner password 2026")
        admin_users.create_user("alice", "Long test user password 2026")
        self.sid = user_sources.add_source(
            "alice", "m3u", "My IPTV",
            {"playlist_url": "https://provider.example/playlist.m3u?key=private"},
        )["source_id"]
        playlist = (
            b"#EXTM3U\n"
            b'#EXTINF:-1 imdb-id="tt1234567",Sample Movie\n'
            b"https://cdn.example.org/film.mp4?token=secret\n"
        )
        with patch.object(user_sources, "_bounded_https",
                          new=AsyncMock(return_value=playlist)):
            await personal_index.sync_owned("alice", self.sid)
        m = personal_manifests.create("alice", "Personal VOD", [self.sid])
        token = urlsplit(m["url"]).path.split("/a/", 1)[1].split("/", 1)[0]
        stream = personal_playback.streams(token, "movie", "tt1234567")["streams"][0]
        self.parts = urlsplit(stream["url"]).path.split("/play/v5/", 1)[1].split("/")
        self.assertEqual(len(self.parts), 9)

    def request(self, method, headers=None):
        return Request({
            "type": "http", "http_version": "1.1",
            "method": method, "scheme": "https",
            "path": "/play/v5/mock",
            "query_string": b"",
            "headers": [(k.lower().encode(), v.encode())
                        for k, v in (headers or {}).items()],
            "client": ("127.0.0.1", 1234),
            "server": ("example.invalid", 18450),
        })

    async def test_range_206_relay_pins_ip_and_sni(self):
        FakeHTTPClient.instances = []
        FakeHTTPClient.status = 206
        FakeHTTPClient.bytes_data = b"TEST"
        with patch.object(user_sources, "_resolve_public",
                          new=AsyncMock(return_value="8.8.8.8")), \
             patch.object(personal_playback.httpx, "AsyncClient", FakeHTTPClient):
            response = await personal_playback.relay(
                *self.parts, self.request("GET", {"Range": "bytes=0-3"})
            )
            self.assertEqual(response.status_code, 206)
            payload = b"".join([b async for b in response.body_iterator])
            self.assertEqual(payload, b"TEST")
        self.assertEqual(len(FakeHTTPClient.instances), 1)
        c = FakeHTTPClient.instances[0]
        self.assertTrue(c.closed)
        self.assertEqual(c.request.headers["Range"], "bytes=0-3")
        self.assertIn("8.8.8.8", c.request.url)
        self.assertEqual(c.request.headers["Host"], "cdn.example.org")
        self.assertEqual(c.request.extensions["sni_hostname"], "cdn.example.org")
        self.assertFalse(c.options["trust_env"])
        self.assertFalse(c.options["follow_redirects"])

    async def test_head_and_range_refusal(self):
        FakeHTTPClient.instances = []
        FakeHTTPClient.status = 200
        with patch.object(user_sources, "_resolve_public",
                          new=AsyncMock(return_value="8.8.8.8")), \
             patch.object(personal_playback.httpx, "AsyncClient", FakeHTTPClient):
            head = await personal_playback.relay(
                *self.parts, self.request("HEAD")
            )
            self.assertEqual(head.status_code, 200)
            self.assertEqual(head.headers["content-length"], "4")
            self.assertTrue(FakeHTTPClient.instances[-1].closed)

            with self.assertRaises(HTTPException) as context:
                await personal_playback.relay(
                    *self.parts, self.request("GET", {"Range": "bytes=0-3"})
                )
            self.assertEqual(context.exception.status_code, 502)
            self.assertTrue(FakeHTTPClient.instances[-1].closed)

    async def test_bad_range_or_revoked_manifest_never_reaches_upstream(self):
        with patch.object(user_sources, "_resolve_public",
                          new=AsyncMock(return_value="8.8.8.8")) as resolver:
            for bad in ("bytes=0-1,5-6", "bytes=-", "bits=0-9"):
                with self.subTest(range=bad):
                    with self.assertRaises(HTTPException):
                        await personal_playback.relay(
                            *self.parts, self.request("GET", {"Range": bad})
                        )
            resolver.assert_not_awaited()

            personal_manifests.delete("alice", self.parts[0])
            with self.assertRaises(HTTPException) as exc:
                await personal_playback.relay(
                    *self.parts, self.request("GET")
                )
            self.assertEqual(exc.exception.status_code, 404)
            resolver.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
