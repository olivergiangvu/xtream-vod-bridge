"""v0.5a Admin/User RBAC, personal Xtream/M3U source security tests.

All upstream requests are mocked. Never uses real source credentials/network.
"""
import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

import ops
import admin_auth
import admin_ui
import user_sources

ORIGIN = "https://admin.example.org:18450"
ADMIN_PASSWORD = "A long test owner password 2026"
USER_PASSWORD = "A secure sample user password 2026"
TOKEN = {"Authorization": "Bearer " + "b" * 40}


class TenantBackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.patches = [
            patch.object(ops, "PATH", Path(self.temp.name) / "index.sqlite"),
            patch.object(admin_auth, "PUBLIC_ORIGIN", ORIGIN),
            patch.object(admin_auth, "LAN_ORIGIN", ""),
            patch.dict(os.environ, {
                "SOURCE_SECRETS_KEY": Fernet.generate_key().decode("ascii"),
            }),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        ops.init()
        admin_auth.init()
        admin_auth.set_password(ADMIN_PASSWORD)
        user_sources.init()
        self.client = TestClient(admin_ui.console)
        self.addCleanup(self.client.close)

    def login(self, username, password):
        response = self.client.post(
            "/api/auth/login", headers={"Origin": ORIGIN},
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200, response.text)
        session = response.cookies.get(admin_auth.COOKIE)
        self.assertTrue(session)
        return {
            "Cookie": admin_auth.COOKIE + "=" + session,
            "Origin": ORIGIN,
            "X-CSRF-Token": response.json()["csrf_token"],
        }

    def new_user(self, username):
        response = self.client.post(
            "/api/system/users", headers=TOKEN,
            json={"username": username, "password": USER_PASSWORD},
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["user"]["role"], "user")

    def test_role_model_exactly_admin_user_and_legacy_owner_unchanged(self):
        owner = self.login("owner", ADMIN_PASSWORD)
        status = self.client.get("/api/auth/session", headers=owner)
        self.assertEqual(status.json()["role"], "admin")
        self.assertEqual(status.json()["username"], "owner")
        self.new_user("alice")
        user = self.login("alice", USER_PASSWORD)
        self.assertEqual(
            self.client.get("/api/auth/session", headers=user).json()["role"], "user"
        )
        listing = self.client.get("/api/system/users", headers=owner)
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(
            {r["role"] for r in listing.json()["users"]},
            {"admin", "user"},
        )
        self.assertNotIn(USER_PASSWORD, listing.text)
        self.assertNotIn("salt", listing.text)
        self.assertEqual(
            self.client.get("/api/system/users", headers=user).status_code, 403
        )
        self.assertEqual(
            self.client.get("/api/manifest", headers=user).status_code, 403
        )
        self.assertEqual(
            self.client.get("/api/overview", headers=user).status_code, 403
        )
        self.assertEqual(
            self.client.put("/api/settings", headers=user,
                json={"source_label": "Attacker"}).status_code, 403
        )
        self.assertEqual(
            self.client.get("/api/my/overview", headers=user).json()["manifest_ready"],
            False,
        )

    def test_csrf_guard_user_creation_and_revocation(self):
        self.new_user("alice")
        headers = self.login("alice", USER_PASSWORD)
        no_csrf = {"Cookie": headers["Cookie"]}
        payload = {
            "kind": "xtream", "name": "Alice's IPTV",
            "config": {
                "base_url": "https://provider.example:8443",
                "username": "privateuser",
                "password": "privatepassword",
            },
        }
        self.assertEqual(
            self.client.post("/api/my/sources", headers=no_csrf,
                json=payload).status_code, 403
        )
        self.assertEqual(
            self.client.post("/api/my/sources",
                headers={**headers, "Origin": "https://evil.invalid"},
                json=payload).status_code, 403
        )
        created = self.client.post("/api/my/sources", headers=headers, json=payload)
        self.assertEqual(created.status_code, 201, created.text)
        source = created.json()["source"]
        self.assertEqual(source["owner"], "alice")
        self.assertNotIn("password", str(source))
        self.assertNotIn("provider.example", str(source))
        data = Path(ops.PATH).read_bytes()
        self.assertNotIn(b"privatepassword", data)
        self.assertNotIn(b"privateuser", data)
        self.assertNotIn(b"provider.example", data)
        self.assertEqual(len(self.client.get(
            "/api/my/sources", headers=headers).json()["sources"]), 1)

        # Disable revokes the session immediately, including nginx gate-check.
        change = self.client.patch(
            "/api/system/users/alice", headers=TOKEN, json={"enabled": False}
        )
        self.assertEqual(change.status_code, 200)
        self.assertEqual(
            self.client.get("/api/auth/gate-check",
                headers={"Cookie": headers["Cookie"]}).status_code, 401
        )
        self.assertEqual(
            self.client.get("/api/my/sources", headers=headers).status_code, 401
        )
        self.assertEqual(
            self.client.post("/api/auth/login", headers={"Origin": ORIGIN},
                json={"username": "alice", "password": USER_PASSWORD}).status_code, 401
        )

    def test_sources_are_never_accessible_across_users(self):
        self.new_user("alice")
        self.new_user("bobby")
        alice = self.login("alice", USER_PASSWORD)
        bob = self.login("bobby", USER_PASSWORD)
        payload = {
            "kind": "m3u", "name": "My playlist",
            "config": {"playlist_url":
                       "https://example.net/playlist.m3u?token=secretvalue"},
        }
        response = self.client.post("/api/my/sources", headers=alice, json=payload)
        self.assertEqual(response.status_code, 201, response.text)
        sid = response.json()["source"]["source_id"]
        for method, suffix, body in (
            ("PATCH", "", {"name": "Hijack"}),
            ("DELETE", "", None),
            ("POST", "/test", None),
        ):
            result = self.client.request(
                method, f"/api/my/sources/{sid}{suffix}",
                headers=bob, json=body,
            )
            self.assertEqual(result.status_code, 404, result.text)
        listing = self.client.get("/api/my/sources", headers=bob).json()
        self.assertEqual(listing["sources"], [])
        self.assertNotIn("secretvalue", str(listing))
        self.assertEqual(
            self.client.delete("/api/system/users/alice", headers=TOKEN).status_code, 422
        )

    def test_source_config_validation_rejects_ssrf_and_unsafe_inputs(self):
        self.new_user("alice")
        user = self.login("alice", USER_PASSWORD)
        for url in (
            "http://provider.example",
            "https://127.0.0.1",
            "https://169.254.169.254/latest/meta-data/",
            "https://192.168.1.1",
            "file:///etc/passwd",
            "https://user:pass@example.org/path",
            "https://provider.local/playlist.m3u",
            "https://example.org:22/playlist.m3u",
            "https://example.org/playlist.m3u#fragment",
        ):
            with self.subTest(url=url):
                payload = {"kind": "m3u", "name": "Unsafe",
                           "config": {"playlist_url": url}}
                result = self.client.post(
                    "/api/my/sources", headers=user, json=payload
                )
                self.assertEqual(result.status_code, 422, result.text)
                self.assertNotIn(url, result.text)
        missing = self.client.post(
            "/api/my/sources", headers=user,
            json={"kind": "m3u", "name": "Bad",
                  "config": {"playlist_url": "http://bad"}},
        )
        self.assertEqual(missing.status_code, 422)

    def test_m3u_test_is_bounded_and_does_not_index_or_fetch_stream_urls(self):
        self.new_user("alice")
        user = self.login("alice", USER_PASSWORD)
        payload = {"kind": "m3u", "name": "M3U",
                   "config": {"playlist_url": "https://media.example/one.m3u?token=hidden"}}
        created = self.client.post("/api/my/sources", headers=user, json=payload)
        self.assertEqual(created.status_code, 201)
        sid = created.json()["source"]["source_id"]
        playlist = (
            b"#EXTM3U\n#EXTINF:-1 group-title=\"Movies\",Sample Movie\n"
            b"https://cdn.example/stream/secretkey.mkv\n"
        )
        with patch.object(user_sources, "_bounded_https",
                          new=AsyncMock(return_value=playlist)) as fetch:
            checked = self.client.post(
                f"/api/my/sources/{sid}/test", headers=user
            )
        self.assertEqual(checked.status_code, 200, checked.text)
        self.assertEqual(checked.json()["test"]["entries"], 1)
        self.assertFalse(checked.json()["test"]["vod_ready"])
        self.assertNotIn("secretkey", checked.text)
        fetch.assert_awaited_once()
        self.assertEqual(
            user_sources._m3u_preview(b"#EXTM3U\n#EXTINF:0,Movie\n")["entries"], 1
        )

    def test_no_vault_key_fails_closed_without_plaintext_write(self):
        self.new_user("alice")
        user = self.login("alice", USER_PASSWORD)
        with patch.dict(os.environ, {"SOURCE_SECRETS_KEY": ""}):
            response = self.client.post(
                "/api/my/sources", headers=user,
                json={"kind": "m3u", "name": "Private",
                      "config": {"playlist_url":
                                "https://example.org/p.m3u?token=confidential"}},
            )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            self.client.get("/api/my/sources", headers=user).json()["sources"], []
        )

    def test_legacy_manifest_and_playback_functions_are_untouched(self):
        # Explicit stage boundary: personal sources are NOT granted access
        # to /a/ legacy global addon stream tokens.
        from test_bridge import bridge
        self.assertEqual(bridge.authorized("a" * 40), None)
        self.assertEqual(self.client.get(
            "/api/manifest", headers=self.login("owner", ADMIN_PASSWORD)
        ).status_code, 200)


class NetworkGuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_dns_rejects_any_private_answer(self):
        records = [
            (2, 1, 6, "", ("8.8.8.8", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ]
        with patch.object(user_sources.socket, "getaddrinfo",
                          return_value=records):
            with self.assertRaisesRegex(ValueError, "Non-public"):
                await user_sources._resolve_public("example.net", 443)

    async def test_dns_global_public_address_accepted(self):
        records = [(2, 1, 6, "", ("8.8.8.8", 443))]
        with patch.object(user_sources.socket, "getaddrinfo",
                          return_value=records):
            self.assertEqual(
                await user_sources._resolve_public("example.net", 443),
                "8.8.8.8",
            )

    async def test_m3u_invalid_header_and_size_rejected(self):
        with self.assertRaises(ValueError):
            user_sources._m3u_preview(b"not-m3u")
        with self.assertRaises(ValueError):
            user_sources._m3u_preview(b"#EXTM3U\n" + b"x" * 4097)


if __name__ == "__main__":
    unittest.main()
