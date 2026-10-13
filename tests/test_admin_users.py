"""Multi-account permissions and secret-only manifest integration tests."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from test_bridge import bridge
import admin_auth
import admin_users
import admin_ui
import ops

ORIGIN = "https://admin.example.org:18450"
OWNER_PASSWORD = "An extremely strong Owner passphrase"
USER_PASSWORD = "Secure per-user passphrase 2026"


class MultiUserAdminTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.patches = [
            patch.object(ops, "PATH", Path(self.tmp.name) / "index.sqlite"),
            patch.object(admin_auth, "PUBLIC_ORIGIN", ORIGIN),
            patch.object(admin_auth, "LAN_ORIGIN", ""),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        ops.init()
        admin_auth.init()
        admin_users.init()
        admin_auth.set_password(OWNER_PASSWORD)
        self.client = TestClient(admin_ui.console)
        self.addCleanup(self.client.close)
        self.owner_header = {"Authorization": "Bearer " + "b" * 40}

    def cookie_login(self, username, password):
        resp = self.client.post("/api/auth/login", headers={"Origin": ORIGIN},
                                json={"username": username, "password": password})
        self.assertEqual(resp.status_code, 200, resp.text)
        c = resp.cookies.get(admin_auth.COOKIE)
        return {"Cookie": admin_auth.COOKIE + "=" + c,
                "Origin": ORIGIN, "X-CSRF-Token": resp.json()["csrf_token"]}

    def create_account(self, username, role):
        return self.client.post(
            "/api/admin-users", headers=self.owner_header,
            json={"username": username, "password": USER_PASSWORD, "role": role})

    def test_owner_can_add_users_and_public_list_never_exposes_hashes(self):
        self.assertEqual(self.create_account("secondadmin", "admin").status_code, 201)
        self.assertEqual(self.create_account("viewerone", "viewer").status_code, 201)
        listing = self.client.get("/api/admin-users", headers=self.owner_header)
        self.assertEqual(listing.status_code, 200)
        users = {x["username"]: x["role"] for x in listing.json()["users"]}
        self.assertEqual(users, {"owner": "owner", "secondadmin": "admin",
                                 "viewerone": "viewer"})
        self.assertNotIn("digest", listing.text)
        self.assertNotIn("salt", listing.text)
        self.assertNotIn(USER_PASSWORD, listing.text)
        self.assertNotIn(USER_PASSWORD.encode(), Path(ops.PATH).read_bytes())

    def test_owner_login_and_legacy_password_work(self):
        response = self.client.post("/api/auth/login", headers={"Origin": ORIGIN},
                                    json={"password": OWNER_PASSWORD})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["username"], "owner")
        headers = self.cookie_login("owner", OWNER_PASSWORD)
        status = self.client.get("/api/auth/session",
                                 headers={"Cookie": headers["Cookie"]}).json()
        self.assertEqual(status["username"], "owner")
        self.assertEqual(status["role"], "owner")

    def test_viewer_cannot_write_read_manifest_or_manage_users(self):
        self.create_account("viewerone", "viewer")
        headers = self.cookie_login("viewerone", USER_PASSWORD)
        self.assertEqual(self.client.get("/api/overview", headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/api/events", headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/api/manifest", headers=headers).status_code, 403)
        self.assertEqual(self.client.put("/api/settings", headers=headers,
                                         json={"source_label": "Hacked"}).status_code, 403)
        self.assertEqual(self.client.get("/api/admin-users", headers=headers).status_code, 403)
        self.assertEqual(self.client.post("/api/admin-users", headers=headers, json={}).status_code, 403)

    def test_admin_can_edit_settings_and_copy_manifest_but_cannot_create_users(self):
        self.create_account("secondadmin", "admin")
        headers = self.cookie_login("secondadmin", USER_PASSWORD)
        with patch.object(admin_ui.bridge, "PUBLIC", "https://example.org:18450"), \
             patch.object(admin_ui.bridge, "ADDON_TOKEN", "S" * 40):
            endpoint = self.client.get("/api/manifest", headers=headers)
            self.assertEqual(endpoint.status_code, 200)
            self.assertEqual(endpoint.json()["url"],
                             "https://example.org:18450/a/" + "S" * 40 + "/manifest.json")
        self.assertEqual(self.client.put(
            "/api/settings", headers=headers,
            json={"source_label": "My Provider"}).status_code, 200)
        self.assertEqual(self.client.get("/api/admin-users", headers=headers).status_code, 403)

    def test_disable_revokes_sessions_and_login(self):
        self.create_account("viewerone", "viewer")
        headers = self.cookie_login("viewerone", USER_PASSWORD)
        update = self.client.patch(
            "/api/admin-users/viewerone", headers=self.owner_header,
            json={"enabled": False})
        self.assertEqual(update.status_code, 200)
        self.assertEqual(self.client.get("/api/overview", headers=headers).status_code, 401)
        denied = self.client.post("/api/auth/login", headers={"Origin": ORIGIN},
                                  json={"username": "viewerone", "password": USER_PASSWORD})
        self.assertEqual(denied.status_code, 401)

    def test_password_reset_revokes_session_and_owner_cannot_be_deleted(self):
        self.create_account("secondadmin", "admin")
        headers = self.cookie_login("secondadmin", USER_PASSWORD)
        self.assertEqual(self.client.patch(
            "/api/admin-users/secondadmin", headers=self.owner_header,
            json={"password": "A different long password for secondadmin"}).status_code, 200)
        self.assertEqual(self.client.get("/api/overview", headers=headers).status_code, 401)
        self.assertEqual(self.client.delete(
            "/api/admin-users/owner", headers=self.owner_header).status_code, 422)
        self.assertEqual(self.client.get("/api/admin-users").status_code, 401)

    def test_manifest_not_exposed_without_admin_auth(self):
        self.assertEqual(self.client.get("/api/manifest").status_code, 401)
        good = self.client.get("/api/manifest", headers=self.owner_header)
        self.assertEqual(good.status_code, 200)
        self.assertTrue(good.json()["url"].endswith("/manifest.json"))
        self.assertNotIn("password", json.dumps(good.json()).lower())
        self.assertEqual(good.headers.get("Cache-Control"), "no-store")
        self.assertEqual(good.headers.get("Referrer-Policy"), "no-referrer")

    def test_invalid_accounts_and_roles_fail_closed(self):
        for u in ("owner", "../../evil", "UPPER", "a", "foo bar"):
            r = self.client.post("/api/admin-users", headers=self.owner_header,
                  json={"username": u, "password": USER_PASSWORD, "role": "admin"})
            self.assertEqual(r.status_code, 422, u)
        self.assertEqual(self.create_account("adminuser", "root").status_code, 422)


if __name__ == "__main__":
    unittest.main()
