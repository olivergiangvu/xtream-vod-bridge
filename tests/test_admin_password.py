"""No-network security regression tests for password login and HttpOnly sessions."""
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
import ops
import admin_auth
import admin_ui

ORIGIN = "https://admin.example.org:18450"
PASSWORD = "An illustrative strong passphrase for admin"


class PasswordLoginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.patches = [
            patch.object(ops, "PATH", Path(self.tmp.name) / "index.sqlite"),
            patch.object(admin_auth, "PUBLIC_ORIGIN", ORIGIN),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        ops.init()
        admin_auth.init()
        self.client = TestClient(admin_ui.console)
        self.addCleanup(self.client.close)
        admin_auth.set_password(PASSWORD)

    def login(self, password=PASSWORD, origin=ORIGIN):
        return self.client.post(
            "/api/auth/login", headers={"Origin": origin},
            json={"password": password},
        )

    def cookie_headers(self, response, *, origin=ORIGIN, csrf=None):
        raw = response.cookies.get(admin_auth.COOKIE)
        self.assertIsNotNone(raw)
        headers = {
            "Cookie": admin_auth.COOKIE + "=" + raw,
            "Origin": origin,
            "X-CSRF-Token": csrf if csrf is not None else response.json()["csrf_token"],
        }
        return headers

    def test_not_configured_has_no_default_password(self):
        with ops.database() as con:
            con.execute("DELETE FROM admin_password")
        status = self.client.get("/api/auth/session").json()
        self.assertFalse(status["password_ready"])
        failure = self.login()
        self.assertEqual(failure.status_code, 503)
        self.assertNotIn(PASSWORD, failure.text)

    def test_login_uses_http_only_secure_strict_cookie_without_returning_token(self):
        result = self.login()
        self.assertEqual(result.status_code, 200)
        cookie = result.headers.get("set-cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("SameSite=strict", cookie)
        self.assertIn("Path=/admin/", cookie)
        self.assertIn("Max-Age=43200", cookie)
        self.assertNotIn(admin_auth.COOKIE, result.text)
        self.assertNotIn(PASSWORD, result.text)
        self.assertNotIn("ADMIN_TOKEN", result.text)
        self.assertEqual(result.json()["expires_in"], 43200)

    def test_cookie_reads_and_mutation_requires_csrf_and_same_origin(self):
        login = self.login()
        headers = self.cookie_headers(login)
        with patch.object(admin_ui, "main_health", return_value={"status": "ok"}):
            authorized = self.client.get(
                "/api/overview", headers={"Cookie": headers["Cookie"]}
            )
        self.assertEqual(authorized.status_code, 200)
        not_authed = self.client.get("/api/overview")
        self.assertEqual(not_authed.status_code, 401)
        missing_csrf = self.client.put(
            "/api/settings", headers={"Cookie": headers["Cookie"]},
            json={"source_label": "Meteor"},
        )
        self.assertEqual(missing_csrf.status_code, 403)
        wrong_csrf = self.client.put(
            "/api/settings",
            headers={**headers, "X-CSRF-Token": "attacker-guess"},
            json={"source_label": "Meteor"},
        )
        self.assertEqual(wrong_csrf.status_code, 403)
        foreign_origin = self.client.put(
            "/api/settings",
            headers={**headers, "Origin": "https://evil.example"},
            json={"source_label": "Meteor"},
        )
        self.assertEqual(foreign_origin.status_code, 403)
        good = self.client.put(
            "/api/settings", headers=headers,
            json={"source_label": "Meteor"},
        )
        self.assertEqual(good.status_code, 200)
        self.assertEqual(ops.get("source_label"), "Meteor")
        restored = self.client.get(
            "/api/auth/session", headers={"Cookie": headers["Cookie"]}
        )
        self.assertTrue(restored.json()["authenticated"])
        self.assertEqual(restored.json()["csrf_token"], login.json()["csrf_token"])

    def test_login_rejects_foreign_or_missing_origin(self):
        self.assertEqual(self.login(origin="https://evil.example").status_code, 403)
        self.assertEqual(
            self.client.post("/api/auth/login", json={"password": PASSWORD}).status_code, 403
        )
        with patch.object(admin_auth, "PUBLIC_ORIGIN", ""):
            self.assertEqual(self.login().status_code, 403)

    def test_approved_local_hostname_is_not_a_wildcard_or_relay_ip_allowlist(self):
        local_origin = "https://homedocker.local:18450"
        with patch.object(admin_auth, "LAN_ORIGIN", local_origin):
            self.assertIn(local_origin, admin_auth.allowed_origins())
            self.assertEqual(self.login(origin=local_origin).status_code, 200)
            self.assertEqual(self.login(origin="https://different.local:18450").status_code, 403)
            self.assertEqual(self.login(origin="https://homedocker.local.evil.org:18450").status_code, 403)
            self.assertEqual(self.login(origin="http://homedocker.local:18450").status_code, 403)

    def test_bad_password_attempts_are_rate_limited_and_no_secret_stored(self):
        for _ in range(5):
            self.assertEqual(self.login(password="incorrect-long-password").status_code, 401)
        self.assertEqual(self.login().status_code, 429)
        raw = Path(ops.PATH).read_bytes()
        self.assertNotIn(PASSWORD.encode(), raw)
        self.assertNotIn(b"incorrect-long-password", raw)
        with ops.database() as con:
            con.execute("DELETE FROM admin_login_guard")
        self.assertEqual(self.login().status_code, 200)

    def test_password_rotation_revokes_session_and_logout_revokes_it(self):
        old = self.login()
        headers = self.cookie_headers(old)
        self.assertTrue(
            self.client.get("/api/auth/session",
                            headers={"Cookie": headers["Cookie"]}).json()["authenticated"]
        )
        admin_auth.set_password("A different long 2026 Admin password")
        self.assertFalse(
            self.client.get("/api/auth/session",
                            headers={"Cookie": headers["Cookie"]}).json()["authenticated"]
        )
        new_login = self.login(password="A different long 2026 Admin password")
        self.assertEqual(new_login.status_code, 200)
        new_headers = self.cookie_headers(new_login)
        logged_out = self.client.post("/api/auth/logout", headers=new_headers)
        self.assertEqual(logged_out.status_code, 200)
        self.assertFalse(
            self.client.get("/api/auth/session",
                            headers={"Cookie": new_headers["Cookie"]}).json()["authenticated"]
        )

    def test_expired_session_is_rejected(self):
        logged = self.login()
        headers = self.cookie_headers(logged)
        with ops.database() as con:
            con.execute("UPDATE admin_sessions SET expires_at=?", (int(time.time()) - 1,))
        self.assertEqual(
            self.client.get("/api/overview",
                            headers={"Cookie": headers["Cookie"]}).status_code, 401
        )

    def test_legacy_bearer_auth_remains_backward_compatible(self):
        headers = {"Authorization": "Bearer " + "b" * 40}
        with patch.object(admin_ui, "main_health", return_value={"status": "ok"}):
            self.assertEqual(self.client.get("/api/overview", headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/api/overview").status_code, 401)

    def test_frontend_does_not_store_token_or_embed_admin_password(self):
        js = self.client.get("/assets/app.js").text
        html = self.client.get("/").text
        self.assertIn("autocomplete=\"current-password\"", html)
        self.assertIn("Advanced: use existing Admin token", html)
        for text in (PASSWORD, "localStorage", "sessionStorage"):
            self.assertNotIn(text, js)
        self.assertIn("auth/session", js)
        self.assertIn("auth/login", js)


if __name__ == "__main__":
    unittest.main()
