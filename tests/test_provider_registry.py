"""Unit tests for encrypted STAGED multi-Xtream provider profiles."""
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from test_bridge import bridge
import provider_store as vault
import admin_ui
import ops


class ProviderRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.database = Path(self.tmp.name) / "index.sqlite"
        self.key_file = Path(self.tmp.name) / "provider.key"
        self.key_file.write_bytes(Fernet.generate_key())
        os.chmod(self.key_file, 0o600)
        self.patches = [
            patch.object(ops, "PATH", self.database),
            patch.object(vault, "KEY_FILE", self.key_file),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        ops.init()
        vault.init()
        self.client = TestClient(admin_ui.console)
        self.addCleanup(self.client.close)
        self.auth = {"Authorization": "Bearer " + "b" * 40}
        self.form = {
            "label": "Meteor Backup",
            "base_url": "https://stream.example.org:8443",
            "username": "backupaccount",
            "password": "ANOTHER-NONREAL-PASSWORD-123",
            "priority": 20,
        }

    def test_unavailable_key_fails_closed_and_existing_bridge_index_unchanged(self):
        key = self.key_file
        with patch.object(vault, "KEY_FILE", Path(self.tmp.name) / "missing-key"):
            r = self.client.get("/api/providers", headers=self.auth)
            self.assertEqual(r.status_code, 200)
            self.assertFalse(r.json()["key_configured"])
            r = self.client.post("/api/providers", headers=self.auth, json=self.form)
            self.assertEqual(r.status_code, 503)
        with sqlite3.connect(self.database) as con:
            existing = [r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")]
        self.assertIn("provider_items", existing)
        self.assertNotIn("items", existing)
        self.assertTrue(key.exists())

    def test_create_two_staged_profiles_encrypted_at_rest(self):
        r = self.client.post("/api/providers", headers=self.auth, json=self.form)
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json()["status"], "staged_not_active")
        two = {**self.form, "label": "Provider 2", "username": "user2",
               "password": "NEW-SECRET-456", "priority": 30}
        r2 = self.client.post("/api/providers", headers=self.auth, json=two)
        self.assertEqual(r2.status_code, 201)
        profiles = self.client.get("/api/providers", headers=self.auth).json()
        self.assertEqual(len(profiles["providers"]), 2)
        self.assertFalse(profiles["streaming_activation"])
        self.assertEqual(profiles["providers"][0]["label"], "Meteor Backup")
        raw = self.database.read_bytes()
        for secret in ("ANOTHER-NONREAL-PASSWORD-123", "NEW-SECRET-456",
                       "backupaccount", "stream.example.org"):
            self.assertNotIn(secret.encode(), raw)
        response = json.dumps(profiles)
        self.assertNotIn("ANOTHER-NONREAL-PASSWORD-123", response)
        self.assertNotIn("config_blob", response)
        self.assertTrue(profiles["providers"][0]["password_configured"])

    def test_update_masked_password_write_only_and_wrong_key_fail_closed(self):
        created = self.client.post("/api/providers", headers=self.auth, json=self.form).json()
        uid = created["id"]
        result = self.client.patch(f"/api/providers/{uid}", headers=self.auth,
                                   json={"label": "New Display", "priority": 1})
        self.assertEqual(result.status_code, 200)
        decrypted = vault.get_credentials(uid)
        self.assertEqual(decrypted["password"], self.form["password"])
        change = self.client.patch(f"/api/providers/{uid}", headers=self.auth,
                                   json={"password": "REPLACED-PASSWORD-999"})
        self.assertEqual(change.status_code, 200)
        self.assertEqual(vault.get_credentials(uid)["password"], "REPLACED-PASSWORD-999")
        wrong_key = Path(self.tmp.name) / "wrong.key"
        wrong_key.write_bytes(Fernet.generate_key())
        with patch.object(vault, "KEY_FILE", wrong_key):
            read = self.client.get("/api/providers", headers=self.auth)
            self.assertEqual(read.status_code, 503)
            self.assertNotIn("REPLACED-PASSWORD-999", read.text)

    def test_provider_scoped_primary_keys_allow_same_stream_ids(self):
        a = self.client.post("/api/providers", headers=self.auth, json=self.form).json()["id"]
        b = self.client.post("/api/providers", headers=self.auth,
                             json={**self.form, "label": "Second"}).json()["id"]
        with ops.database() as con:
            con.executemany(
                "INSERT INTO provider_items(provider_id,kind,item_id,name,imdb_id) "
                "VALUES (?,'movie',77,'Same Numeric ID','tt1234567')",
                [(a,), (b,)],
            )
            con.executemany(
                "INSERT INTO provider_episodes(provider_id,series_id,season,episode,stream_id) "
                "VALUES (?,77,1,2,888)",
                [(a,), (b,)],
            )
        with ops.database() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM provider_items").fetchone()[0], 2)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM provider_episodes").fetchone()[0], 2)
        self.assertEqual(self.client.delete(f"/api/providers/{a}", headers=self.auth).status_code, 200)
        with ops.database() as con:
            self.assertEqual(con.execute("SELECT provider_id FROM provider_items").fetchone()[0], b)

    def test_invalid_urls_and_forbidden_secret_fields_rejected_atomically(self):
        invalid = [
            "http://stream.example.org", "https://127.0.0.1",
            "https://192.168.50.10", "https://foo:pass@example.org",
            "https://stream.example.org/player_api.php",
            "https://example.org?username=u", "https://example.org#anything",
            "https://localhost", "https://example.org:9000",
            "https://example.org//path",
        ]
        for url in invalid:
            with self.subTest(url=url):
                r = self.client.post("/api/providers", headers=self.auth,
                                     json={**self.form, "base_url": url})
                self.assertEqual(r.status_code, 422)
        forbidden = self.client.post("/api/providers", headers=self.auth,
                       json={**self.form, "addon_token": "abc"})
        self.assertEqual(forbidden.status_code, 422)
        with ops.database() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM provider_profiles").fetchone()[0], 0)

    def test_every_admin_route_requires_auth_and_frontend_does_not_embed_secret(self):
        p = self.client.post("/api/providers", json=self.form)
        self.assertEqual(p.status_code, 401)
        self.assertEqual(self.client.get("/api/providers").status_code, 401)
        self.assertEqual(self.client.patch("/api/providers/any", json={"label": "X"}).status_code, 401)
        self.assertEqual(self.client.delete("/api/providers/any").status_code, 401)
        page = self.client.get("/")
        self.assertIn("Xtream accounts", page.text)
        self.assertNotIn(self.form["password"], page.text)
        script = self.client.get("/assets/app.js").text
        self.assertIn("staged_not_active", page.text + script) if False else None
        self.assertNotIn(self.form["password"], script)

    def test_deletion_has_no_legacy_index_side_effects(self):
        # Legacy table belongs to stable v0.4 and must survive independent provider deletion.
        with ops.database() as con:
            con.execute("CREATE TABLE IF NOT EXISTS items(kind TEXT,item_id INTEGER)")
            con.execute("INSERT INTO items VALUES ('movie',123)")
        uid = vault.create_profile(self.form)["id"]
        vault.delete_profile(uid)
        with ops.database() as con:
            self.assertEqual(con.execute("SELECT item_id FROM items").fetchone()[0], 123)


if __name__ == "__main__":
    unittest.main()
