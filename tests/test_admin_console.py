"""No-network unit tests for isolated admin console and SQLite overrides."""
import json
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from test_bridge import bridge
import admin_ui
import ops


class AdminConsoleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        bridge.init_db()
        with ops.database() as con:
            con.execute("DELETE FROM runtime_settings")
            con.execute("DELETE FROM diagnostic_events")
        self.client = TestClient(admin_ui.console)
        self.headers = {"Authorization": "Bearer " + ("b" * 40)}

    def tearDown(self):
        with ops.database() as con:
            con.execute("DELETE FROM runtime_settings")
            con.execute("DELETE FROM diagnostic_events")
        self.client.close()

    def test_admin_api_rejects_unauthorized_and_url_token(self):
        self.assertEqual(self.client.get("/api/overview").status_code, 401)
        self.assertEqual(self.client.get("/api/overview?token=" + "b" * 40).status_code, 401)
        self.assertEqual(self.client.get("/api/overview", headers={
            "Authorization": "Bearer " + "x" * 40
        }).status_code, 401)
        self.assertEqual(self.client.put("/api/settings", json={
            "source_label": "Attack"
        }).status_code, 401)

    def test_admin_overview_redacts_credentials_and_urls(self):
        with patch.object(admin_ui, "main_health",
                          return_value={"status": "ok", "version": "0.4.0",
                                        "index": {"movie": {"total": 200}}}):
            response = self.client.get("/api/overview", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["bridge"]["status"], "ok")
        raw = json.dumps(payload)
        for secret in ("example", "b" * 40, "c" * 40, "player_api.php", "playback_secret"):
            self.assertNotIn(secret, raw.lower())
        self.assertTrue(response.headers.get("cache-control") == "no-store")
        self.assertIn("default-src 'none'", response.headers["content-security-policy"])

    def test_source_name_is_saved_and_visible_in_stremio_streams(self):
        with bridge.db() as con:
            con.execute("DELETE FROM items")
            con.execute("INSERT INTO items(kind,item_id,name,extension,imdb_id)"
                        " VALUES ('movie',17,'Movie Test','mkv','tt1234567')")
        response = self.client.put("/api/settings", headers=self.headers,
                                   json={"source_label": "Meteor"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ops.get("source_label"), "Meteor")
        # Must survive a fresh sqlite connection (no in-memory settings only).
        with ops.database() as con:
            self.assertEqual(con.execute("SELECT value FROM runtime_settings "
                                         "WHERE key='source_label'").fetchone()[0], "Meteor")

    async def test_source_name_propagates_to_stremio_and_hot_jit_toggle(self):
        with bridge.db() as con:
            con.execute("DELETE FROM items")
            con.execute("INSERT INTO items(kind,item_id,name,extension,imdb_id)"
                        " VALUES ('movie',17,'Movie Test','mkv','tt1234567')")
        ops.update({"source_label": "Meteor", "series_on_demand": False})
        r = await bridge.streams("a" * 40, "movie", "tt1234567")
        self.assertEqual(r["streams"][0]["name"], "Meteor")
        self.assertIn("Meteor", r["streams"][0]["title"])
        self.assertTrue(r["streams"][0]["url"].startswith(bridge.PUBLIC + "/play/movie/"))
        self.assertFalse(ops.get("series_on_demand"))
        ops.update({"series_on_demand": True})
        self.assertTrue(ops.get("series_on_demand"))

    def test_reject_secret_keys_html_controls_and_invalid_quota_atomically(self):
        bad = [
            {"xtream_password": "password"},
            {"source_label": "<script>alert(1)</script>"},
            {"source_label": "bad\\nlabel"},
            {"source_label": ""},
            {"series_enrich_per_sync": -1},
            {"series_jit_max_variants": 500},
            {"series_on_demand": "true"},
        ]
        for candidate in bad:
            with self.subTest(candidate=candidate):
                response = self.client.put("/api/settings", headers=self.headers,
                                           json=candidate)
                self.assertEqual(response.status_code, 422)
        response = self.client.put("/api/settings", headers=self.headers,
                                   json={"source_label": "OK", "series_jit_max_variants": 100})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(ops.get("source_label"), "IPTV VOD")

    def test_private_events_are_bounded_and_redacted(self):
        ops.event("series_jit", "series", "ok", duration_ms=122, amount=13)
        ops.event("series_jit", "series", "oops credentials", duration_ms=50)
        recent = self.client.get("/api/events", headers=self.headers)
        self.assertEqual(recent.status_code, 200)
        self.assertEqual(len(recent.json()["events"]), 1)
        self.assertEqual(recent.json()["events"][0]["duration_ms"], 122)
        self.assertNotIn("password", json.dumps(recent.json()))

    def test_frontend_contains_no_embedded_secret(self):
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Xtream VOD Bridge", page.text)
        self.assertNotIn("b" * 40, page.text)
        self.assertNotIn("XTREAM_PASSWORD=", page.text)
        self.assertEqual(self.client.get("/assets/app.js").status_code, 200)
        self.assertEqual(self.client.get("/assets/style.css").status_code, 200)


if __name__ == "__main__":
    unittest.main()
