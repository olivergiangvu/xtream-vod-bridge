"""Offline multi-provider isolation, HMAC v3 and on-demand routing tests."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import os

from cryptography.fernet import Fernet
from test_bridge import bridge
import provider_store as vault
import provider_router as router
import ops


class ProviderRoutingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.key = Path(self.temp.name) / "secret.key"
        self.key.write_bytes(Fernet.generate_key())
        os.chmod(self.key, 0o600)
        self.path = Path(self.temp.name) / "index.sqlite"
        self.patches = [
            patch.object(ops, "PATH", self.path),
            patch.object(vault, "KEY_FILE", self.key),
            patch.object(router, "ENABLED", True),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        ops.init()
        vault.init()
        router.JIT_LOCKS.clear()
        router.COOLDOWN.clear()
        for x in router.COUNTERS:
            router.COUNTERS[x] = 0
        bridge.init_db()
        with bridge.db() as con:
            con.execute("DELETE FROM items")
            con.execute("DELETE FROM episodes")
        self.a = vault.create_profile({
            "label": "Meteor 4K", "base_url": "https://a.example.org",
            "username": "A", "password": "secret-A", "priority": 10,
        })["id"]
        self.b = vault.create_profile({
            "label": "Backup 1080p", "base_url": "https://b.example.org",
            "username": "B", "password": "secret-B", "priority": 20,
        })["id"]

    async def index_both(self):
        async def provider_catalog(credentials, action, **kwargs):
            if action == "get_series":
                return [{
                    "series_id": 77, "name": "4K Example Show" if credentials["username"] == "A"
                    else "1080p Example Show", "imdb_id": "tt7654321",
                }]
            if action == "get_vod_streams":
                return [{
                    "stream_id": 77, "name": "4K Example Movie" if credentials["username"] == "A"
                    else "1080p Example Movie", "container_extension": "mkv",
                    "imdb_id": "tt1234567",
                }]
            raise AssertionError(action)
        with patch.object(router, "provider_api", new=provider_catalog):
            self.assertEqual(await router.sync_profile(self.a, bridge), 2)
            self.assertEqual(await router.sync_profile(self.b, bridge), 2)
        vault.set_active(self.a, True)
        vault.set_active(self.b, True)

    async def test_colliding_ids_return_distinct_provider_signed_movie_urls(self):
        await self.index_both()
        streams = await router.resolve_streams("movie", "tt1234567", bridge)
        self.assertEqual(len(streams), 2)
        self.assertEqual([s["name"] for s in streams],
                         ["Meteor 4K 2160p", "Backup 1080p 1080p"])
        self.assertNotEqual(streams[0]["url"], streams[1]["url"])
        self.assertIn("/play/provider/" + self.a + "/movie/77/", streams[0]["url"])
        self.assertIn("/play/provider/" + self.b + "/movie/77/", streams[1]["url"])
        self.assertNotIn("secret-A", str(streams))
        with ops.database() as con:
            self.assertEqual(con.execute("SELECT count(*) FROM provider_items "
                                         "WHERE item_id=77 AND kind='movie'").fetchone()[0], 2)

    async def test_hmac_cannot_replay_from_provider_a_to_b(self):
        await self.index_both()
        streams = await router.resolve_streams("movie", "tt1234567", bridge)
        import urllib.parse
        raw_path = urllib.parse.urlsplit(streams[0]["url"]).path
        # PUBLIC may include an nginx prefix, so split after /play/provider/.
        path = raw_path.split("/play/provider/", 1)[1].split("/")
        self.assertEqual(path[0], self.a)
        args = path[:7]
        self.assertTrue(router.valid_signature(*args, bridge))
        args[0] = self.b
        self.assertFalse(router.valid_signature(*args, bridge))
        args[0] = self.a
        args[2] = "88"
        self.assertFalse(router.valid_signature(*args, bridge))
        self.assertTrue(router.existing_stream(self.a, "movie", 77, "mkv"))
        self.assertTrue(router.existing_stream(self.b, "movie", 77, "mkv"))

    async def test_series_cache_scoped_per_provider_and_warm_request(self):
        await self.index_both()
        calls = []
        async def provider_details(creds, action, **kwargs):
            self.assertEqual(action, "get_series_info")
            calls.append(creds["username"])
            return {"episodes": {"1": [{
                "id": 888, "episode_num": 2, "container_extension": "mkv",
                "title": "Episode 2",
            }]}}
        with patch.object(router, "provider_api", new=provider_details):
            first = await router.resolve_streams("series", "tt7654321:1:2", bridge)
            second = await router.resolve_streams("series", "tt7654321:1:2", bridge)
        self.assertEqual(len(first), 2)
        self.assertEqual(len(second), 2)
        self.assertEqual(sorted(calls), ["A", "B"])
        self.assertTrue(all("S01E02" in r["behaviorHints"]["filename"] for r in first))
        with ops.database() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM provider_episodes "
                                         "WHERE stream_id=888").fetchone()[0], 2)

    async def test_one_provider_failure_does_not_suppress_other(self):
        await self.index_both()
        async def partial(creds, action, **kwargs):
            if creds["username"] == "A":
                raise RuntimeError("xtream?password=secret-A")
            return {"episodes": {"1": [{"id": 900, "episode_num": 1,
                                           "container_extension": "mp4"}]}}
        with patch.object(router, "provider_api", new=partial):
            streams = await router.resolve_streams("series", "tt7654321:1:1", bridge)
        self.assertEqual(len(streams), 1)
        self.assertEqual(streams[0]["name"], "Backup 1080p 1080p")
        self.assertEqual(router.COUNTERS["detail_error"], 1)

    async def test_disabling_one_provider_does_not_destroy_cached_rows(self):
        await self.index_both()
        vault.set_active(self.a, False)
        streams = await router.resolve_streams("movie", "tt1234567", bridge)
        self.assertEqual(len(streams), 1)
        self.assertTrue(streams[0]["name"].startswith("Backup"))
        with ops.database() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM provider_items "
                                         "WHERE kind='movie'").fetchone()[0], 2)

    async def test_legacy_movie_path_works_while_router_enabled(self):
        await self.index_both()
        with bridge.db() as con:
            con.execute("INSERT INTO items(kind,item_id,name,extension,imdb_id) "
                        "VALUES('movie',77,'Legacy film','mkv','tt1234567')")
        # Provider scope is separate, legacy index record untouched.
        legacy_url = bridge.signed_url("movie", 77, "mkv")
        from urllib.parse import urlsplit, parse_qs
        p = urlsplit(legacy_url)
        q = parse_qs(p.query)
        self.assertTrue(bridge.valid_signature("movie",77,"mkv",q["exp"][0],q["sig"][0]))
        extra = await router.resolve_streams("movie", "tt1234567", bridge)
        self.assertEqual(len(extra), 2)
        with bridge.db() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM items "
                                         "WHERE kind='movie' AND item_id=77").fetchone()[0], 1)

    def test_inactive_provider_cannot_receive_new_playback(self):
        # All new providers are staged until catalog index and explicit activation.
        self.assertFalse(router.existing_stream(self.a, "movie", 77, "mkv"))
        with self.assertRaises(ValueError):
            vault.set_active(self.a, True)


if __name__ == "__main__":
    unittest.main()
