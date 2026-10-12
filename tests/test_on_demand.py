"""Demand-first Xtream Series regression tests. No external network or secrets."""
import asyncio
import time
import unittest
from unittest.mock import patch

from test_bridge import bridge

TOKEN = "a" * 40


class OnDemandSeriesTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        bridge.init_db()
        with bridge.db() as con:
            con.execute("DELETE FROM episodes")
            con.execute("DELETE FROM items")
            con.execute("DELETE FROM crosswalk")
        bridge.JIT_SERIES_LOCKS.clear()
        bridge.JIT_RETRY_AFTER.clear()
        for key in bridge.JIT_STATS:
            bridge.JIT_STATS[key] = 0

    def seed(self, *items):
        with bridge.db() as con:
            con.executemany(
                "INSERT INTO items(kind,item_id,name,extension,imdb_id,tmdb_id) "
                "VALUES ('series',?,?,'mkv',?,?)", items)

    async def test_cold_series_resolves_on_first_request_and_warm_cache(self):
        self.seed((601, "4K Fixture Show", "tt7654321", "42"),
                  (602, "1080p Fixture Show", "tt7654321", "42"))
        calls = []

        async def source(action, **params):
            self.assertEqual(action, "get_series_info")
            calls.append(params["series_id"])
            sid = params["series_id"]
            return {"episodes": {"1": [{"id": sid + 1000, "episode_num": 2,
                    "container_extension": "mkv", "title": "Episode 2"}]}}

        with patch.object(bridge, "SERIES_ON_DEMAND", True), patch.object(bridge, "xtream", new=source):
            cold = await bridge.streams(TOKEN, "series", "tt7654321:1:2")
            warm = await bridge.streams(TOKEN, "series", "tt7654321:1:2")
            via_tmdb = await bridge.streams(TOKEN, "series", "tmdb:tv:42:1:2")
        self.assertEqual(sorted(calls), [601, 602])
        self.assertEqual(len(cold["streams"]), 2)
        self.assertEqual(len(warm["streams"]), 2)
        self.assertEqual(len(via_tmdb["streams"]), 2)
        self.assertEqual({x["name"] for x in cold["streams"]},
                         {"IPTV VOD 2160p", "IPTV VOD 1080p"})
        self.assertTrue(all("/play/series/" in x["url"] for x in cold["streams"]))
        self.assertTrue(all("?exp=" not in x["url"] for x in cold["streams"]))
        self.assertGreaterEqual(bridge.JIT_STATS["cache_hit"], 0)
        with bridge.db() as con:
            self.assertEqual(con.execute("SELECT count(*) FROM episodes").fetchone()[0], 2)

    async def test_duplicate_concurrent_request_is_singleflight(self):
        self.seed((711, "Example Show", "tt7654321", "42"))
        calls = []
        async def source(action, **params):
            calls.append(params["series_id"])
            await asyncio.sleep(0.025)
            return {"episodes": {"0": [{"episode_num": 1, "id": 811,
                                         "container_extension": "mp4"}]}}
        with patch.object(bridge, "SERIES_ON_DEMAND", True), patch.object(bridge, "xtream", new=source):
            results = await asyncio.gather(*(bridge.streams(TOKEN, "series", "tt7654321:0:1")
                                             for _ in range(5)))
        self.assertEqual(calls, [711])
        self.assertTrue(all(len(x["streams"]) == 1 for x in results))
        self.assertGreaterEqual(bridge.JIT_STATS["deduplicated"], 1)

    async def test_negative_episode_cache_then_ttl_refresh(self):
        self.seed((721, "Episodic Show", "tt7654321", "42"))
        calls = []
        async def source(action, **params):
            calls.append(params["series_id"])
            eps = [{"id": 921, "episode_num": 1, "container_extension": "mp4"}]
            if len(calls) >= 2:
                eps += [{"id": 922, "episode_num": 2, "container_extension": "mp4"}]
            return {"episodes": {"1": eps}}
        with patch.object(bridge, "SERIES_ON_DEMAND", True), patch.object(bridge, "xtream", new=source):
            first = await bridge.streams(TOKEN, "series", "tt7654321:1:2")
            second = await bridge.streams(TOKEN, "series", "tt7654321:1:2")
            self.assertEqual(len(calls), 1)
            self.assertEqual(first["streams"], second["streams"])
            with bridge.db() as con:
                con.execute("UPDATE items SET checked_at=? WHERE kind='series'",
                            (int(time.time()) - bridge.SERIES_JIT_TTL - 10,))
            third = await bridge.streams(TOKEN, "series", "tt7654321:1:2")
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(third["streams"]), 1)
        self.assertGreaterEqual(bridge.JIT_STATS["negative_cache"], 1)

    async def test_failed_provider_is_cooled_down_without_erasing_episodes(self):
        self.seed((731, "Failing Show", "tt7654321", "42"))
        calls = []
        async def source(action, **params):
            calls.append(params["series_id"])
            raise RuntimeError("https://s.example/player_api.php?password=SENSITIVE")
        with patch.object(bridge, "SERIES_ON_DEMAND", True), patch.object(bridge, "xtream", new=source):
            one = await bridge.streams(TOKEN, "series", "tt7654321:2:5")
            two = await bridge.streams(TOKEN, "series", "tt7654321:2:5")
        self.assertEqual(one["streams"], [])
        self.assertEqual(two["streams"], [])
        self.assertEqual(calls, [731])
        self.assertNotIn("SENSITIVE", str(bridge.JIT_STATS))
        with bridge.db() as con:
            self.assertEqual(con.execute("SELECT checked_at FROM items WHERE item_id=731").fetchone()[0], 0)

    async def test_partial_results_when_other_variant_times_out(self):
        self.seed((741, "4K Fixture Show", "tt7654321", "42"),
                  (742, "1080p Fixture Show", "tt7654321", "42"))
        async def source(action, **params):
            if params["series_id"] == 741:
                await asyncio.sleep(0.3)
            else:
                await asyncio.sleep(0.005)
            return {"episodes": {"2": [{"id": 1000 + params["series_id"], "episode_num": 3,
                                          "container_extension": "mkv"}]}}
        with (patch.object(bridge, "SERIES_ON_DEMAND", True),
              patch.object(bridge, "SERIES_JIT_TIMEOUT", 0.05),
              patch.object(bridge, "xtream", new=source)):
            result = await bridge.streams(TOKEN, "series", "tt7654321:2:3")
        self.assertEqual(len(result["streams"]), 1)
        self.assertEqual(result["streams"][0]["name"], "IPTV VOD 1080p")
        self.assertGreaterEqual(bridge.JIT_STATS["timeout"], 1)
        with bridge.db() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM episodes").fetchone()[0], 1)

    async def test_disabled_feature_does_not_call_provider(self):
        self.seed((751, "Example Show", "tt7654321", "42"))
        async def forbidden(action, **params):
            raise AssertionError("Opt-in OFF may not trigger on-demand network")
        with patch.object(bridge, "SERIES_ON_DEMAND", False), patch.object(bridge, "xtream", new=forbidden):
            data = await bridge.streams(TOKEN, "series", "tt7654321:1:1")
        self.assertEqual(data["streams"], [])

    def test_nested_episode_parser_and_no_number_guess(self):
        raw = {"episodes": {
            "Season 0": {"episodes": [
                {"episode_id": "801", "episode_number": "1",
                 "info": {"container_extension": "mkv", "title": "Special"}},
                {"episode_id": "802", "info": {"title": "No explicit episode number"}},
            ]},
            "Season 2": [{"stream_id": 903, "title": "Show.S02E03"}],
        }}
        episodes = bridge.extract_episodes(raw)
        self.assertEqual(sorted(e[:4] for e in episodes),
                         [(0, 1, 801, "mkv"), (2, 3, 903, "mp4")])

    async def test_preexisting_series_episode_and_movie_unchanged(self):
        self.seed((761, "4K Show", "tt7654321", "42"))
        with bridge.db() as con:
            con.execute("INSERT INTO episodes(series_id,season,episode,stream_id,extension,name)"
                        " VALUES (761,1,1,999,'mkv','Episode 1')")
            con.execute("INSERT INTO items(kind,item_id,name,extension,imdb_id)"
                        " VALUES ('movie',17,'Film','mkv','tt1234567')")
        async def forbidden(action, **params):
            raise AssertionError("Warm cache needs no provider")
        with patch.object(bridge, "SERIES_ON_DEMAND", True), patch.object(bridge, "xtream", new=forbidden):
            show = await bridge.streams(TOKEN, "series", "tt7654321:1:1")
            movie = await bridge.streams(TOKEN, "movie", "tt1234567")
        self.assertEqual(len(show["streams"]), 1)
        self.assertEqual(len(movie["streams"]), 1)
        self.assertIn("S01E01.2160p", show["streams"][0]["behaviorHints"]["filename"])


if __name__ == "__main__":
    unittest.main()
