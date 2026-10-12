"""No live IPTV credentials or external network required."""
import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

_TMP = tempfile.TemporaryDirectory()
for key, val in {
    "DATA_DIR": _TMP.name, "XTREAM_BASE_URL": "https://example.invalid:25461",
    "XTREAM_USERNAME": "example", "XTREAM_PASSWORD": "example",
    "PUBLIC_BASE_URL": "https://example.invalid/xtream-vod",
    "ADDON_TOKEN": "a" * 40, "ADMIN_TOKEN": "b" * 40,
    "PLAYBACK_SECRET": "c" * 40,
}.items():
    os.environ[key] = val

SPEC = importlib.util.spec_from_file_location("bridge", Path(__file__).resolve().parents[1] / "app.py")
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)


class Tests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        bridge.init_db()

    async def test_movie_by_imdb(self):
        with bridge.db() as con:
            con.execute("DELETE FROM items")
            con.execute("INSERT INTO items(kind,item_id,name,extension,imdb_id,last_seen) VALUES (?,?,?,?,?,?)",
                        ("movie", 17, "A Test Movie (2020)", "mkv", "tt1234567", int(time.time())))
        result = await bridge.streams("a" * 40, "movie", "tt1234567")
        self.assertEqual(len(result["streams"]), 1)
        stream = result["streams"][0]
        self.assertIn("/play/movie/17/tt1234567/", stream["url"])
        self.assertNotIn("example:example", stream["url"])
        self.assertIn("A.Test.Movie", stream["behaviorHints"]["filename"])

    async def test_series_episode(self):
        with bridge.db() as con:
            con.execute("DELETE FROM items")
            con.execute("DELETE FROM episodes")
            con.execute("INSERT INTO items(kind,item_id,name,extension,imdb_id) VALUES (?,?,?,?,?)",
                        ("series", 88, "Example Series", "mp4", "tt7654321"))
            con.execute("INSERT INTO episodes(series_id,season,episode,stream_id,extension,name) VALUES (?,?,?,?,?,?)",
                        (88, 2, 3, 919, "mkv", "Episode Three"))
        r = await bridge.streams("a" * 40, "series", "tt7654321:2:3")
        self.assertEqual(len(r["streams"]), 1)
        self.assertIn("S02E03", r["streams"][0]["behaviorHints"]["filename"])
        r2 = await bridge.streams("a" * 40, "series", "tt7654321:2:4")
        self.assertEqual(r2["streams"], [])

    async def test_tmdb_id_direct(self):
        with bridge.db() as con:
            con.execute("DELETE FROM items")
            con.execute("INSERT INTO items(kind,item_id,name,extension,tmdb_id) VALUES (?,?,?,?,?)",
                        ("movie", 17, "The Example", "mp4", "603"))
        r = await bridge.streams("a" * 40, "movie", "tmdb:movie:603")
        self.assertEqual(len(r["streams"]), 1)
        self.assertIn("/movie/17/tmdb-movie-603/", r["streams"][0]["url"])

    def test_stream_hmac(self):
        u = bridge.signed_url("movie", 11, "mp4")
        from urllib.parse import urlsplit, parse_qs
        parts = urlsplit(u)
        query = parse_qs(parts.query)
        self.assertTrue(bridge.valid_signature("movie", 11, "mp4", query["exp"][0], query["sig"][0]))
        self.assertFalse(bridge.valid_signature("movie", 12, "mp4", query["exp"][0], query["sig"][0]))

    async def test_error_response_does_not_expose_request_secrets(self):
        # HTTPX exceptions can contain Xtream URL query parameters. Never put
        # those exception messages in /health or docker logs.
        with patch.object(bridge, "sync_lists", new=AsyncMock(side_effect=RuntimeError(
            "https://iptv.invalid/player_api.php?username=secretuser&password=secretpass"))):
            result = await bridge.sync_all()
        self.assertEqual(result["status"], "error")
        self.assertEqual(bridge.LAST_RUN["last_error"], "RuntimeError")
        self.assertNotIn("secretpass", str(bridge.LAST_RUN))

    async def test_enrich_from_metadata(self):
        with bridge.db() as con:
            con.execute("DELETE FROM items")
            con.execute("INSERT INTO items(kind,item_id,name,extension) VALUES (?,?,?,?)",
                        ("movie", 12, "Metadata Test", "mp4"))
        original_limit = bridge.MAX_ENRICH
        bridge.MAX_ENRICH = 1
        try:
            with patch.object(bridge, "xtream", new=AsyncMock(return_value={"info": {"tmdb_id": "603", "imdb_id": "tt0133093"}, "movie_data": {"container_extension": "mkv"}})):
                with patch.object(bridge.asyncio, "sleep", new=AsyncMock()):
                    self.assertEqual(await bridge.enrich_items(), 1)
        finally:
            bridge.MAX_ENRICH = original_limit
        r = await bridge.streams("a" * 40, "movie", "tt0133093")
        self.assertEqual(len(r["streams"]), 1)


if __name__ == "__main__":
    unittest.main()
