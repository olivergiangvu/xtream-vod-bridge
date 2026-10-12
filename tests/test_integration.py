"""Mocked Xtream API -> SQLite -> Stremio HTTP -> signed playback relay contract tests.

No live IPTV credentials, internet access, or HomeDocker deployment is used.
"""
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient

from test_bridge import bridge

TOKEN = "a" * 40


class MockedIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        bridge.init_db()
        with bridge.db() as con:
            con.execute("DELETE FROM episodes")
            con.execute("DELETE FROM items")
            con.execute("DELETE FROM crosswalk")
        self.client = TestClient(bridge.app)

    async def test_full_xtream_movie_and_episode_to_stremio(self):
        async def fake_xtream(action, **params):
            fixtures = {
                "get_vod_streams": [{"stream_id": 41, "name": "Example Film", "container_extension": "mkv", "tmdb": "603"}],
                "get_series": [{"series_id": 58, "name": "Example Show"}],
                "get_vod_info": {"info": {"imdb_id": "tt0133093", "anilist_id": "7777"}, "movie_data": {"container_extension": "mkv"}},
                "get_series_info": {"info": {"imdb_id": "tt7654321", "tmdb_id": "1399", "kitsu_id": "8888"}, "episodes": {
                    "1": [{"id": "910", "episode_num": 2, "container_extension": "mp4", "title": "Episode 2"}]}},
            }
            return fixtures[action]

        with patch.object(bridge, "xtream", new=fake_xtream), \
             patch.object(bridge.asyncio, "sleep", new=AsyncMock()):
            # Disable TMDb lookup: fixture already supplied IMDb IDs.
            result = await bridge.sync_all()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["lists"], {"movie": 1, "series": 1})
        self.assertEqual(result["enriched"], 2)

        manifest = self.client.get(f"/a/{TOKEN}/manifest.json")
        self.assertEqual(manifest.status_code, 200)
        self.assertEqual(manifest.json()["resources"], ["stream"])
        self.assertEqual(manifest.json()["types"], ["movie", "series"])
        movie = self.client.get(f"/a/{TOKEN}/stream/movie/tt0133093.json")
        self.assertEqual(movie.status_code, 200)
        self.assertEqual(len(movie.json()["streams"]), 1)
        self.assertIn("/play/movie/41/tt0133093/", movie.json()["streams"][0]["url"])
        self.assertTrue(movie.json()["streams"][0]["url"].endswith("/Example.Film.mkv"))
        self.assertEqual(movie.json()["streams"][0]["behaviorHints"]["filename"], "Example.Film.mkv")
        self.assertNotIn("?exp=", movie.json()["streams"][0]["url"])
        self.assertEqual(len(self.client.get(f"/a/{TOKEN}/stream/movie/anilist:7777.json").json()["streams"]), 1)
        self.assertNotIn("/movie/example/example/", movie.text)
        self.assertNotIn("username=", movie.text)
        episode = self.client.get(f"/a/{TOKEN}/stream/series/tt7654321:1:2.json")
        self.assertEqual(episode.status_code, 200)
        self.assertIn("/play/series/910/tt7654321/", episode.json()["streams"][0]["url"])
        self.assertTrue(episode.json()["streams"][0]["url"].endswith("/Example.Show.S01E02.mp4"))
        self.assertEqual(episode.json()["streams"][0]["behaviorHints"]["filename"], "Example.Show.S01E02.mp4")
        self.assertEqual(len(self.client.get(f"/a/{TOKEN}/stream/series/kitsu:8888:1:2.json").json()["streams"]), 1)
        self.assertEqual(len(self.client.get(f"/a/{TOKEN}/stream/series/tmdb:tv:1399:1:2.json").json()["streams"]), 1)
        self.assertEqual(self.client.get(f"/a/{TOKEN}/stream/series/tt7654321:1:3.json").json(), {"streams": []})
        self.assertEqual(self.client.get("/a/invalid/manifest.json").status_code, 404)

    async def test_signed_playback_range_head_and_tampering(self):
        with bridge.db() as con:
            con.execute("INSERT INTO items(kind,item_id,name,extension) VALUES ('movie',45,'Fake Film','mp4')")
        calls = []

        def playback(request):
            calls.append(request)
            if request.method == "HEAD":
                return httpx.Response(200, headers={"Content-Type": "video/mp4", "Content-Length": "6"})
            if request.headers.get("Range") == "bytes=2-4":
                return httpx.Response(206, content=b"cde", headers={"Content-Range": "bytes 2-4/6", "Content-Length": "3"})
            return httpx.Response(200, content=b"abcdef", headers={"Content-Type": "video/mp4"})

        def factory():
            return httpx.AsyncClient(transport=httpx.MockTransport(playback), follow_redirects=False)

        url = bridge.signed_url("movie", 45, "mp4")
        suffix = url[len(bridge.PUBLIC):]
        with patch.object(bridge, "make_stream_client", factory):
            get = self.client.get(suffix, headers={"Range": "bytes=2-4"})
            self.assertEqual(get.status_code, 206)
            self.assertEqual(get.content, b"cde")
            self.assertEqual(get.headers["Content-Range"], "bytes 2-4/6")
            self.assertEqual(get.headers["Cache-Control"], "private, no-store")
            head = self.client.head(suffix)
            self.assertEqual(head.status_code, 200)
            self.assertEqual(head.content, b"")
            self.assertEqual(head.headers["content-length"], "6")
        self.assertEqual([r.method for r in calls], ["GET", "HEAD"])
        self.assertIn("/movie/example/example/45.mp4", str(calls[0].url))
        self.assertEqual(self.client.get(suffix.replace("sig=", "sig=bad")).status_code, 403)
        self.assertEqual(self.client.get(suffix.replace("/45.mp4", "/46.mp4")).status_code, 403)

    async def test_unsafe_redirect_blocked_and_approved_cdn_follows(self):
        with bridge.db() as con:
            con.execute("INSERT INTO items(kind,item_id,name,extension) VALUES ('movie',46,'Fake Film','mp4')")
        suffix = bridge.signed_url("movie", 46, "mp4")[len(bridge.PUBLIC):]

        def evil(request):
            return httpx.Response(302, headers={"Location": "http://127.0.0.1:8000/private"})

        with patch.object(bridge, "make_stream_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(evil))):
            res = self.client.get(suffix)
        self.assertEqual(res.status_code, 502)

        seen = []

        def cdn(request):
            seen.append(str(request.url))
            if request.url.host == "example.invalid":
                return httpx.Response(302, headers={"Location": "https://cdn.example.invalid/asset.mp4"})
            return httpx.Response(200, content=b"stream-bytes")

        with patch.object(bridge, "REDIRECT_ALLOWED_HOSTS", {"cdn.example.invalid"}), \
             patch.object(bridge, "make_stream_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(cdn))):
            res = self.client.get(suffix)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.content, b"stream-bytes")
        self.assertEqual(len(seen), 2)
        self.assertNotIn("/movie/example/example/", seen[1])
        self.assertFalse(bridge.safe_redirect("file:///etc/passwd"))
        self.assertFalse(bridge.safe_redirect("https://user:pass@cdn.example.invalid/a"))
        self.assertFalse(bridge.safe_redirect("http://cdn.example.invalid/a"))
        self.assertFalse(bridge.safe_redirect("https://cdn.example.invalid:22/a"))
        self.assertFalse(bridge.safe_redirect("https://example.invalid:22/admin"))

    async def test_http_cdn_downgrade_opt_in_and_range(self):
        with bridge.db() as con:
            con.execute("INSERT INTO items(kind,item_id,name,extension) VALUES ('movie',47,'Fake Film','mp4')")
        suffix = bridge.signed_url("movie", 47, "mp4")[len(bridge.PUBLIC):]
        seen = []

        def redirected(request):
            seen.append(request)
            if request.url.host == "example.invalid":
                return httpx.Response(302, headers={"Location": "http://8.8.8.8/media/asset.mp4"})
            return httpx.Response(206, content=b"abcd",
                                  headers={"Content-Range": "bytes 0-3/10"})

        def factory():
            return httpx.AsyncClient(transport=httpx.MockTransport(redirected),
                                     follow_redirects=False)

        # A valid public IPv4 redirect still fails unless explicitly enabled.
        with (patch.object(bridge, "HTTP_REDIRECT_ALLOWED_IPS", set()),
             patch.object(bridge, "make_stream_client", factory)):
            self.assertEqual(self.client.get(suffix, headers={"Range": "bytes=0-3"}).status_code, 502)

        seen.clear()
        with (patch.object(bridge, "HTTP_REDIRECT_ALLOWED_IPS", {"8.8.8.8"}),
             patch.object(bridge, "make_stream_client", factory)):
            response = self.client.get(suffix, headers={"Range": "bytes=0-3"})
        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.content, b"abcd")
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[1].url.scheme, "http")
        self.assertEqual(seen[1].headers.get("range"), "bytes=0-3")
        self.assertNotIn("example", str(seen[1].url))
        self.assertNotIn(bridge.PASSWORD, str(seen[1].url))

    async def test_http_cdn_only_exact_global_ipv4_port_80(self):
        with patch.object(bridge, "HTTP_REDIRECT_ALLOWED_IPS",
                          {"8.8.8.8", "127.0.0.1", "192.168.1.1", "169.254.169.254", "cdn.example.invalid"}):
            self.assertTrue(bridge.safe_redirect("http://8.8.8.8/asset.mp4"))
            self.assertTrue(bridge.safe_redirect("http://8.8.8.8:80/asset.mp4"))
            for target in (
                "http://8.8.4.4/asset.mp4",
                "http://8.8.8.8:8080/asset.mp4",
                "http://8.8.8.8:22/asset.mp4",
                "http://127.0.0.1/asset.mp4",
                "http://192.168.1.1/asset.mp4",
                "http://169.254.169.254/latest/meta-data/",
                "http://cdn.example.invalid/asset.mp4",
                "http://u:p@8.8.8.8/asset.mp4",
                "file:///etc/passwd",
                "http://8.8.8.8:invalid/asset.mp4",
                "http://[::1]/asset.mp4",
            ):
                with self.subTest(target=target):
                    self.assertFalse(bridge.safe_redirect(target))


    async def test_named_playback_https_filename_signature_and_range(self):
        with bridge.db() as con:
            con.execute("INSERT INTO items(kind,item_id,name,extension,imdb_id) "
                        "VALUES ('movie',48,'Zootopia 2 (2025)','mkv','tt1234567')")
        filename = bridge.friendly_filename("Zootopia 2 (2025)", "movie", "mkv")
        url = bridge.signed_url("movie", 48, "mkv",
                                filename=filename, identity="tt1234567")
        self.assertTrue(url.endswith("/Zootopia.2.2025.mkv"))
        self.assertNotIn("?", url)
        self.assertTrue(bridge.valid_named_signature("movie", 48, "tt1234567",
            url.split("/")[-3], url.split("/")[-2], filename))
        suffix = url[len(bridge.PUBLIC):]

        def playback(request):
            if request.method == "HEAD":
                return httpx.Response(200, headers={"Content-Type": "video/x-matroska"})
            return httpx.Response(206, content=b"abcd",
                                  headers={"Content-Range": "bytes 0-3/90"})
        factory = lambda: httpx.AsyncClient(transport=httpx.MockTransport(playback))
        with patch.object(bridge, "make_stream_client", factory):
            res = self.client.get(suffix, headers={"Range": "bytes=0-3"})
            self.assertEqual(res.status_code, 206)
            self.assertEqual(res.content, b"abcd")
            self.assertIn("Zootopia.2.2025.mkv", res.headers["content-disposition"])
            head = self.client.head(suffix)
            self.assertEqual(head.status_code, 200)
            self.assertEqual(head.content, b"")
            self.assertEqual(self.client.get(suffix.replace("Zootopia.", "Fake.")).status_code, 403)
            self.assertEqual(self.client.get(suffix.replace("/tt1234567/", "/tt7654321/")).status_code, 403)

    async def test_dynamic_public_ipv4_http_redirect_still_blocks_private_network(self):
        with (patch.object(bridge, "HTTP_REDIRECT_MODE", "public-ip"),
              patch.object(bridge, "HTTP_REDIRECT_ALLOWED_IPS", set())):
            self.assertTrue(bridge.safe_redirect("http://1.1.1.1/video/file.mkv"))
            self.assertFalse(bridge.safe_redirect("http://1.1.1.1:8080/video/file.mkv"))
            self.assertFalse(bridge.safe_redirect("http://127.0.0.1/file.mkv"))
            self.assertFalse(bridge.safe_redirect("http://192.168.50.153/file.mkv"))
            self.assertFalse(bridge.safe_redirect("http://169.254.169.254/latest/meta-data/"))
            self.assertFalse(bridge.safe_redirect("http://224.0.0.1/udp"))
            self.assertFalse(bridge.safe_redirect("http://240.0.0.1/reserved"))
            self.assertFalse(bridge.safe_redirect("http://public.example.org/asset.mkv"))
            self.assertFalse(bridge.safe_redirect("file:///etc/passwd"))
        with (patch.object(bridge, "HTTP_REDIRECT_MODE", "allowlist"),
              patch.object(bridge, "HTTP_REDIRECT_ALLOWED_IPS", set())):
            self.assertFalse(bridge.safe_redirect("http://1.1.1.1/video/file.mkv"))

    async def test_anime_metadata_migration_episode_zero_and_flat_list(self):
        with bridge.db() as con:
            for col in ("anilist_id", "kitsu_id", "mal_id"):
                self.assertIn(col, [r["name"] for r in con.execute("PRAGMA table_info(items)")])
        ids = bridge.find_anime_ids({"info": {"mal_id": "123", "kitsu_id": 456}})
        self.assertEqual(ids, {"mal_id": "123", "kitsu_id": "456"})
        episodes = bridge.extract_episodes({
            "episodes": [{"season_number": 0, "episode_number": 1,
                          "stream_id": 998, "container_extension": "mkv", "title": "Special"}]})
        self.assertEqual(episodes[0][:4], (0, 1, 998, "mkv"))
        self.assertEqual(bridge.friendly_filename("アニメ", "series", "mkv", 1, 2),
                         "アニメ.S01E02.mkv")

    async def test_transient_empty_listing_does_not_delete_index(self):
        with bridge.db() as con:
            con.execute("INSERT INTO items(kind,item_id,name,extension,last_seen) VALUES ('movie',7,'Preserved','mp4',1)")
        with patch.object(bridge, "xtream", new=AsyncMock(return_value=[])):
            counts = await bridge.sync_lists()
        self.assertEqual(counts["movie"], 0)
        with bridge.db() as con:
            self.assertEqual(con.execute("SELECT count(*) FROM items WHERE item_id=7").fetchone()[0], 1)

    async def test_metadata_ids_merge_from_nested_fields(self):
        imdb, tmdb = bridge.find_metadata({"imdb_id": "tt0133093", "info": {"tmdb_id": "603"}}, "movie")
        self.assertEqual((imdb, tmdb), ("tt0133093", "603"))

    async def test_bad_series_detail_preserves_episode_data(self):
        with bridge.db() as con:
            con.execute("INSERT INTO items(kind,item_id,name,extension) VALUES ('series',88,'Example Show','mp4')")
            con.execute("INSERT INTO episodes(series_id,season,episode,stream_id,extension) VALUES (88,1,1,777,'mkv')")
        with patch.object(bridge, "xtream", new=AsyncMock(return_value={"info": {"imdb_id": "tt7654321"}})):
            await bridge.enrich_items()
        with bridge.db() as con:
            count = con.execute("SELECT count(*) FROM episodes WHERE stream_id=777").fetchone()[0]
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
