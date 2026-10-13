"""Provider-scoped VOD ingest for personal Xtream and M3U sources.

Only exact provider-supplied IMDb/TMDb IDs create matches; no fuzzy titles or
Live/EPG ingestion. All URL-bearing M3U entries are encrypted in SQLite.
Index keys and every query include source_id to prevent stream ID collisions.
"""
import asyncio
import hashlib
import json
import re
import time
from urllib.parse import urlsplit

import app as bridge
import ops
import user_sources

MAX_ROWS = 12000
MAX_LIST_BYTES = 24 * 1024 * 1024
DETAIL_MOVIES = 12
DETAIL_SERIES = 20
M3U_ATTRIBUTES = re.compile(r'([a-zA-Z][a-zA-Z0-9_-]*)="([^"\r\n]{0,256})"')
SERIES_NAME = re.compile(r"(?<!\w)S(\d{1,3})[ ._-]*E(\d{1,4})(?!\w)", re.I)
SYNC_LIMIT = asyncio.Semaphore(2)


def init():
    user_sources.init()
    with ops.database() as con:
        con.execute(
            "CREATE TABLE IF NOT EXISTS tenant_media ("
            "source_id TEXT NOT NULL,kind TEXT NOT NULL "
            "CHECK(kind IN ('movie','series')),item_key TEXT NOT NULL,"
            "name TEXT NOT NULL,imdb_id TEXT,tmdb_id TEXT,"
            "extension TEXT NOT NULL,stream_ciphertext BLOB,"
            "indexed_at INTEGER NOT NULL,"
            "PRIMARY KEY(source_id,kind,item_key))"
        )
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_tenant_media_imdb "
            "ON tenant_media(source_id,kind,imdb_id)"
        )
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_tenant_media_tmdb "
            "ON tenant_media(source_id,kind,tmdb_id)"
        )
        con.execute(
            "CREATE TABLE IF NOT EXISTS tenant_episodes ("
            "source_id TEXT NOT NULL,series_key TEXT NOT NULL,"
            "season INTEGER NOT NULL,episode INTEGER NOT NULL,"
            "stream_key TEXT NOT NULL,extension TEXT NOT NULL,"
            "name TEXT NOT NULL,stream_ciphertext BLOB,"
            "PRIMARY KEY(source_id,series_key,season,episode,stream_key))"
        )
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_tenant_ep_lookup "
            "ON tenant_episodes(source_id,series_key,season,episode)"
        )
        con.execute(
            "CREATE TABLE IF NOT EXISTS tenant_sync_guard ("
            "source_id TEXT PRIMARY KEY,last_started INTEGER NOT NULL)"
        )


def _movie(raw):
    if not isinstance(raw, dict):
        return None
    key = bridge.safe_int(raw.get("stream_id") or raw.get("id"))
    if key is None:
        return None
    imdb, tmdb = bridge.find_metadata(raw, "movie")
    if not imdb and not tmdb:
        return None
    name = str(raw.get("name") or raw.get("title") or "")[:200]
    return ("movie", str(key), name,
            imdb, tmdb, bridge.extension(raw.get("container_extension")), None)


def _series(raw, detail=None):
    if not isinstance(raw, dict):
        return None
    key = bridge.safe_int(raw.get("series_id") or raw.get("id"))
    if key is None:
        return None
    imdb, tmdb = bridge.find_metadata(raw, "series")
    if detail:
        x, y = bridge.find_metadata(detail, "series")
        imdb, tmdb = imdb or x, tmdb or y
    if not imdb and not tmdb:
        return None
    name = str(raw.get("name") or raw.get("title") or "")[:200]
    return ("series", str(key), name, imdb, tmdb, "mp4", None)


def _m3u_rows(data):
    text = data.decode("utf-8-sig")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "#EXTM3U":
        raise ValueError("Not an M3U playlist")
    if len(lines) > 20000 or any(len(s) > 4096 for s in lines):
        raise ValueError("Playlist exceeds safety limits")
    cipher = user_sources._cipher()
    items, episodes = [], []
    metadata = None
    for line in lines[1:]:
        line = line.strip()
        if line.startswith("#EXTINF:"):
            attrs = {k.lower(): v for k, v in M3U_ATTRIBUTES.findall(line[:4096])}
            display = line.rsplit(",", 1)[-1].strip()[:200]
            metadata = (attrs, display)
        elif line and not line.startswith("#") and metadata:
            attrs, display = metadata
            metadata = None
            if len(items) >= MAX_ROWS or len(episodes) >= MAX_ROWS:
                break
            try:
                url = user_sources._validated_url(line, playlist=True)
            except ValueError:
                continue
            imdb = bridge.clean_imdb(attrs.get("imdb-id") or attrs.get("imdb_id")
                                     or attrs.get("imdb"))
            tmdb = bridge.clean_id(attrs.get("tmdb-id") or attrs.get("tmdb_id")
                                    or attrs.get("tmdb"))
            if not imdb and not tmdb:
                continue
            filename = urlsplit(url).path.rsplit("/", 1)[-1]
            ext = bridge.extension(filename.rsplit(".", 1)[-1])
            encrypted = cipher.encrypt(url.encode("utf-8"))
            match = SERIES_NAME.search(display)
            if match:
                series_key = ("imdb-" + imdb) if imdb else ("tmdb-" + tmdb)
                items.append(("series", series_key,
                              SERIES_NAME.sub("", display).strip()[:200],
                              imdb, tmdb, ext, None))
                season, episode = int(match.group(1)), int(match.group(2))
                stream_key = hashlib.sha256(url.encode()).hexdigest()[:24]
                episodes.append((series_key, season, episode, stream_key,
                                 ext, display, encrypted))
            else:
                item_key = hashlib.sha256(url.encode()).hexdigest()[:24]
                items.append(("movie", item_key, display, imdb, tmdb, ext, encrypted))
    return items, episodes


async def _xtream_rows(config):
    base = config["base_url"] + "/player_api.php"

    async def action(name, **params):
        raw = await user_sources._bounded_https(
            base, params={"username": config["username"],
                          "password": config["password"], "action": name,
                          **params}, limit=MAX_LIST_BYTES
        )
        obj = json.loads(raw)
        if isinstance(obj, dict) and obj.get("user_info", {}).get("auth") == 0:
            raise ValueError("Provider denied access")
        return obj

    movies, series = await action("get_vod_streams"), await action("get_series")
    if not isinstance(movies, list) or not isinstance(series, list):
        raise ValueError("Unexpected Xtream source response")

    records, episodes = [], []
    unknown_movies = 0
    for m in movies[:MAX_ROWS]:
        row = _movie(m)
        if not row and unknown_movies < DETAIL_MOVIES:
            mid = bridge.safe_int(m.get("stream_id")) if isinstance(m, dict) else None
            if mid:
                unknown_movies += 1
                try:
                    info = await action("get_vod_info", vod_id=mid)
                    combined = dict(m)
                    combined["info"] = info.get("info", info) if isinstance(info, dict) else {}
                    row = _movie(combined)
                except (ValueError, RuntimeError, json.JSONDecodeError, Exception):
                    # A single malformed provider title must not abort entire sync.
                    row = None
        if row:
            records.append(row)

    detail_calls = 0
    for s in series[:MAX_ROWS]:
        if not isinstance(s, dict):
            continue
        info = None
        if detail_calls < DETAIL_SERIES:
            series_id = bridge.safe_int(s.get("series_id"))
            if series_id:
                detail_calls += 1
                try:
                    info = await action("get_series_info", series_id=series_id)
                except Exception:
                    info = None
        row = _series(s, info)
        if not row:
            continue
        records.append(row)
        if isinstance(info, dict):
            for season, episode, sid, ext, name in bridge.extract_episodes(info)[:2500]:
                episodes.append((row[1], season, episode, str(sid), ext,
                                 str(name)[:200], None))
    return records[:MAX_ROWS], episodes[:MAX_ROWS]


def _claim_sync(source_id):
    # Atomic cross-worker throttle: enforce at most one source sync per 5 min.
    now = int(time.time())
    with ops.database() as con:
        existing = con.execute(
            "SELECT last_started FROM tenant_sync_guard WHERE source_id=?",
            (source_id,),
        ).fetchone()
        if existing and now - existing["last_started"] < 300:
            raise ValueError("Sync cooldown active; try later")
        con.execute(
            "INSERT INTO tenant_sync_guard(source_id,last_started) VALUES(?,?) "
            "ON CONFLICT(source_id) DO UPDATE SET last_started=excluded.last_started",
            (source_id, now),
        )


async def sync_owned(owner, source_id):
    init()
    row = user_sources.get_owned(owner, source_id)
    if not row["enabled"]:
        raise ValueError("Source disabled")
    config = user_sources._config(row)
    # Source limit and global semaphore avoid unbounded provider API traffic.
    _claim_sync(source_id)
    async with SYNC_LIMIT:
        if row["kind"] == "m3u":
            payload = await user_sources._bounded_https(
                config["playlist_url"], limit=user_sources.MAX_M3U
            )
            rows, episodes = _m3u_rows(payload)
        else:
            rows, episodes = await _xtream_rows(config)
        timestamp = int(time.time())
        with ops.database() as con:
            con.executemany(
                "INSERT INTO tenant_media(source_id,kind,item_key,name,imdb_id,"
                "tmdb_id,extension,stream_ciphertext,indexed_at) "
                "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(source_id,kind,item_key) "
                "DO UPDATE SET name=excluded.name,imdb_id=excluded.imdb_id,"
                "tmdb_id=excluded.tmdb_id,extension=excluded.extension,"
                "stream_ciphertext=excluded.stream_ciphertext,"
                "indexed_at=excluded.indexed_at",
                [(source_id, *r, timestamp) for r in rows],
            )
            con.executemany(
                "INSERT INTO tenant_episodes(source_id,series_key,season,episode,"
                "stream_key,extension,name,stream_ciphertext) "
                "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(source_id,series_key,season,"
                "episode,stream_key) DO UPDATE SET extension=excluded.extension,"
                "name=excluded.name,stream_ciphertext=excluded.stream_ciphertext",
                [(source_id, *r) for r in episodes],
            )
            con.execute(
                "UPDATE vod_sources SET status='indexed',updated_at=? "
                "WHERE owner=? AND source_id=?",
                (timestamp, owner, source_id),
            )
        return {
            "status": "indexed", "movies": sum(r[0] == "movie" for r in rows),
            "series": sum(r[0] == "series" for r in rows),
            "episodes": len(episodes), "exact_metadata_only": True,
        }


def resolve_for_manifest(sources, kind, imdb=None, tmdb=None, season=None, episode=None):
    """Lookup only within selected source IDs. Never share caches between users."""
    init()
    if not sources or kind not in ("movie", "series"):
        return []
    found = []
    with ops.database() as con:
        for source in sources[:8]:
            rows = con.execute(
                "SELECT * FROM tenant_media WHERE source_id=? AND kind=? "
                "AND ((imdb_id IS NOT NULL AND imdb_id=?) OR "
                "(tmdb_id IS NOT NULL AND tmdb_id=?)) LIMIT 30",
                (source, kind, imdb, tmdb),
            ).fetchall()
            for r in rows:
                if kind == "movie":
                    found.append((dict(r), None))
                else:
                    eps = con.execute(
                        "SELECT * FROM tenant_episodes WHERE source_id=? "
                        "AND series_key=? AND season=? AND episode=? LIMIT 15",
                        (source, r["item_key"], season, episode),
                    ).fetchall()
                    found.extend((dict(r), dict(ep)) for ep in eps)
    return found[:40]
