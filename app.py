"""Xtream VOD -> Stremio streams bridge (single authorised provider, metadata-ID indexed)."""
import asyncio
import ipaddress
import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import time
import unicodedata
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from urllib.parse import quote, urlencode, urljoin, urlsplit

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from starlette.background import BackgroundTask
from fastapi.responses import Response, StreamingResponse

VERSION = "0.2.0"
LOG = logging.getLogger("xtream-vod-bridge")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
# Xtream player_api.php uses query-string credentials. The HTTP client may
# otherwise log the complete URL (including username/password) at INFO.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

BASE = os.getenv("XTREAM_BASE_URL", "").rstrip("/")
USER = os.getenv("XTREAM_USERNAME", "")
PASSWORD = os.getenv("XTREAM_PASSWORD", "")
PUBLIC = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
ADDON_TOKEN = os.getenv("ADDON_TOKEN", "")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
SECRET = os.getenv("PLAYBACK_SECRET", "")
TMDB_KEY = os.getenv("TMDB_API_KEY", "")
SYNC_HOURS = max(1, int(os.getenv("SYNC_HOURS", "6")))
MAX_ENRICH = max(0, int(os.getenv("MAX_ENRICH_PER_SYNC", "250")))
INFO_DAYS = max(1, int(os.getenv("REFRESH_INFO_DAYS", "30")))
PLAY_HOURS = max(1, int(os.getenv("PLAY_URL_HOURS", "48")))
MOVIES_ONLY = os.getenv("MOVIES_ONLY", "0") == "1"
# Fail closed on redirects. Some providers use CDN redirects; explicitly allow
# only approved CDN hostnames, not arbitrary targets supplied by the provider.
REDIRECT_ALLOWED_HOSTS = {host.strip().lower() for host in
                          os.getenv("XTREAM_REDIRECT_ALLOWED_HOSTS", "").split(",") if host.strip()}
# Opt-in for HTTPS provider -> plain HTTP public IPv4 CDN hops only.
# This is explicitly distinct from the HTTPS redirect allowlist.
HTTP_REDIRECT_ALLOWED_IPS = {ip.strip() for ip in
                             os.getenv("XTREAM_HTTP_REDIRECT_ALLOWED_IPS", "").split(",") if ip.strip()}
# Explicit opt-in; no fixed CDN IP maintenance needed when the provider
# redirects to rotating public IPv4 addresses. Private IPs remain blocked.
HTTP_REDIRECT_MODE = os.getenv("XTREAM_HTTP_REDIRECT_MODE", "allowlist").strip().lower()
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "index.sqlite"
VALID_EXT = re.compile(r"^(?:mp4|mkv|avi|mov|ts|m3u8|flv|wmv|3gp)$", re.I)
VALID_ID = re.compile(r"^tt\d{7,10}$")
STREAM_REQUEST = re.compile(r"^(tt\d{7,10})(?::(\d+):(\d+))?$")
TMDB_REQUEST = re.compile(r"^tmdb:(?:(?:movie|tv|series):)?(\d+)(?::(\d+):(\d+))?$")
ANIME_REQUEST = re.compile(r"^(anilist|kitsu|mal):(\d+)(?::(\d+):(\d+))?$")
MEDIA_KEY = re.compile(r"^(?:tt\d{7,10}|tmdb-(?:movie|tv)-\d+|(?:anilist|kitsu|mal)-\d+)$")
FILENAME = re.compile(r"^[\w.-]{1,200}\.(?:mp4|mkv|avi|mov|ts|m3u8|flv|wmv|3gp)$", re.I)
ANIME_COLUMNS = {"anilist": "anilist_id", "kitsu": "kitsu_id", "mal": "mal_id"}

LAST_RUN = {"list_sync": None, "enriched": 0, "last_error": None}
LOCK = asyncio.Lock()


def check_settings():
    required = {"XTREAM_BASE_URL": BASE, "XTREAM_USERNAME": USER, "XTREAM_PASSWORD": PASSWORD,
                "PUBLIC_BASE_URL": PUBLIC, "ADDON_TOKEN": ADDON_TOKEN,
                "ADMIN_TOKEN": ADMIN_TOKEN, "PLAYBACK_SECRET": SECRET}
    bad = [key for key, val in required.items() if not val or val.startswith("REPLACE_")]
    if bad:
        raise RuntimeError(f"Missing/placeholder configuration: {', '.join(bad)}")
    if urlsplit(BASE).scheme not in ("http", "https") or not urlsplit(BASE).hostname:
        raise RuntimeError("XTREAM_BASE_URL must be http(s) URL")
    if urlsplit(PUBLIC).scheme != "https":
        raise RuntimeError("PUBLIC_BASE_URL must be public HTTPS URL")
    for key, val in (("ADDON_TOKEN", ADDON_TOKEN), ("ADMIN_TOKEN", ADMIN_TOKEN), ("PLAYBACK_SECRET", SECRET)):
        if len(val) < 32:
            raise RuntimeError(f"{key} requires at least 32 random characters")
    if len({ADDON_TOKEN, ADMIN_TOKEN, SECRET}) < 3:
        raise RuntimeError("Each secret must be different")
    if HTTP_REDIRECT_MODE not in ("allowlist", "public-ip"):
        raise RuntimeError("XTREAM_HTTP_REDIRECT_MODE must be allowlist or public-ip")
    for value in HTTP_REDIRECT_ALLOWED_IPS:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise RuntimeError("HTTP redirect allowlist requires public IPv4 addresses") from exc
        if (not isinstance(address, ipaddress.IPv4Address) or not address.is_global
                or address.is_multicast or address.is_reserved or value != str(address)):
            raise RuntimeError("HTTP redirect allowlist requires canonical public IPv4 addresses")


@contextmanager
def db():
    con = sqlite3.connect(DB_PATH, timeout=15)
    try:
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA busy_timeout=15000")
        with con:
            yield con
    finally:
        con.close()


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS items (
          kind TEXT NOT NULL CHECK(kind IN ('movie','series')),
          item_id INTEGER NOT NULL,
          name TEXT NOT NULL DEFAULT '',
          extension TEXT NOT NULL DEFAULT 'mp4',
          tmdb_id TEXT, imdb_id TEXT,
          checked_at INTEGER NOT NULL DEFAULT 0,
          last_seen INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY(kind, item_id)
        );
        CREATE INDEX IF NOT EXISTS idx_item_imdb ON items(kind, imdb_id);
        CREATE INDEX IF NOT EXISTS idx_item_tmdb ON items(kind, tmdb_id);
        CREATE TABLE IF NOT EXISTS episodes (
          series_id INTEGER NOT NULL,
          season INTEGER NOT NULL,
          episode INTEGER NOT NULL,
          stream_id INTEGER NOT NULL,
          extension TEXT NOT NULL DEFAULT 'mp4',
          name TEXT DEFAULT '',
          PRIMARY KEY(series_id, season, episode, stream_id)
        );
        CREATE INDEX IF NOT EXISTS idx_ep_lookup ON episodes(series_id, season, episode);
        CREATE TABLE IF NOT EXISTS crosswalk (
          kind TEXT NOT NULL, imdb_id TEXT NOT NULL, tmdb_id TEXT,
          checked_at INTEGER NOT NULL,
          PRIMARY KEY(kind, imdb_id)
        );
        """)
        # Non-destructive additive migration; retains all indexed movies/episodes.
        existing = {r["name"] for r in conn.execute("PRAGMA table_info(items)")}
        for column in ANIME_COLUMNS.values():
            if column not in existing:
                conn.execute(f"ALTER TABLE items ADD COLUMN {column} TEXT")
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{column} ON items(kind, {column})")


def clean_id(value):
    if value is None:
        return None
    text = str(value).strip()
    return text if text.isdigit() and int(text) > 0 else None


def clean_imdb(value):
    if isinstance(value, str):
        match = re.search(r"tt\d{7,10}", value)
        return match.group(0) if match else None
    return None


def extension(value):
    value = str(value or "mp4").lower().strip().lstrip(".")
    return value if VALID_EXT.fullmatch(value) else "mp4"


def safe_int(value):
    try:
        n = int(value)
        return n if n > 0 else None
    except (ValueError, TypeError):
        return None


async def xtream(action, **params):
    query = {"username": USER, "password": PASSWORD, "action": action, **params}
    async with httpx.AsyncClient(timeout=httpx.Timeout(45.0, connect=10.0), follow_redirects=False) as client:
        response = await client.get(BASE + "/player_api.php", params=query)
        response.raise_for_status()
        result = response.json()
    if isinstance(result, dict) and (result.get("user_info", {}).get("auth") == 0):
        raise RuntimeError("Xtream authentication failed")
    return result


async def tmdb(path, **params):
    if not TMDB_KEY:
        return {}
    async with httpx.AsyncClient(timeout=12.0) as client:
        r = await client.get("https://api.themoviedb.org/3/" + path,
                             params={"api_key": TMDB_KEY, **params})
        r.raise_for_status()
        return r.json()


async def imdb_from_tmdb(kind, tmdb_id):
    try:
        result = await tmdb(("movie" if kind == "movie" else "tv") + "/" + str(tmdb_id) + "/external_ids")
        return clean_imdb(result.get("imdb_id"))
    except Exception as exc:
        LOG.warning("TMDb reverse-ID lookup failed: %s", type(exc).__name__)
        return None


async def tmdb_from_imdb(kind, imdb_id):
    if not TMDB_KEY:
        return None
    now = int(time.time())
    with db() as con:
        cached = con.execute("SELECT tmdb_id,checked_at FROM crosswalk WHERE kind=? AND imdb_id=?",
                             (kind, imdb_id)).fetchone()
    if cached and now - cached["checked_at"] < 7 * 86400:
        return cached["tmdb_id"]
    try:
        result = await tmdb("find/" + imdb_id, external_source="imdb_id")
        matches = result.get("movie_results" if kind == "movie" else "tv_results", [])
        found = clean_id(matches[0].get("id")) if matches else None
    except Exception as exc:
        LOG.warning("TMDb forward-ID lookup failed: %s", type(exc).__name__)
        return None
    with db() as con:
        con.execute("INSERT INTO crosswalk(kind,imdb_id,tmdb_id,checked_at) VALUES(?,?,?,?) "
                    "ON CONFLICT(kind,imdb_id) DO UPDATE SET tmdb_id=excluded.tmdb_id, checked_at=excluded.checked_at",
                    (kind, imdb_id, found, now))
    return found


def choose_tmdb(payload):
    for key in ("tmdb_id", "tmdb", "tmdbId"):
        found = clean_id(payload.get(key))
        if found:
            return found
    return None


def choose_imdb(payload):
    for key in ("imdb_id", "imdb", "imdbId"):
        found = clean_imdb(payload.get(key))
        if found:
            return found
    return None


def find_metadata(payload, kind):
    if not isinstance(payload, dict):
        return None, None
    parts = [payload]
    parts += [payload[k] for k in ("info", "movie_data") if isinstance(payload.get(k), dict)]
    imdb_id = tmdb_id = None
    for part in parts:
        imdb_id = imdb_id or choose_imdb(part)
        tmdb_id = tmdb_id or choose_tmdb(part)
        if imdb_id and tmdb_id:
            break
    return imdb_id, tmdb_id


def find_anime_ids(payload):
    """Only use IDs provided by the Xtream data, never infer from titles."""
    result = {}
    if not isinstance(payload, dict):
        return result
    parts = [payload]
    parts += [payload[k] for k in ("info", "movie_data") if isinstance(payload.get(k), dict)]
    candidates = {
        "anilist_id": ("anilist_id", "anilist", "anilistId"),
        "kitsu_id": ("kitsu_id", "kitsu", "kitsuId"),
        "mal_id": ("mal_id", "myanimelist_id", "mal", "malId"),
    }
    for part in parts:
        for column, aliases in candidates.items():
            if column not in result:
                for alias in aliases:
                    value = clean_id(part.get(alias))
                    if value:
                        result[column] = value
                        break
    return result


def friendly_filename(name, kind, ext, season=None, episode=None):
    """Clean UTF-8 basename is the last URL component for mpv/metadata scrapers."""
    text = unicodedata.normalize("NFKC", str(name or "Media"))
    text = re.sub(r"\.(?:mp4|mkv|avi|mov|ts|m3u8|flv|wmv|3gp)$", "", text, flags=re.I)
    text = re.sub(r"^(?:(?:\[(?:4K|UHD|HD|FHD|1080P|2160P)\]|(?:4K|UHD|FHD)[\s:_|-]+)\s*)+", "", text, flags=re.I)
    text = re.sub(r"[^\w]+", ".", text, flags=re.UNICODE).strip(".")
    text = text[:145].rstrip(".") or "Media"
    if kind == "series":
        text += f".S{int(season):02d}E{int(episode):02d}"
    return f"{text}.{ext}"


def media_key(row, kind, requested=None):
    imdb = row["imdb_id"]
    if imdb:
        return imdb
    tmdb_id = row["tmdb_id"]
    if tmdb_id:
        return f"tmdb-{'movie' if kind == 'movie' else 'tv'}-{tmdb_id}"
    for name, col in ANIME_COLUMNS.items():
        if row[col]:
            return f"{name}-{row[col]}"
    return requested or "unknown"


def extract_episodes(info):
    epmap = info.get("episodes") if isinstance(info, dict) else None
    if isinstance(epmap, dict):
        seasons = epmap.items()
    elif isinstance(epmap, list):
        seasons = [(None, epmap)]
    else:
        return []
    results = []
    for season_key, entries in seasons:
        if not isinstance(entries, list):
            continue
        for raw in entries:
            if not isinstance(raw, dict):
                continue
            raw_season = season_key if season_key is not None else raw.get("season") or raw.get("season_number", 1)
            try:
                season = int(raw_season)
            except (TypeError, ValueError):
                continue
            if season < 0:
                continue
            episode = safe_int(raw.get("episode_num") or raw.get("episode_number") or raw.get("number"))
            stream_id = safe_int(raw.get("id") or raw.get("stream_id"))
            if episode and stream_id:
                results.append((season, episode, stream_id, extension(raw.get("container_extension")), str(raw.get("title") or "")))
    return results


async def sync_lists():
    """Refresh listing; never prune on transient provider errors."""
    now = int(time.time())
    counts = {}
    for kind, action in (("movie", "get_vod_streams"), ("series", "get_series")):
        if kind == "series" and MOVIES_ONLY:
            continue
        items = await xtream(action)
        if not isinstance(items, list):
            raise RuntimeError(f"Unexpected provider response for {action}")
        # Several Xtream-compatible panels transiently return [] on failure.
        # Never erase the entire indexed library on a single empty response.
        if not items:
            LOG.warning("Provider returned empty %s listing; preserving prior index", kind)
            counts[kind] = 0
            continue
        count = 0
        with db() as con:
            for item in items:
                if not isinstance(item, dict):
                    continue
                item_id = safe_int(item.get("stream_id") if kind == "movie" else item.get("series_id"))
                if not item_id:
                    continue
                imdb_id, tmdb_id = find_metadata(item, kind)
                anime = find_anime_ids(item)
                con.execute("""INSERT INTO items(kind,item_id,name,extension,tmdb_id,imdb_id,
                    anilist_id,kitsu_id,mal_id,last_seen)
                    VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(kind,item_id) DO UPDATE SET
                      name=excluded.name, extension=excluded.extension,
                      tmdb_id=COALESCE(excluded.tmdb_id, items.tmdb_id),
                      imdb_id=COALESCE(excluded.imdb_id, items.imdb_id),
                      anilist_id=COALESCE(excluded.anilist_id, items.anilist_id),
                      kitsu_id=COALESCE(excluded.kitsu_id, items.kitsu_id),
                      mal_id=COALESCE(excluded.mal_id, items.mal_id),
                      last_seen=excluded.last_seen""",
                    (kind, item_id, str(item.get("name") or item.get("title") or ""),
                     extension(item.get("container_extension")), tmdb_id, imdb_id,
                     anime.get("anilist_id"), anime.get("kitsu_id"), anime.get("mal_id"), now))
                count += 1
            # Prune only on a successfully completed listing fetch.
            ids = con.execute("SELECT item_id FROM items WHERE kind=? AND last_seen < ?", (kind, now)).fetchall()
            if kind == "series" and ids:
                con.executemany("DELETE FROM episodes WHERE series_id=?", [(r["item_id"],) for r in ids])
            con.execute("DELETE FROM items WHERE kind=? AND last_seen < ?", (kind, now))
        counts[kind] = count
    LAST_RUN["list_sync"] = now
    return counts


async def enrich_items():
    threshold = int(time.time()) - INFO_DAYS * 86400
    with db() as con:
        pending = con.execute("SELECT * FROM items WHERE checked_at < ? ORDER BY checked_at ASC LIMIT ?",
                              (threshold, MAX_ENRICH)).fetchall()
    count = 0
    for row in pending:
        kind, item_id = row["kind"], row["item_id"]
        try:
            result = await xtream("get_vod_info" if kind == "movie" else "get_series_info",
                                  **({"vod_id": item_id} if kind == "movie" else {"series_id": item_id}))
            if not isinstance(result, dict):
                raise RuntimeError("Invalid detail result")
            imdb_id, tmdb_id = find_metadata(result, kind)
            imdb_id = imdb_id or row["imdb_id"]
            tmdb_id = tmdb_id or row["tmdb_id"]
            if tmdb_id and not imdb_id and TMDB_KEY:
                imdb_id = await imdb_from_tmdb(kind, tmdb_id)
            movie_data = result.get("movie_data") or {}
            ext = extension(movie_data.get("container_extension") or row["extension"])
            anime_info = find_anime_ids(result)
            if kind == "series" and not isinstance(result.get("episodes"), (dict, list)):
                raise RuntimeError("Series details missing episodes mapping")
            episodes = extract_episodes(result) if kind == "series" else []
            with db() as con:
                con.execute("UPDATE items SET tmdb_id=?, imdb_id=?, extension=?, "
                            "anilist_id=?, kitsu_id=?, mal_id=?, checked_at=? "
                            "WHERE kind=? AND item_id=?",
                            (tmdb_id, imdb_id, ext,
                             anime_info.get("anilist_id") or row["anilist_id"],
                             anime_info.get("kitsu_id") or row["kitsu_id"],
                             anime_info.get("mal_id") or row["mal_id"],
                             int(time.time()), kind, item_id))
                if kind == "series":
                    con.execute("DELETE FROM episodes WHERE series_id=?", (item_id,))
                    con.executemany("INSERT INTO episodes(series_id,season,episode,stream_id,extension,name) "
                                    "VALUES(?,?,?,?,?,?)", [(item_id, *ep) for ep in episodes])
            count += 1
            # Soft throttle. Per-provider acceptable rate varies.
            await asyncio.sleep(0.25)
        except Exception as exc:
            LOG.warning("Details failed kind=%s id=%s error=%s", kind, item_id, type(exc).__name__)
            # Do not hammer a broken detail endpoint on every sync.
            with db() as con:
                con.execute("UPDATE items SET checked_at=? WHERE kind=? AND item_id=?",
                            (int(time.time()) - (INFO_DAYS - 1) * 86400, kind, item_id))
    LAST_RUN["enriched"] = count
    return count


async def sync_all():
    if LOCK.locked():
        return {"status": "already_running"}
    async with LOCK:
        try:
            lists = await sync_lists()
            enriched = await enrich_items()
            LAST_RUN["last_error"] = None
            return {"status": "ok", "lists": lists, "enriched": enriched}
        except Exception as exc:
            # Exception messages from HTTP clients may contain credential-bearing URLs.
            # Never surface those in /health or persistent logs.
            LAST_RUN["last_error"] = type(exc).__name__
            LOG.error("Sync failed: %s", type(exc).__name__)
            return {"status": "error", "error": "Check server logs; provider may be unavailable"}


async def loop():
    while True:
        try:
            result = await sync_all()
            LOG.info("Sync complete status=%s enriched=%s", result["status"], result.get("enriched"))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOG.error("Scheduled sync exception: %s", type(exc).__name__)
        await asyncio.sleep(SYNC_HOURS * 3600)


@asynccontextmanager
async def lifespan(_app):
    check_settings()
    init_db()
    task = asyncio.create_task(loop())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Xtream VOD Bridge", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


@app.get("/health")
async def health():
    # No secret values or upstream host exposed.
    with db() as con:
        stats = {r["kind"]: {"total": r["total"], "mapped": r["mapped"]}
                 for r in con.execute("SELECT kind, COUNT(*) AS total, "
                                      "SUM(CASE WHEN imdb_id IS NOT NULL OR tmdb_id IS NOT NULL "
                                      "THEN 1 ELSE 0 END) AS mapped FROM items GROUP BY kind")}
        episode_count = con.execute("SELECT COUNT(*) FROM episodes").fetchone()[0]
    return {"status": "ok", "version": VERSION, "last_sync": LAST_RUN["list_sync"],
            "enriched_last_sync": LAST_RUN["enriched"], "last_error": LAST_RUN["last_error"],
            "index": stats, "episodes": episode_count}


@app.post("/admin/refresh")
async def refresh(x_admin_token: str = Header(default="")):
    if not ADMIN_TOKEN or not hmac.compare_digest(x_admin_token, ADMIN_TOKEN):
        raise HTTPException(403)
    return await sync_all()


def authorized(token):
    if not ADDON_TOKEN or not hmac.compare_digest(token, ADDON_TOKEN):
        raise HTTPException(404)


@app.get("/a/{token}/manifest.json")
async def manifest(token: str):
    authorized(token)
    return {"id": "org.homedocker.xtreamvod", "version": VERSION,
            "name": "Xtream VOD Bridge", "description": "Private Xtream VOD HTTP streams by verified IMDb/TMDb IDs",
            "resources": ["stream"], "types": ["movie"] if MOVIES_ONLY else ["movie", "series"],
            "catalogs": [], "idPrefixes": ["tt", "tmdb:", "anilist:", "kitsu:", "mal:"]}


def signed_url(kind, stream_id, ext, *, filename=None, identity=None):
    """New URLs end with the real media filename; legacy links still work."""
    expiry = int(time.time()) + PLAY_HOURS * 3600
    if filename and identity:
        mac = hmac.new(SECRET.encode(),
                       f"v2:{kind}:{stream_id}:{identity}:{expiry}:{filename}".encode(),
                       hashlib.sha256).hexdigest()
        return PUBLIC + f"/play/{kind}/{stream_id}/{identity}/{expiry}/{mac}/" + quote(filename, safe="")
    # Legacy query-signature form remains valid for already issued links.
    path = f"/play/{kind}/{stream_id}.{ext}"
    mac = hmac.new(SECRET.encode(), f"{path}:{expiry}".encode(), hashlib.sha256).hexdigest()
    return PUBLIC + path + "?" + urlencode({"exp": expiry, "sig": mac})


def records_for(kind, imdb_id=None, tmdb_id=None, anime_kind=None, anime_id=None):
    with db() as con:
        if anime_kind in ANIME_COLUMNS and anime_id:
            column = ANIME_COLUMNS[anime_kind]  # fixed mapping, never user SQL
            return con.execute(f"SELECT * FROM items WHERE kind=? AND {column}=? "
                               "ORDER BY item_id DESC LIMIT 20", (kind, anime_id)).fetchall()
        if tmdb_id:
            return con.execute("SELECT * FROM items WHERE kind=? AND (imdb_id=? OR tmdb_id=?) "
                               "ORDER BY item_id DESC LIMIT 20", (kind, imdb_id, tmdb_id)).fetchall()
        return con.execute("SELECT * FROM items WHERE kind=? AND imdb_id=? "
                           "ORDER BY item_id DESC LIMIT 20", (kind, imdb_id)).fetchall()


@app.get("/a/{token}/stream/{media_type}/{media_id}.json")
async def streams(token: str, media_type: str, media_id: str):
    authorized(token)
    if media_type not in ("movie", "series") or (media_type == "series" and MOVIES_ONLY):
        return {"streams": []}
    imdb_match = STREAM_REQUEST.fullmatch(media_id)
    tmdb_match = TMDB_REQUEST.fullmatch(media_id)
    anime_match = ANIME_REQUEST.fullmatch(media_id)
    if not (imdb_match or tmdb_match or anime_match):
        return {"streams": []}
    if anime_match:
        anime_kind, anime_id, season, episode = anime_match.groups()
        requested_identity = f"{anime_kind}-{anime_id}"
        rows = records_for(media_type, anime_kind=anime_kind, anime_id=anime_id)
    else:
        media_id_value, season, episode = (imdb_match or tmdb_match).groups()
        requested_identity = (media_id_value if imdb_match else
                              f"tmdb-{'movie' if media_type == 'movie' else 'tv'}-{media_id_value}")
        if imdb_match:
            rows = records_for(media_type, imdb_id=media_id_value)
            if not rows and TMDB_KEY:
                rows = records_for(media_type, imdb_id=media_id_value,
                                   tmdb_id=await tmdb_from_imdb(media_type, media_id_value))
        else:
            rows = records_for(media_type, tmdb_id=media_id_value)
    if media_type == "series" and (season is None or episode is None):
        return {"streams": []}
    if media_type == "movie" and season is not None:
        return {"streams": []}
    result = []
    for row in rows:
        if media_type == "movie":
            selected = [(row["item_id"], row["extension"])]
        else:
            with db() as con:
                eps = con.execute("SELECT * FROM episodes WHERE series_id=? AND season=? AND episode=?",
                                  (row["item_id"], int(season), int(episode))).fetchall()
            selected = [(r["stream_id"], r["extension"]) for r in eps]
        for sid, ext in selected:
            filename = friendly_filename(row["name"], media_type, ext, season, episode)
            # Carry the exact Stremio request identity downstream. This also
            # preserves a requested IMDb ID when only TMDb was stored locally,
            # or a requested Kitsu/AniList ID when the row has an IMDb as well.
            identity = requested_identity
            if not MEDIA_KEY.fullmatch(identity):
                continue
            metadata_label = identity.replace("tmdb-", "TMDb ").replace("anilist-", "AniList ").replace("kitsu-", "Kitsu ").replace("mal-", "MAL ")
            hints = {"notWebReady": ext.lower() != "mp4", "filename": filename}
            if media_type == "series":
                hints["bingeGroup"] = f"xtream-vod-series-{row['item_id']}"
            result.append({"name": "IPTV VOD",
                           "title": f"{filename} | {metadata_label} | IPTV VOD",
                           "description": f"{filename} | {metadata_label} | IPTV VOD",
                           "url": signed_url(media_type, sid, ext,
                                             filename=filename, identity=identity),
                           "behaviorHints": hints})
        if len(result) >= 20:
            break
    return {"streams": result[:20]}


def valid_signature(kind, sid, ext, exp, sig):
    if kind not in ("movie", "series") or not safe_int(sid) or not VALID_EXT.fullmatch(ext):
        return False
    try:
        until = int(exp)
    except (TypeError, ValueError):
        return False
    if until < int(time.time()) or until > int(time.time()) + PLAY_HOURS * 3600 + 120:
        return False
    path = f"/play/{kind}/{sid}.{ext}"
    expected = hmac.new(SECRET.encode(), f"{path}:{until}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig or "")


def valid_named_signature(kind, sid, media_id, exp, sig, filename):
    if kind not in ("movie", "series") or not safe_int(sid):
        return False
    if not MEDIA_KEY.fullmatch(media_id) or not FILENAME.fullmatch(filename):
        return False
    if not re.fullmatch(r"[0-9a-f]{64}", sig or ""):
        return False
    try:
        until = int(exp)
    except (TypeError, ValueError):
        return False
    if until < int(time.time()) or until > int(time.time()) + PLAY_HOURS * 3600 + 120:
        return False
    expected = hmac.new(SECRET.encode(),
                        f"v2:{kind}:{sid}:{media_id}:{until}:{filename}".encode(),
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def make_stream_client():
    return httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=15.0), follow_redirects=False,
                             limits=httpx.Limits(max_connections=10, max_keepalive_connections=4))


def safe_redirect(target):
    try:
        parsed = urlsplit(target)
        source = urlsplit(BASE)
        if parsed.username or parsed.password or not parsed.hostname or parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname.lower()
        port = parsed.port  # Invalid ports must fail closed.
        if source.scheme == "https" and parsed.scheme == "http":
            # Exception ONLY for explicitly approved globally routable IPv4
            # CDN destinations on port 80. No hostnames, private/multicast IPs,
            # wildcard allowlists or other destination ports can downgrade TLS.
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                return False
            return (
                isinstance(address, ipaddress.IPv4Address)
                and address.is_global
                and not address.is_multicast and not address.is_reserved
                and (HTTP_REDIRECT_MODE == "public-ip" or str(address) in HTTP_REDIRECT_ALLOWED_IPS)
                and port in (None, 80)
            )
        if host == source.hostname.lower():
            # Same-origin redirects may use the provider's configured port or the
            # standard scheme port, but never arbitrary service ports.
            scheme_port = 443 if parsed.scheme == "https" else 80
            return port in (None, scheme_port, source.port)
        # HTTPS CDN redirects still need an explicit hostname allowlist.
        if host in REDIRECT_ALLOWED_HOSTS:
            return port in (None, 443 if parsed.scheme == "https" else 80)
        return False
    except ValueError:
        return False


@app.api_route("/play/{kind}/{sid}.{ext}", methods=["GET", "HEAD"])
async def play(kind: str, sid: int, ext: str, request: Request, exp: str = "", sig: str = ""):
    # Compatibility: old query-signed URLs remain valid until their expiry.
    if not valid_signature(kind, sid, ext, exp, sig):
        raise HTTPException(403)
    return await relay_stream(kind, sid, ext, request)


@app.api_route("/play/{kind}/{sid}/{media_id}/{exp}/{sig}/{filename}", methods=["GET", "HEAD"])
async def play_named(kind: str, sid: int, media_id: str, exp: str, sig: str,
                     filename: str, request: Request):
    if not valid_named_signature(kind, sid, media_id, exp, sig, filename):
        raise HTTPException(403)
    ext = filename.rsplit(".", 1)[-1].lower()
    return await relay_stream(kind, sid, ext, request, filename=filename)


async def relay_stream(kind, sid, ext, request, filename=None):
    with db() as con:
        if kind == "movie":
            exists = con.execute("SELECT 1 FROM items WHERE kind='movie' AND item_id=? AND extension=?",
                                 (sid, ext)).fetchone()
        else:
            exists = con.execute("SELECT 1 FROM episodes WHERE stream_id=? AND extension=?", (sid, ext)).fetchone()
    if not exists:
        raise HTTPException(404)
    # Relay stream bytes: credentials are never included in Stremio or AIOStreams URLs.
    url = f"{BASE}/{'movie' if kind == 'movie' else 'series'}/{quote(USER, safe='')}/{quote(PASSWORD, safe='')}/{sid}.{ext}"
    headers = {}
    if request.headers.get("range"):
        headers["Range"] = request.headers["range"]
    method = request.method
    client = make_stream_client()
    try:
        # Redirects only to original provider host or explicitly approved CDN hosts.
        # Never use automatic redirects with an untrusted Location target.
        for redirect_count in range(4):
            upstream_req = client.build_request(method, url, headers=headers)
            upstream = await client.send(upstream_req, stream=True)
            if upstream.status_code not in (301, 302, 303, 307, 308):
                break
            location = upstream.headers.get("location", "")
            await upstream.aclose()
            target = urljoin(url, location)
            if not safe_redirect(target):
                await client.aclose()
                raise HTTPException(502, "Provider redirect not allowed")
            if redirect_count == 3:
                await client.aclose()
                raise HTTPException(502, "Provider redirected too many times")
            url = target
    except HTTPException:
        raise
    except Exception:
        await client.aclose()
        raise HTTPException(502, "Xtream stream unavailable")
    if upstream.status_code not in (200, 206):
        await upstream.aclose()
        await client.aclose()
        raise HTTPException(502, "Xtream returned an unusable stream")
    out_headers = {k: v for k, v in upstream.headers.items()
                   if k.lower() in ("content-range", "accept-ranges", "content-length", "content-type")}
    # Do not allow provider cookies or cacheable auth results to reach players.
    out_headers["Cache-Control"] = "private, no-store"
    if filename:
        # Client hints; unlike query-string signatures, players also receive
        # a clean human-readable final filename from the path.
        out_headers["Content-Disposition"] = "inline; filename*=UTF-8''" + quote(filename, safe="")

    async def chunks():
        try:
            async for chunk in upstream.aiter_bytes(chunk_size=128 * 1024):
                yield chunk
        finally:
            await upstream.aclose()
            await client.aclose()

    if method == "HEAD":
        await upstream.aclose()
        await client.aclose()
        return Response(content=b"", status_code=upstream.status_code, headers=out_headers)
    return StreamingResponse(chunks(), status_code=upstream.status_code, headers=out_headers,
                             background=BackgroundTask(client.aclose))
