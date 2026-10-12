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
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from urllib.parse import quote, urlencode, urljoin, urlsplit

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from starlette.background import BackgroundTask
from fastapi.responses import Response, StreamingResponse

VERSION = "0.1.3"
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
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "index.sqlite"
VALID_EXT = re.compile(r"^(?:mp4|mkv|avi|mov|ts|m3u8|flv|wmv|3gp)$", re.I)
VALID_ID = re.compile(r"^tt\d{7,10}$")
STREAM_REQUEST = re.compile(r"^(tt\d{7,10})(?::(\d+):(\d+))?$")
TMDB_REQUEST = re.compile(r"^tmdb:(?:(?:movie|tv|series):)?(\d+)(?::(\d+):(\d+))?$")
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
    for value in HTTP_REDIRECT_ALLOWED_IPS:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise RuntimeError("HTTP redirect allowlist requires public IPv4 addresses") from exc
        if not isinstance(address, ipaddress.IPv4Address) or not address.is_global or value != str(address):
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


def extract_episodes(info):
    epmap = info.get("episodes") if isinstance(info, dict) else None
    if not isinstance(epmap, dict):
        return []
    results = []
    for season_key, entries in epmap.items():
        season = safe_int(season_key)
        # Season 0 specials can be supported by Xtream, and Stremio uses season 0.
        if str(season_key).strip() == "0":
            season = 0
        if season is None or not isinstance(entries, list):
            continue
        for raw in entries:
            if not isinstance(raw, dict):
                continue
            episode = safe_int(raw.get("episode_num"))
            stream_id = safe_int(raw.get("id"))
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
                con.execute("""INSERT INTO items(kind,item_id,name,extension,tmdb_id,imdb_id,last_seen)
                    VALUES(?,?,?,?,?,?,?) ON CONFLICT(kind,item_id) DO UPDATE SET
                      name=excluded.name, extension=excluded.extension,
                      tmdb_id=COALESCE(excluded.tmdb_id, items.tmdb_id),
                      imdb_id=COALESCE(excluded.imdb_id, items.imdb_id),
                      last_seen=excluded.last_seen""",
                    (kind, item_id, str(item.get("name") or item.get("title") or ""),
                     extension(item.get("container_extension")), tmdb_id, imdb_id, now))
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
            if kind == "series" and not isinstance(result.get("episodes"), dict):
                raise RuntimeError("Series details missing episodes dictionary")
            episodes = extract_episodes(result) if kind == "series" else []
            with db() as con:
                con.execute("UPDATE items SET tmdb_id=?, imdb_id=?, extension=?, checked_at=? "
                            "WHERE kind=? AND item_id=?",
                            (tmdb_id, imdb_id, ext, int(time.time()), kind, item_id))
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
            "catalogs": [], "idPrefixes": ["tt", "tmdb:"]}


def signed_url(kind, stream_id, ext):
    expiry = int(time.time()) + PLAY_HOURS * 3600
    path = f"/play/{kind}/{stream_id}.{ext}"
    mac = hmac.new(SECRET.encode(), f"{path}:{expiry}".encode(), hashlib.sha256).hexdigest()
    return PUBLIC + path + "?" + urlencode({"exp": expiry, "sig": mac})


def records_for(kind, imdb_id, tmdb_id):
    with db() as con:
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
    if not imdb_match and not tmdb_match:
        return {"streams": []}
    media_id_value, season, episode = (imdb_match or tmdb_match).groups()
    if media_type == "series" and (season is None or episode is None):
        return {"streams": []}
    if media_type == "movie" and season is not None:
        return {"streams": []}
    if imdb_match:
        imdb_id = media_id_value
        # First use the local indexed IMDb mapping; only call TMDb if we have no local match.
        rows = records_for(media_type, imdb_id, None)
        if not rows and TMDB_KEY:
            tmdb_id = await tmdb_from_imdb(media_type, imdb_id)
            rows = records_for(media_type, imdb_id, tmdb_id)
    else:
        # Direct TMDb ID lookup needs no third-party lookup call.
        rows = records_for(media_type, "", media_id_value)
    result = []
    for row in rows:
        if media_type == "movie":
            selected = [(row["item_id"], row["extension"], row["name"])]
        else:
            with db() as con:
                eps = con.execute("SELECT * FROM episodes WHERE series_id=? AND season=? AND episode=?",
                                  (row["item_id"], int(season), int(episode))).fetchall()
            selected = [(r["stream_id"], r["extension"], r["name"]) for r in eps]
        for sid, ext, name in selected:
            filename = (f"{row['name']}.S{int(season):02d}E{int(episode):02d}.{ext}"
                        if media_type == "series" else f"{row['name']}.{ext}")
            result.append({"name": "Xtream VOD Bridge",
                           "title": f"{filename} | IPTV VOD",
                           "url": signed_url(media_type, sid, ext),
                           "behaviorHints": {"notWebReady": ext.lower() != "mp4", "filename": filename}})
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
                and str(address) in HTTP_REDIRECT_ALLOWED_IPS
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
    if not valid_signature(kind, sid, ext, exp, sig):
        raise HTTPException(403)
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
