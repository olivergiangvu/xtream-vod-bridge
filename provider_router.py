"""Opt-in provider-aware Xtream catalog, on-demand streams and HMAC v3.

Legacy database, legacy signatures and working movie/series relay are preserved.
Every numeric Xtream media/episode ID is scoped by immutable provider_id.
"""
import asyncio
import hashlib
import hmac
import ipaddress
import logging
import os
import socket
import time
from urllib.parse import quote, urlsplit

import httpx
import ops
import provider_store as vault

LOG = logging.getLogger("xtream-provider-router")
SEMAPHORE = asyncio.Semaphore(2)
SYNC_LOCK = asyncio.Lock()
JIT_LOCKS = {}
COOLDOWN = {}
COUNTERS = {"detail_ok": 0, "detail_error": 0, "cache_hit": 0,
            "cache_miss": 0, "sync_ok": 0, "sync_error": 0}
MAX_DETAIL_SECONDS = 8
REFRESH_HOURS = 6
ENABLED = os.getenv("XTREAM_MULTIPROVIDER_ENABLED", "0") == "1"


def _public_dns_hostname(hostname):
    # This guards literal private/loopback/metadata hosts before network calls.
    # The actual transport must be separately audited for DNS rebinding.
    def check():
        answers = socket.getaddrinfo(hostname, None, family=socket.AF_INET)
        if not answers:
            return False
        for result in answers:
            addr = ipaddress.ip_address(result[4][0])
            if not (isinstance(addr, ipaddress.IPv4Address) and addr.is_global
                    and not addr.is_reserved and not addr.is_multicast):
                return False
        return True
    return check()


async def provider_api(credentials, action, **params):
    base = credentials["base_url"].rstrip("/")
    hostname = urlsplit(base).hostname
    if not hostname or not await asyncio.to_thread(_public_dns_hostname, hostname):
        raise RuntimeError("Provider address is not a public DNS destination")
    async with SEMAPHORE:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(13.0, connect=4.0),
            follow_redirects=False, trust_env=False
        ) as client:
            response = await client.get(
                base + "/player_api.php",
                params={
                    "username": credentials["username"],
                    "password": credentials["password"],
                    "action": action,
                    **params,
                },
            )
            if response.status_code != 200:
                raise RuntimeError("Provider API returned non-200")
            if len(response.content) > 30 * 1024 * 1024:
                raise RuntimeError("Provider catalog is over safety limit")
            return response.json()


def _scope_row(uid, row, kind, bridge):
    raw_id = row.get("stream_id") if kind == "movie" else row.get("series_id")
    item_id = bridge.safe_int(raw_id)
    if item_id is None:
        return None
    imdb_id, tmdb_id = bridge.find_metadata(row, kind)
    return (uid, kind, item_id, str(row.get("name") or row.get("title") or "")[:500],
            bridge.extension(row.get("container_extension")), imdb_id, tmdb_id,
            int(time.time()))


async def sync_profile(uid, bridge):
    if not ENABLED:
        raise RuntimeError("Multi-provider router not enabled")
    details, credentials = vault.active_profile(uid) if _is_active(uid) else _staged_profile(uid)
    count = 0
    for kind, action in (("movie", "get_vod_streams"), ("series", "get_series")):
        if kind == "series" and bridge.MOVIES_ONLY:
            continue
        result = await provider_api(credentials, action)
        if not isinstance(result, list):
            raise RuntimeError("Unexpected Xtream provider catalog structure")
        # Empty provider list never deletes previously verified metadata.
        items = [x for row in result if isinstance(row, dict)
                 if (x := _scope_row(uid, row, kind, bridge)) is not None]
        if not items:
            continue
        with ops.database() as con:
            con.executemany(
                "INSERT INTO provider_items(provider_id,kind,item_id,name,extension,"
                "imdb_id,tmdb_id,last_seen) VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(provider_id,kind,item_id) DO UPDATE SET "
                "name=excluded.name,extension=excluded.extension,"
                "imdb_id=COALESCE(excluded.imdb_id,provider_items.imdb_id),"
                "tmdb_id=COALESCE(excluded.tmdb_id,provider_items.tmdb_id),"
                "last_seen=excluded.last_seen",
                items,
            )
        count += len(items)
    COUNTERS["sync_ok"] += 1
    ops.event("sync", "system", "ok", amount=count)
    return count


def _is_active(uid):
    with ops.database() as con:
        row = con.execute("SELECT enabled FROM provider_profiles WHERE provider_id=?",
                          (uid,)).fetchone()
    return bool(row and row[0])


def _staged_profile(uid):
    # Used by explicitly authorized admin pre-activation catalog sync only.
    credentials = vault.get_credentials(uid)
    with ops.database() as con:
        row = con.execute("SELECT provider_id,label,priority,enabled "
                          "FROM provider_profiles WHERE provider_id=?", (uid,)).fetchone()
    if row is None:
        raise KeyError("Unknown provider")
    return dict(row), credentials


async def sync_all(bridge):
    if not ENABLED:
        return {"status": "disabled"}
    if SYNC_LOCK.locked():
        return {"status": "busy"}
    async with SYNC_LOCK:
        with ops.database() as con:
            rows = con.execute("SELECT provider_id FROM provider_profiles").fetchall()
        successes = errors = 0
        for r in rows:
            try:
                await sync_profile(r[0], bridge)
                successes += 1
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                errors += 1
                COUNTERS["sync_error"] += 1
                LOG.warning("Provider catalog sync unavailable error=%s", type(exc).__name__)
        return {"status": "ok" if not errors else "partial",
                "providers_synced": successes, "providers_failed": errors}


async def periodic_sync(bridge):
    while True:
        try:
            await sync_all(bridge)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOG.warning("Provider catalog background error=%s", type(exc).__name__)
        await asyncio.sleep(max(1, bridge.SYNC_HOURS) * 3600)


def lookup_rows(kind, imdb=None, tmdb=None, anime=None):
    if not imdb and not tmdb:
        return []
    with ops.database() as con:
        return con.execute(
            "SELECT pi.*, p.label, p.priority FROM provider_items pi "
            "JOIN provider_profiles p ON p.provider_id=pi.provider_id "
            "WHERE p.enabled=1 AND pi.kind=? "
            "AND ((? IS NOT NULL AND pi.imdb_id=?) "
            " OR (? IS NOT NULL AND pi.tmdb_id=?)) "
            "ORDER BY p.priority ASC, pi.item_id DESC LIMIT 32",
            (kind, imdb, imdb, tmdb, tmdb),
        ).fetchall()


def episode_rows(uid, sid, season, episode):
    with ops.database() as con:
        return con.execute(
            "SELECT * FROM provider_episodes WHERE provider_id=? AND series_id=? "
            "AND season=? AND episode=?",
            (uid, sid, season, episode),
        ).fetchall()


async def hydrate(uid, sid, season, episode, bridge):
    if episode_rows(uid, sid, season, episode):
        COUNTERS["cache_hit"] += 1
        return
    COUNTERS["cache_miss"] += 1
    key = (uid, sid)
    lock = JIT_LOCKS.setdefault(key, asyncio.Lock())
    async with lock:
        if episode_rows(uid, sid, season, episode):
            return
        with ops.database() as con:
            row = con.execute("SELECT checked_at FROM provider_items "
                              "WHERE provider_id=? AND kind='series' AND item_id=?",
                              (uid, sid)).fetchone()
        if row is None:
            return
        if row[0] and row[0] > time.time() - REFRESH_HOURS * 3600:
            return
        if COOLDOWN.get(key, 0) > time.monotonic():
            return
        try:
            _, credentials = vault.active_profile(uid)
            result = await provider_api(credentials, "get_series_info", series_id=sid)
            if not isinstance(result, dict) or not isinstance(result.get("episodes"), (dict, list)):
                raise ValueError("Invalid episode details")
            episodes = bridge.extract_episodes(result)
            with ops.database() as con:
                if episodes:
                    con.executemany(
                        "INSERT INTO provider_episodes(provider_id,series_id,season,episode,"
                        "stream_id,extension,name) VALUES(?,?,?,?,?,?,?) "
                        "ON CONFLICT(provider_id,series_id,season,episode,stream_id) "
                        "DO UPDATE SET extension=excluded.extension,name=excluded.name",
                        [(uid, sid, *ep) for ep in episodes],
                    )
                con.execute("UPDATE provider_items SET checked_at=? "
                            "WHERE provider_id=? AND kind='series' AND item_id=?",
                            (int(time.time()), uid, sid))
            COUNTERS["detail_ok"] += 1
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            COOLDOWN[key] = time.monotonic() + 120
            COUNTERS["detail_error"] += 1
            LOG.warning("Provider episode metadata unavailable error=%s", type(exc).__name__)


def signed_url(uid, kind, sid, identity, filename, bridge):
    expiry = int(time.time()) + bridge.PLAY_HOURS * 3600
    payload = f"v3:{uid}:{kind}:{sid}:{identity}:{expiry}:{filename}"
    mac = hmac.new(bridge.SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return bridge.PUBLIC + (
        f"/play/provider/{uid}/{kind}/{sid}/{identity}/{expiry}/{mac}/"
        + quote(filename, safe="")
    )


def valid_signature(uid, kind, sid, identity, expiry, signature, filename, bridge):
    if (not isinstance(uid, str) or len(uid) != 32 or
            any(ch not in "0123456789abcdef" for ch in uid) or
            kind not in ("movie", "series") or not bridge.safe_int(sid) or
            not bridge.MEDIA_KEY.fullmatch(identity or "") or
            not bridge.FILENAME.fullmatch(filename or "")):
        return False
    try:
        exp = int(expiry)
    except (ValueError, TypeError):
        return False
    if exp < time.time() or exp > time.time() + bridge.PLAY_HOURS * 3600 + 120:
        return False
    payload = f"v3:{uid}:{kind}:{sid}:{identity}:{exp}:{filename}"
    mac = hmac.new(bridge.SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, signature or "")


async def resolve_streams(kind, media_id, bridge):
    if not ENABLED:
        return []
    match_imdb = bridge.STREAM_REQUEST.fullmatch(media_id)
    match_tmdb = bridge.TMDB_REQUEST.fullmatch(media_id)
    if not (match_imdb or match_tmdb):
        return []  # Anime ID crosswalk remains a separate workstream.
    identity, season, episode = (match_imdb or match_tmdb).groups()
    original_identity = (identity if match_imdb else
                         f"tmdb-{'movie' if kind == 'movie' else 'tv'}-{identity}")
    tmdb = None if match_imdb else identity
    imdb = identity if match_imdb else None
    rows = lookup_rows(kind, imdb=imdb, tmdb=tmdb)
    if not rows and imdb and bridge.TMDB_KEY:
        crosswalk = await bridge.tmdb_from_imdb(kind, imdb)
        rows = lookup_rows(kind, imdb=imdb, tmdb=crosswalk)
    if not rows:
        return []
    if kind == "series":
        if season is None or episode is None:
            return []
        season, episode = int(season), int(episode)
        chosen = rows[:bridge.SERIES_JIT_MAX_VARIANTS]
        tasks = [
            asyncio.create_task(hydrate(r["provider_id"], r["item_id"], season, episode, bridge))
            for r in chosen if not episode_rows(r["provider_id"], r["item_id"], season, episode)
        ]
        if tasks:
            done, waiting = await asyncio.wait(tasks, timeout=MAX_DETAIL_SECONDS)
            for t in waiting:
                t.cancel()
            if waiting:
                await asyncio.gather(*waiting, return_exceptions=True)
            for t in done:
                if not t.cancelled():
                    try:
                        t.result()
                    except Exception:
                        pass
    streams = []
    for r in rows[:24]:
        if kind == "movie":
            selected = [(r["item_id"], r["extension"], None)]
        else:
            episodes = episode_rows(r["provider_id"], r["item_id"], season, episode)
            selected = [(ep["stream_id"], ep["extension"], ep["name"]) for ep in episodes]
        for sid, ext, episode_name in selected:
            quality = bridge.quality_hint(episode_name, r["name"])
            filename = bridge.friendly_filename(
                r["name"], kind, ext, season, episode, quality=quality
            )
            label = r["label"] + (" " + quality if quality else "")
            streams.append({
                "name": label,
                "title": f"{filename} | {label}",
                "description": f"{filename} | {label}",
                "url": signed_url(r["provider_id"], kind, sid, original_identity, filename, bridge),
                "behaviorHints": {
                    "notWebReady": ext.lower() != "mp4",
                    "filename": filename,
                    **({"bingeGroup": "xtream-" + r["provider_id"] + "-" + str(r["item_id"])}
                       if kind == "series" else {}),
                },
            })
            if len(streams) >= 20:
                return streams
    return streams


def existing_stream(uid, kind, sid, ext):
    try:
        vault.active_profile(uid)
    except (KeyError, vault.RegistryUnavailable):
        return False
    with ops.database() as con:
        if kind == "movie":
            row = con.execute(
                "SELECT 1 FROM provider_items WHERE provider_id=? AND "
                "kind='movie' AND item_id=? AND extension=?",
                (uid, sid, ext),
            ).fetchone()
        else:
            row = con.execute(
                "SELECT 1 FROM provider_episodes WHERE provider_id=? "
                "AND stream_id=? AND extension=?",
                (uid, sid, ext),
            ).fetchone()
    return bool(row)


def health():
    if not ENABLED:
        return {"enabled": False}
    with ops.database() as con:
        indexed = con.execute(
            "SELECT COUNT(DISTINCT provider_id) FROM provider_items").fetchone()[0]
        profiles = con.execute(
            "SELECT COUNT(*), SUM(enabled) FROM provider_profiles").fetchone()
    return {"enabled": True, "profiles": profiles[0],
            "active": profiles[1] or 0, "indexed": indexed,
            "counters": dict(COUNTERS)}
