"""Tenant-scoped Stremio addon and HMAC-v5 VOD streaming relay.

Legacy /a/{ADDON_TOKEN} and /play v2 are not modified. v5 HMAC binds
manifest + source + exact record + requested media identity + filename.
A revoked manifest or disabled source invalidates future playback requests.
"""
import hashlib
import hmac
import ipaddress
import re
import time
from urllib.parse import quote, urlsplit, urlunsplit

import httpx
from fastapi import HTTPException, Request, Response
from fastapi.responses import StreamingResponse

import app as bridge
import ops
import personal_index
import personal_manifests
import user_sources

SAFE_ID = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
PLAY_HOURS = 6


def _sign(mid, source_id, kind, item_key, stream_key, identity, expiry, filename):
    payload = (f"v5:{mid}:{source_id}:{kind}:{item_key}:{stream_key}:"
               f"{identity}:{expiry}:{filename}")
    return hmac.new(
        bridge.SECRET.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()


def _signed_url(mid, source_id, kind, item_key, stream_key, identity, filename):
    expires = int(time.time()) + min(bridge.PLAY_HOURS, PLAY_HOURS) * 3600
    signature = _sign(
        mid, source_id, kind, item_key, stream_key, identity, expires, filename
    )
    return (
        bridge.PUBLIC.rstrip("/") + "/play/v5/" +
        "/".join((mid, source_id, kind, item_key, stream_key, identity,
                  str(expires), signature, quote(filename, safe="")))
    )


def manifest(token):
    cfg = personal_manifests.resolve_token(token)
    if not cfg:
        raise HTTPException(404)
    return {
        "id": "org.homedocker.xtreamvod." + cfg["manifest_id"],
        "version": "0.5.0",
        "name": cfg["name"],
        "description": "User-owned, private VOD sources by verified IMDb/TMDb IDs",
        "resources": ["stream"],
        "types": ["movie", "series"] if not bridge.MOVIES_ONLY else ["movie"],
        "catalogs": [],
        "idPrefixes": ["tt", "tmdb:"],
    }


def streams(token, media_type, media_id):
    manifest = personal_manifests.resolve_token(token)
    if not manifest:
        raise HTTPException(404)
    if media_type not in ("movie", "series") or (
        media_type == "series" and bridge.MOVIES_ONLY
    ):
        return {"streams": []}
    imdb_match = bridge.STREAM_REQUEST.fullmatch(media_id)
    tmdb_match = bridge.TMDB_REQUEST.fullmatch(media_id)
    if not (imdb_match or tmdb_match):
        return {"streams": []}

    media_value, season, episode = (imdb_match or tmdb_match).groups()
    if media_type == "movie" and season is not None:
        return {"streams": []}
    if media_type == "series" and (season is None or episode is None):
        return {"streams": []}
    identity = media_value if imdb_match else (
        "tmdb-" + ("movie" if media_type == "movie" else "tv") + "-" + media_value
    )
    lookup = personal_index.resolve_for_manifest(
        manifest["sources"], media_type,
        imdb=media_value if imdb_match else None,
        tmdb=media_value if tmdb_match else None,
        season=int(season) if season is not None else None,
        episode=int(episode) if episode is not None else None,
    )
    results = []
    for row, ep in lookup[:20]:
        name = ep["name"] if ep else row["name"]
        ext = ep["extension"] if ep else row["extension"]
        stream_key = ep["stream_key"] if ep else row["item_key"]
        filename = bridge.friendly_filename(
            name or row["name"], media_type, ext, season, episode,
            quality=bridge.quality_hint(name, row["name"]),
        )
        if not bridge.FILENAME.fullmatch(filename):
            continue
        results.append({
            "name": row["name"][:64],
            "title": filename,
            "url": _signed_url(
                manifest["manifest_id"], row["source_id"], media_type,
                row["item_key"], stream_key, identity, filename,
            ),
            "behaviorHints": {
                "notWebReady": ext.lower() != "mp4",
                "filename": filename,
                **({"bingeGroup": "xtream-v5-" + row["source_id"]}
                   if media_type == "series" else {}),
            },
        })
    return {"streams": results}


def _validate_play(mid, source_id, kind, item_key, stream_key, identity, exp, sig, filename):
    keys = [mid, source_id, item_key, stream_key]
    if (not all(SAFE_ID.fullmatch(v or "") for v in keys)
            or kind not in ("movie", "series")
            or not bridge.MEDIA_KEY.fullmatch(identity or "")
            or not bridge.FILENAME.fullmatch(filename or "")
            or not re.fullmatch(r"[a-f0-9]{64}", sig or "")):
        return False
    try:
        expiry = int(exp)
    except ValueError:
        return False
    if expiry < int(time.time()) or expiry > int(time.time()) + PLAY_HOURS * 3600 + 120:
        return False
    return hmac.compare_digest(
        _sign(mid, source_id, kind, item_key, stream_key, identity, expiry, filename),
        sig,
    )


def _source_stream(mid, source_id, kind, item_key, stream_key):
    owner = personal_manifests.resolve_id(mid, source_id)
    if owner is None:
        raise HTTPException(404)
    with ops.database() as con:
        media = con.execute(
            "SELECT * FROM tenant_media WHERE source_id=? AND kind=? AND item_key=?",
            (source_id, kind, item_key),
        ).fetchone()
        if media is None:
            raise HTTPException(404)
        if kind == "movie":
            if item_key != stream_key:
                raise HTTPException(404)
            episode = None
        else:
            episode = con.execute(
                "SELECT * FROM tenant_episodes WHERE source_id=? AND "
                "series_key=? AND stream_key=? LIMIT 1",
                (source_id, item_key, stream_key),
            ).fetchone()
            if episode is None:
                raise HTTPException(404)
    source = user_sources.get_owned(owner, source_id)
    config = user_sources._config(source)
    encrypted = episode["stream_ciphertext"] if episode else media["stream_ciphertext"]
    if source["kind"] == "m3u":
        if not encrypted:
            raise HTTPException(404)
        from cryptography.fernet import InvalidToken
        try:
            url = user_sources._cipher().decrypt(encrypted).decode("utf-8")
        except (InvalidToken, UnicodeError):
            raise HTTPException(404) from None
    else:
        # Numeric Xtream stream IDs are required; never trust arbitrary URL
        # fragments as a provider path.
        if not stream_key.isdecimal() or not 0 < int(stream_key) < 2**63:
            raise HTTPException(404)
        ext = episode["extension"] if episode else media["extension"]
        from urllib.parse import quote
        url = (config["base_url"] +
               ("/movie/" if kind == "movie" else "/series/") +
               quote(config["username"], safe="") + "/" +
               quote(config["password"], safe="") + "/" +
               stream_key + "." + ext)
    # Always revalidate before reaching outbound network.
    try:
        return user_sources._validated_url(url, playlist=True)
    except ValueError:
        raise HTTPException(404) from None


async def relay(mid, source_id, kind, item_key, stream_key,
                identity, exp, sig, filename, request: Request):
    if not _validate_play(mid, source_id, kind, item_key, stream_key,
                          identity, exp, sig, filename):
        raise HTTPException(403)
    upstream = _source_stream(mid, source_id, kind, item_key, stream_key)
    target = urlsplit(upstream)
    port = target.port or 443
    range_header = request.headers.get("range")
    if range_header and (
        len(range_header) > 100 or
        not re.fullmatch(r"bytes=\d*-\d*", range_header) or
        range_header == "bytes=-"
    ):
        raise HTTPException(416)
    try:
        ip = await user_sources._resolve_public(target.hostname, port)
    except (ValueError, OSError):
        raise HTTPException(502, "Upstream resolution failed") from None
    host_header = target.netloc
    netloc = ("[" + ip + "]" if ":" in ip else ip) + f":{port}"
    pinned_url = urlunsplit(("https", netloc, target.path or "/",
                            target.query, ""))
    headers = {"Host": host_header, "Accept-Encoding": "identity"}
    if range_header:
        headers["Range"] = range_header
    client = httpx.AsyncClient(
        timeout=httpx.Timeout(90.0, connect=12.0),
        follow_redirects=False, trust_env=False,
    )
    try:
        req = client.build_request(
            request.method, pinned_url, headers=headers,
            extensions={"sni_hostname": target.hostname},
        )
        upstream_response = await client.send(req, stream=True)
        if upstream_response.status_code not in (200, 206):
            await upstream_response.aclose()
            await client.aclose()
            raise HTTPException(502, "Upstream playback unavailable")
        if range_header and upstream_response.status_code != 206:
            await upstream_response.aclose()
            await client.aclose()
            raise HTTPException(502, "Upstream did not support Range")
        response_headers = {
            "Accept-Ranges": "bytes",
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        }
        for key in ("content-range", "content-length"):
            value = upstream_response.headers.get(key)
            if value and len(value) < 120:
                response_headers[key.title()] = value
        mime = upstream_response.headers.get("content-type", "application/octet-stream")
        if not (mime.startswith("video/") or mime in (
                "application/octet-stream", "application/vnd.apple.mpegurl",
                "application/x-mpegURL")):
            mime = "application/octet-stream"
        if request.method == "HEAD":
            await upstream_response.aclose()
            await client.aclose()
            return Response(status_code=upstream_response.status_code,
                            headers=response_headers, media_type=mime)

        async def body():
            try:
                async for chunk in upstream_response.aiter_raw():
                    yield chunk
            finally:
                await upstream_response.aclose()
                await client.aclose()

        return StreamingResponse(
            body(), status_code=upstream_response.status_code,
            headers=response_headers, media_type=mime,
        )
    except HTTPException:
        raise
    except (httpx.HTTPError, OSError):
        await client.aclose()
        raise HTTPException(502, "Upstream playback unavailable") from None
