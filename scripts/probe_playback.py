#!/usr/bin/env python3
"""Read-only HTTPS and bounded Range probe for an authorized Xtream VOD Bridge.

Run on HomeDocker: sudo python3 scripts/probe_playback.py
- TLS verifies the configured public hostname but connects to local nginx loopback.
- Never prints IPTV credentials, addon tokens, signed URLs, or response bodies.
- Fetches no more than 1024 media bytes per selected movie/episode.
"""
from __future__ import annotations

import argparse
import http.client
import json
import re
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit


def config_values(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in (root / ".env").read_text().splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        result[key.strip()] = value.strip().strip("'\"")
    return result


def local_https_request(
    host: str, port: int, path: str, *, max_bytes: int = 65536,
    headers: dict[str, str] | None = None, timeout: float = 25.0
) -> tuple[int, dict[str, str], bytes]:
    """Validate TLS against host while using 127.0.0.1 instead of DDNS/NAT."""
    if not path.startswith("/") or max_bytes < 1:
        raise ValueError("Invalid request")
    context = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, port, context=context, timeout=timeout)
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        conn.sock = context.wrap_socket(raw, server_hostname=host)
        conn.request("GET", path, headers=headers or {})
        response = conn.getresponse()
        return (
            response.status,
            {key.lower(): value for key, value in response.getheaders()},
            response.read(max_bytes),
        )
    finally:
        conn.close()


def movie_ids(limit: int) -> list[str]:
    sql = """
import sqlite3
con=sqlite3.connect('/data/index.sqlite')
for row in con.execute(
    "SELECT DISTINCT imdb_id FROM items "
    "WHERE kind='movie' AND imdb_id LIKE 'tt%' AND checked_at > 0 "
    "ORDER BY checked_at DESC LIMIT ?", (5,)):
    print(row[0])
"""
    result = subprocess.run(
        ["docker", "exec", "xtream-vod-bridge", "python", "-c", sql],
        capture_output=True, text=True, timeout=15, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Movie index unavailable")
    ids = [line for line in result.stdout.splitlines()
           if re.fullmatch(r"tt[0-9]{7,10}", line)]
    return ids[:limit]


def episode_ids(limit: int) -> list[str]:
    """Choose up to N mapped, hydrated episodes across distinct Series.

    Only emits validated IDs into this process; never prints titles, tokens,
    provider URLs or internal database keys.
    """
    sql = """
import sqlite3
con=sqlite3.connect('/data/index.sqlite')
for r in con.execute(
    "SELECT i.imdb_id, i.tmdb_id, e.season, e.episode "
    "FROM episodes e INNER JOIN items i "
    "ON i.kind='series' AND i.item_id=e.series_id "
    "WHERE (i.imdb_id LIKE 'tt%' OR i.tmdb_id IS NOT NULL) "
    "GROUP BY e.series_id ORDER BY i.checked_at DESC LIMIT ?", (5,)
):
    imdb_id, tmdb_id, season, episode = r
    if imdb_id and str(imdb_id).startswith('tt'):
        print(f'{imdb_id}:{season}:{episode}')
    elif tmdb_id:
        print(f'tmdb:tv:{tmdb_id}:{season}:{episode}')
"""
    result = subprocess.run(
        ["docker", "exec", "xtream-vod-bridge", "python", "-c", sql],
        capture_output=True, text=True, timeout=15, check=False,
    )
    if result.returncode:
        raise RuntimeError("Series episode index unavailable")
    valid = re.compile(
        r"^(?:tt\d{7,10}|tmdb:tv:\d+):\d+:\d+$"
    )
    return [x for x in result.stdout.splitlines() if valid.fullmatch(x)][:limit]


def playback_path(raw_url: str, base_url: str, media_kind: str = "movie") -> str:
    """Accept only playback signed URLs on this bridge's exact HTTPS origin."""
    target, public = urlsplit(raw_url), urlsplit(base_url)
    if media_kind not in ("movie", "series"):
        raise ValueError("Unsupported media kind")
    prefix = public.path.rstrip("/") + "/play/" + media_kind + "/"
    if (
        target.scheme != "https" or public.scheme != "https"
        or target.hostname != public.hostname
        or target.port != public.port
        or target.username or target.password or target.fragment
        or not target.path.startswith(prefix)
    ):
        raise ValueError("Stream URL does not match configured bridge origin")
    # v0.2 query-free names keep the signed credentials in parent path
    # and end with a readable media filename, which fixes mpv filename detection.
    if not target.query:
        path = unquote(target.path)
        if not re.fullmatch(
            re.escape(prefix) + r"\d+/(?:tt\d{7,10}|tmdb-(?:movie|tv)-\d+|(?:anilist|kitsu|mal)-\d+)/"
            r"\d+/[0-9a-f]{64}/[^/]+\.(?:mp4|mkv|avi|mov|ts|m3u8|flv|wmv|3gp)", path, re.I
        ):
            raise ValueError("Invalid descriptive signed playback URL")
        return target.path
    if "exp=" not in target.query or "sig=" not in target.query:
        raise ValueError("Missing legacy playback token")
    return target.path + "?" + target.query



def wait_for_health(
    checker, *, attempts: int = 25, pause_seconds: float = 2,
    sleeper=time.sleep,
) -> tuple[int, int]:
    """Wait for nginx→backend readiness after container recreate.

    Retry only transient unavailable statuses and transport errors. Fail closed
    on permission/configuration errors such as 403/404, and never print URLs.
    """
    if attempts < 1:
        raise ValueError("attempts must be positive")
    last_status = 0
    for attempt in range(1, attempts + 1):
        try:
            last_status = checker()
        except (OSError, http.client.HTTPException):
            last_status = 0
        if last_status == 200:
            return 200, attempt
        if last_status not in (0, 502, 503, 504):
            return last_status, attempt
        if attempt < attempts:
            sleeper(pause_seconds)
    return last_status, attempts


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bounded HTTPS and byte-range probe; never prints secrets"
    )
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--type", choices=("movie", "series"), default="movie",
                        help="select mapped Movies or hydrated Series episodes")
    parser.add_argument("--timeout", type=float, default=25.0)
    args = parser.parse_args()
    if not 1 <= args.samples <= 5 or not 2 <= args.timeout <= 60:
        parser.error("samples must be 1..5; timeout must be 2..60")

    try:
        settings = config_values(Path(__file__).resolve().parents[1])
        token = settings.get("ADDON_TOKEN", "")
        public_url = settings.get("PUBLIC_BASE_URL", "").rstrip("/")
        public = urlsplit(public_url)
        if (
            len(token) < 32 or token.startswith("REPLACE_")
            or public.scheme != "https" or not public.hostname
            or public.username or public.password or public.query or public.fragment
        ):
            raise ValueError("Invalid local settings")
        host = public.hostname
        port = public.port or 443
        base_path = public.path.rstrip("/")
        prefix = base_path + "/a/" + quote(token, safe="")

        def get(path: str, **kwargs):
            return local_https_request(host, port, path, timeout=args.timeout, **kwargs)

        health_status, attempts = wait_for_health(
            lambda: local_https_request(
                host, port, "/health", max_bytes=4096, timeout=4
            )[0],
        )
        print("LOCAL_HTTPS_HEALTH:", health_status)
        print("HEALTH_ATTEMPTS:", attempts)
        if health_status != 200:
            raise RuntimeError("Local HTTPS health failed after bounded readiness wait")

        status, _, manifest_bytes = get(prefix + "/manifest.json")
        manifest = json.loads(manifest_bytes)
        print("MANIFEST_HTTP:", status)
        if status != 200 or "stream" not in manifest.get("resources", []):
            raise RuntimeError("Stremio manifest invalid")

        candidates = (episode_ids(args.samples) if args.type == "series"
                      else movie_ids(args.samples))
        print("CANDIDATE_EPISODES:" if args.type == "series" else "CANDIDATE_MOVIES:",
              len(candidates))
        if not candidates:
            raise RuntimeError("No hydrated mapped content IDs for selected type")
        results: list[str] = []
        for index, media_id in enumerate(candidates, start=1):
            try:
                status, _, payload = get(prefix + "/stream/" + args.type + "/" + media_id + ".json")
                if status != 200:
                    print(f"SAMPLE_{index}: STREAM_HTTP_{status}")
                    results.append("NO_STREAM")
                    continue
                streams = json.loads(payload).get("streams", [])
                if not streams:
                    print(f"SAMPLE_{index}: STREAM_EMPTY")
                    results.append("NO_STREAM")
                    continue
                path = playback_path(streams[0].get("url", ""), public_url,
                                     media_kind=args.type)
                if args.type == "series":
                    clean_filename = bool(re.search(
                        r"\.S\d{2,3}E\d{2,3}\.", unquote(path), re.I
                    ))
                    print(f"SAMPLE_{index}: CLEAN_EPISODE_FILENAME={clean_filename}")
                    if not clean_filename:
                        results.append("BAD_FILENAME")
                        continue
                status, headers, data = get(
                    path, headers={"Range": "bytes=0-1023"}, max_bytes=1024,
                )
                size = len(data)
                content_range = headers.get("content-range", "")
                if status == 206 and size and content_range.startswith("bytes 0-"):
                    outcome = "PASS_206"
                elif status == 200 and size:
                    outcome = "REVIEW_200_NO_RANGE"
                else:
                    outcome = "REVIEW"
                results.append(outcome)
                print(f"SAMPLE_{index}: HTTP={status} BYTES={size} RANGE={bool(content_range)} {outcome}")
            except Exception as exc:
                # Exceptions may contain credential-bearing request URLs: print type only.
                print(f"SAMPLE_{index}: ERROR={type(exc).__name__}")
                results.append("ERROR")

        successes = results.count("PASS_206")
        print(f"RANGE_206_PASS: {successes}/{len(results)}")
        print("AIOSTREAMS_PLAYBACK_GATE:", "PASS" if successes else "REVIEW_REQUIRED")
        return 0 if successes else 2
    except Exception as exc:
        print("PROBE_FAILED:", type(exc).__name__)
        return 2


if __name__ == "__main__":
    sys.exit(main())
