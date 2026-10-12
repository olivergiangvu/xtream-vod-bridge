#!/usr/bin/env python3
"""Inspect only upstream HTTP statuses and redirect hosts for mapped VOD.

Run inside the existing bridge container through stdin:
  sudo git -C /opt/xtream-vod-bridge show origin/main:scripts/inspect_provider_redirects.py \
    | sudo docker exec -i xtream-vod-bridge python -

Reads existing provider environment and SQLite index, makes at most three
GET Range: bytes=0-0 upstream requests, closes responses without reading body.
Never prints media IDs, credentials, complete URLs, path/query or response body.
"""
from __future__ import annotations

import ipaddress
import sqlite3
from urllib.parse import quote, urljoin, urlsplit

import httpx

import app as bridge


def safe_host_name(host: str | None) -> str:
    """Preserve public CDN hostname, hide internal/private address."""
    if not host:
        return "(missing)"
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            return "(non-public-address)"
    except ValueError:
        pass
    return host.lower()


def redirect_details(url: str, location: str) -> dict[str, str]:
    """Return only metadata needed to reason about a redirect, never its URL."""
    try:
        target = urljoin(url, location)
        parsed = urlsplit(target)
        source = urlsplit(bridge.BASE)
        if not parsed.hostname:
            return {"redirect_target": "(invalid)", "allowed": "False", "reason": "invalid"}
        if parsed.username or parsed.password:
            reason = "userinfo_present"
        elif parsed.scheme not in ("http", "https"):
            reason = "unsupported_scheme"
        elif source.scheme == "https" and parsed.scheme != "https":
            reason = "https_downgrade"
        elif parsed.hostname.lower() != source.hostname.lower():
            reason = "different_hostname"
        elif parsed.port not in (None, source.port, 443 if parsed.scheme == "https" else 80):
            reason = "different_port"
        else:
            reason = "same_provider_host"
        allowed = bridge.safe_redirect(target)
        return {
            "redirect_target": safe_host_name(parsed.hostname),
            "redirect_scheme": parsed.scheme,
            "redirect_port": str(parsed.port or "default"),
            "allowed": str(allowed),
            "reason": reason if not allowed else "allowed",
        }
    except Exception:
        return {"redirect_target": "(invalid)", "allowed": "False", "reason": "invalid"}


def main() -> int:
    with sqlite3.connect(bridge.DB_PATH) as con:
        rows = con.execute(
            "SELECT item_id, extension FROM items "
            "WHERE kind='movie' AND imdb_id LIKE 'tt%' AND checked_at > 0 "
            "ORDER BY checked_at DESC LIMIT 3"
        ).fetchall()
    print("UPSTREAM_REDIRECT_DIAGNOSIS")
    print("SAMPLES:", len(rows))
    if not rows:
        return 2
    failures = 0
    for n, (stream_id, ext) in enumerate(rows, 1):
        url = (
            f"{bridge.BASE}/movie/{quote(bridge.USER, safe='')}/"
            f"{quote(bridge.PASSWORD, safe='')}/{stream_id}.{ext}"
        )
        try:
            with httpx.Client(
                timeout=httpx.Timeout(18.0, connect=10.0),
                follow_redirects=False,
            ) as client:
                request = client.build_request(
                    "GET", url, headers={"Range": "bytes=0-0"}
                )
                response = client.send(request, stream=True)
                try:
                    status = response.status_code
                    print(f"SAMPLE_{n}_UPSTREAM_HTTP: {status}")
                    if status in (301, 302, 303, 307, 308):
                        info = redirect_details(url, response.headers.get("location", ""))
                        for key, value in info.items():
                            print(f"SAMPLE_{n}_{key.upper()}: {value}")
                        failures += not (info["allowed"] == "True")
                    elif status not in (200, 206):
                        failures += 1
                finally:
                    response.close()
        except Exception as exc:
            # Never print exception messages: httpx can include secret-bearing URL.
            print(f"SAMPLE_{n}_ERROR: {type(exc).__name__}")
            failures += 1
    print("REVIEW_COUNT:", failures)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
