"""Read-only local Stremio contract smoke test; never prints provider credentials or signed URLs.

Run from repository root: python scripts/smoke_test.py --movie tt0133093
Requires a running bridge bound on loopback and .env with ADDON_TOKEN.
"""
import argparse
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


def secret_from_env(name):
    value = os.environ.get(name, "")
    if value:
        return value
    env_file = Path(__file__).resolve().parents[1] / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip().strip("\"'")
    return ""


def fetch(url):
    with urlopen(Request(url, headers={"Accept": "application/json"}), timeout=10) as response:
        return json.load(response)


def main():
    cli = argparse.ArgumentParser(description="Check local addon HTTP contract (no secrets output)")
    cli.add_argument("--local", default="http://127.0.0.1:18767")
    cli.add_argument("--movie", help="IMDb movie ID, e.g. tt0133093")
    cli.add_argument("--episode", help="IMDb episode ID, e.g. tt7654321:1:2")
    args = cli.parse_args()
    token = secret_from_env("ADDON_TOKEN")
    if not token or token.startswith("REPLACE_"):
        cli.error("ADDON_TOKEN unavailable; configure the local .env first")
    base = args.local.rstrip("/")
    # Do not accept a remote origin for this script: only test local daemon.
    if base not in ("http://127.0.0.1:18767", "http://localhost:18767"):
        cli.error("Only local loopback 18767 is supported")
    prefix = base + "/a/" + quote(token, safe="")
    try:
        status = fetch(base + "/health")
        manifest = fetch(prefix + "/manifest.json")
        if "stream" not in manifest.get("resources", []) or "movie" not in manifest.get("types", []):
            raise ValueError("Missing standard Stremio stream resource")
        print("HTTP manifest: PASS; version:", manifest.get("version"))
        print("Index stats:", json.dumps(status.get("index", {}), ensure_ascii=False))
        print("Last index sync:", status.get("last_sync"))
        for media, media_id in (("movie", args.movie), ("series", args.episode)):
            if not media_id:
                continue
            result = fetch(prefix + "/stream/" + media + "/" + quote(media_id, safe=":") + ".json")
            streams = result.get("streams", [])
            if not isinstance(streams, list):
                raise ValueError("Stream endpoint returned invalid data")
            print(f"{media} mapped streams: {len(streams)}")
            # Not returning a mapped stream is significant: fixture match incomplete.
            if not streams:
                raise ValueError(f"No mapped IPTV stream for requested {media}")
            for item in streams:
                if not item.get("url", "").startswith("https://"):
                    raise ValueError("Playback URL is not public HTTPS")
        print("Smoke test: PASS (playback byte delivery not tested)")
    except (HTTPError, URLError, ValueError, KeyError) as exc:
        # Print only exception *type* to avoid leaking secret-bearing URLs.
        raise SystemExit("Smoke test failed: " + type(exc).__name__)


if __name__ == "__main__":
    main()
