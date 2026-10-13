# HomeDocker Admin Console — v0.4 pilot

This Web UI is an **optional second Docker service**, not a route of the public
Stremio addon. It is never exposed by the nginx TLS server on 18450.

## Features

- Operations dashboard: Movies, Series, episodes, on-demand cache hits/misses,
  fetch failures, current JIT/Series settings.
- Strand-style **Source Name** (e.g. `Meteor`) applied live to Stremio
  `name`, `title` and `description`. Quality suffixes like `2160p` are
  appended where already recognized. The original signed playback URL remains
  unchanged.
- Editable, bounded, non-secret settings: Source Name, enable/disable on-demand,
  JIT timeout (2–15 s), missing-episode TTL (1–168 h), failure retry (30–3600 s),
  max provider Series variants (1–8), and Series detail quota (0–500, still
  capped by the global MAX_ENRICH_PER_SYNC).
- A ring of 2000 operational events in the existing SQLite index, recording
  only event class, media type, status, duration and returned source count.
- Settings persist across Docker recreations/reboots via `xtream_vod_index`.
  They do not edit `.env` in-place.

**Excluded from Web UI:** IPTV username/password, provider URL, TMDb key, admin/
addon/playback secrets, host networking, public nginx, bootstrap scheduler
enable/disable, redirect policy. Manage these through protected SSH config.
A Web-based raw `.env` editor is intentionally prohibited.

## Deploy safely

Before upgrading, copy `.env` into a root-only backup directory and use
SQLite's `Connection.backup` or `docker cp` to snapshot the index. Avoid
`docker compose down -v`. Pin a reviewed commit and run Movie/Series
`probe_playback.py --samples 3` after upgrade. v0.3.0 rollback is
`2b297cce0076d0c9a89bcb8ad3d8c0b2073084f1`.

```sh
cd /opt/xtream-vod-bridge
sudo docker compose config --quiet
sudo docker compose up -d --build xtream-vod-bridge xtream-vod-admin
sudo docker compose ps
sudo python3 scripts/probe_playback.py --samples 3
sudo python3 scripts/probe_playback.py --type series --samples 3
```

Admin is published only at **`127.0.0.1:18768`** on Linux host. To access
from your Mac, open an SSH tunnel on the Mac (do not run this command on Linux):

```sh
ssh -N -L 18768:127.0.0.1:18768 YOUR_SSH_USER@192.168.50.153
```

Open `http://127.0.0.1:18768/` on the Mac. Enter the existing `ADMIN_TOKEN`
from the server's `.env`; it is **not stored in cookies, localStorage or
sessionStorage** and must be entered again after a browser reload. Never paste
tokens into public chats, GitHub issues or screenshots. If another process
occupies host port 18768, set `BRIDGE_ADMIN_HOST_PORT` in `.env` and change
the SSH tunnel correspondingly.

**Never add nginx `proxy_pass` for admin or router port forwarding on 18768.**
Only the playback/manifest service on 18767 is proxied publicly.

## Using and troubleshooting

1. Log in; check health, source catalog and JIT counters.
2. Change **IPTV source name** from `IPTV VOD` to your chosen brand (e.g.
   `Meteor`), and save. The next backend stream request uses it. Re-open
   the episode/refresh sources in AIOStreams to invalidate old UI-side caches.
3. If an episode source is missing, check diagnostic counters and recent
   `series_jit` events; compare `cache_hit`, `fetch_ok`, `fetch_failed`,
   `timeout` in health. No personally identifying content IDs are shown.
4. For raw server logs run `sudo docker logs --tail 100 xtream-vod-bridge`
   **locally only** and scrub before sharing. Signed URLs and IPTV credentials
   must never enter logs.
5. If admin shows bridge offline, verify the main service is healthy and both
   containers share the Compose network. Do not expose admin publicly to
   diagnose network access.

Safety notes: The admin token is required for **every** API request, and API
responses have `Cache-Control: no-store`, strict CSP, no cross-origin access,
and no embedded credential fields. Docker services run as unprivileged UID
10001, root filesystem read-only, with no additional privileges or Docker
socket. Provider-facing request limits are not raised by the console.
