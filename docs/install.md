# Installation and recovery — v0.6.0

[Home](../README.md) · [Usage](usage.md) · [Operations](operations.md) · [DR](deployment/homedocker-v0.6.md)

## Choose the correct installation path

**A. Restore the accepted HomeDocker image (recommended for HomeDocker replacement).** This repository does **not** distribute a pullable v0.6.0 Docker image. The authoritative binary is archived in the private encrypted Restic/OneDrive backup. Restore its exact tar, the original private `production.env`, external SQLite volume and nginx configuration.

**B. Build from source (developers/test only).** The locally hotfixed production image is **not proven equivalent** to a fresh `Dockerfile.unified` build. Never silently replace the running production image with a freshly built one.

The root [`compose.yaml`](../compose.yaml) is a *reference* pinned to the HomeDocker image SHA, not a turnkey deployment. It requires an existing external volume and a private `production.env`.

## Prerequisites

- Linux server with Docker Engine, `docker compose` plugin and a host-level nginx reverse proxy with trusted HTTPS certificate.
- Private storage/credentials for a permitted Xtream or M3U VOD provider and matching `SOURCE_SECRETS_KEY`; never include the provider password inside a public URL.
- Private persisted SQLite volume `xtream-vod-bridge_xtream_vod_index` for HomeDocker restores; **do not create an empty replacement volume and mistake it for a successful restore**.
- Port `127.0.0.1:18769` available on host and nginx HTTPS port `18450` allocated per your current plan. Other installations can choose different loopback ports but must update nginx and Compose together.

## Path A — restore existing HomeDocker

1. Restore the canonical private files to `/opt/homedocker/stacks/xtream-vod-unified/` and protect them (`production.env` owner root, mode 0600). Restore nginx vhost/auth snippet and the volume **with no active old writers**.
2. Recover the archived Docker image, verify its archive integrity via your backup manifest, and load it:
   ```bash
   sudo docker load -i /path/to/verified/local-images/7a00ea49da7ff90bcff1823c45b183a779c5ea46424331fa397308c3ab6e1ebd.tar
   sudo docker image inspect sha256:7a00ea49da7ff90bcff1823c45b183a779c5ea46424331fa397308c3ab6e1ebd --format '{{.Id}}'
   ```
   Inspect output must be **exactly** `sha256:7a00ea49da7ff90bcff1823c45b183a779c5ea46424331fa397308c3ab6e1ebd`. A local tag is optional; GitHub is not the binary registry.
3. Confirm restored `SOURCE_SECRETS_KEY` matches the restored SQLite ciphertext. An incorrect Fernet key makes the personal source passwords undecryptable.
4. Validate without printing secrets, and review the rendered Compose for volumes and local port:
   ```bash
   sudo docker compose -f /opt/homedocker/stacks/xtream-vod-unified/compose.yml config -q
   sudo nginx -t
   sudo docker volume inspect xtream-vod-bridge_xtream_vod_index --format '{{.Name}}'
   ```
5. Only when restore and nginx allowlist are verified, start **one** service:
   ```bash
   sudo docker compose -f /opt/homedocker/stacks/xtream-vod-unified/compose.yml up -d --no-build --pull never
   ```
6. Wait for the 60s health cycle, then test:
   ```bash
   sudo docker inspect xtream-vod-unified --format 'HEALTH={{.State.Health.Status}} RESTARTS={{.RestartCount}}'
   curl --noproxy '*' -sS -o /dev/null -w 'LIVE=%{http_code}\n' http://127.0.0.1:18769/live
   curl --noproxy '*' -sS -o /dev/null -w 'READY=%{http_code}\n' http://127.0.0.1:18769/ready
   ```
   Both URLs should be HTTP 200, with Docker health `healthy`. Confirm `/admin/` redirects unauthenticated users to the sign-in page, and validate authorized manifest/playback separately without pasting tokens into public logs.

### nginx is mandatory for protected Web UI

Do not directly expose backend :18769. Host nginx owns TLS :18450 and uses explicit public allowlist `/a/*`, `/play/*`. Private `/admin/*` must use `auth_request` to the internal auth gate; `/admin-signin/*` is the public HTTPS login form. Deny public `/api/*`, `/assets/*`, `/gateway/*`, `/console`, and `/`. Use the recovered **tested production** nginx config (not archived old `:18768` snippets); run `nginx -t` before any reload. A wrong nginx catch-all previously exposed internal Admin endpoints.

## Path B — source build for a disposable test stack

```bash
git clone https://github.com/olivergiangvu/xtream-vod-bridge.git
cd xtream-vod-bridge
git checkout v0.6.0
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
node --check admin/assets/app.js
node --check admin/assets/workspace.js
python3 scripts/check_repo.py
docker build -f Dockerfile.unified -t xtream-vod-unified:local-test .
```

This yields **your own** image ID, not the SHA of the accepted HomeDocker image. For disposable testing, create a separate directory, local env/secrets, non-production volume and port, then explicitly reference `xtream-vod-unified:local-test`; **never** run root `compose.yaml` against the production external volume. Test auth/manifest/Range playback and nginx routing before proposing production promotion.

## Configuration

Copy the non-secret example [`.env.example`](../.env.example) to a **private** `production.env` in your runtime directory, then enter real credentials only there; use mode `0600`. Key variables:
- `PUBLIC_BASE_URL`: externally reachable trusted HTTPS origin with port (e.g. `https://your.example:18450`), no credentials and no custom `/xtream-vod` prefix unless your reverse proxy has been explicitly engineered for it.
- `ADDON_TOKEN`, `ADMIN_TOKEN`, `PLAYBACK_SECRET`: independent random secrets, not a reused password.
- `XTREAM_BASE_URL`, `XTREAM_USERNAME`, `XTREAM_PASSWORD`: optional/required according to the configured legacy global provider; keep them server-side.
- `SOURCE_SECRETS_KEY`: persistent Fernet key for personal encrypted sources. **Back up paired with SQLite**.
- `XTREAM_UNIFIED_MODE=1`, `LEGACY_SYNC_ENABLED=1`: accepted HomeDocker Unified scheduler settings.

See [operations](operations.md) before enabling any Watchtower/Dockhand auto-redeploy; `pull_policy: never` and immutable image SHA intentionally prevent untested updates.

## Limitations

No registry image download, automated safe WAN nginx installer, full bare-metal recovery test or universal provider success is claimed. The historical v0.3–v0.5 LAN and Canary scripts are retained as reference, not current deployment recipes.
