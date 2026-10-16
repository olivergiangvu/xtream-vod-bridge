# HomeDocker Unified v0.6 — deployment and DR reference

> This page records the already-accepted host architecture. **It is not an approval to modify a live host**, and the example Compose is not a replacement for the private canonical Compose.

## Authoritative production resources

- Canonical Compose: `/opt/homedocker/stacks/xtream-vod-unified/compose.yml`.
- Secret environment: adjacent `production.env`, root-only mode 0600, contains `SOURCE_SECRETS_KEY`. Never commit it.
- Image ID: `sha256:7a00ea49da7ff90bcff1823c45b183a779c5ea46424331fa397308c3ab6e1ebd`. Current accepted binary was locally patched for JS asset read permissions.
- Persistent volume: `xtream-vod-bridge_xtream_vod_index` mounted `/data`.
- Network: container :8767, bound only to host `127.0.0.1:18769`; existing nginx HTTPS :18450.
- Public nginx `/a/`, `/play/`; gated `/admin/` with internal `auth_request`; native Safari `/admin-signin/`; default deny unrelated root/Admin routes.

## Restore sequence — new server

1. Provision Linux/Docker + HTTPS nginx and recover protected OneDrive/restic access. Recreate old LAN/IP/TLS routing by reviewing the recovered config.
2. Restore canonical Compose, nginx files/snippets, **matching** encrypted `production.env`, and SQLite volume. Preserve UID/GID 10001 and ensure no simultaneous legacy writer.
3. Restore the exact production image tar `consistent/local-images/7a00ea49da7ff90bcff1823c45b183a779c5ea46424331fa397308c3ab6e1ebd.tar`, run `docker load -i <verified-image-archive>`, and verify `docker image inspect` matches the pinned SHA. Do not pull a mutable tag instead.
4. Validate external volume and secrets, available port 18769, and nginx config. Start *only* the canonical Unified Compose (`docker compose -f /opt/homedocker/stacks/xtream-vod-unified/compose.yml up -d --no-build --pull never`).
5. Await healthcheck (interval 60s), verify `/live`, `/ready`, `/admin/` unauthorized 302, sign-in HTTP 200 and valid Safari account login. Verify `/a/<private-token>/manifest.json` privately and real signed playback without exposing credentials.
6. Run a full restore drill before promising hardware migration reliability. Never delete the production Docker volume or run blanket Docker prune on the multi-service host.

## Rollback / data loss

Old image archives, historical SQLite checkpoints and nginx backups were saved locally in `/opt/homedocker/stacks/xtream-vod-unified/rollback-legacy`. These SQLite snapshots predate new Unified writes, so using them causes **irreversible loss of later data** unless you first create a new safe checkpoint. The old automatic `cutover.py` script was removed and is not an available recovery tool.

The 09:52 16-Oct OneDrive restic snapshot `4cee1ca2` predates the later local legacy-rollback archive. A new backup is required to protect those recent files.

Reference [Unified Compose](../../deploy/compose.unified.example.yaml), [release evidence](../release/0.6-unified-stable-gates.md) and [security](../../SECURITY.md).
