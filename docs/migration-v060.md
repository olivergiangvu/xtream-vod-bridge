# Migration & v0.6.0 post-cutover cleanup

[Home](../README.md) · [Install](install.md) · [Operations](operations.md)

## What changed

- **Before:** separate `xtream-vod-bridge` and `xtream-vod-admin` containers, historical Admin backend 18768, Canary experiment and legacy release script.
- **After:** one `xtream-vod-unified` container on `127.0.0.1:18769`, one scheduler/writer, nginx HTTPS `:18450` and a retained external SQLite volume.
- Canonical stack lives at `/opt/homedocker/stacks/xtream-vod-unified/compose.yml`; Docker labels confirm same Compose owner.
- Owner/User My Workspace and System Administration share the same backend, with nginx session gate retained.
- Dockhand Stacks → `xtream-vod-unified` was adopted as **Internal** without redeploying production; Compose stayed bytewise identical and container Healthy.

## Migration evidence — 2026-10-16

- Production pinned image ID `sha256:7a00ea49da7ff90bcff1823c45b183a779c5ea46424331fa397308c3ab6e1ebd`, local tag `homedocker/xtream-vod-unified:0.6.0-stable`.
- `/live` and `/ready` HTTP 200; unauthorized `/admin/` HTTP 302; actual legacy manifest/playback verified earlier.
- Retired two stopped legacy containers and old Canary containers; preserved local encrypted-DR artifacts and historical SQLite/nginx rollback checkpoints.
- Selective image cleanup: **22 obsolete Xtream image tags removed**, **0 skipped**. Production volume left untouched; no broad Docker prune.
- GitHub Release `v0.6.0` published, separate from unverified future clean-source builds.

## Rollback boundaries

Restoring a historical SQLite checkpoint is a **point-in-time destructive restore**, not a harmless image downgrade. Legacy `cutover.py` was retired; old two-service root Compose is archived under `docs/archive` and must **not** run against the live volume. Do not start both scheduler versions concurrently. Preserve production secrets and the matching Fernet key.

## Deferred validation

- New personal Xtream/M3U manifest → real AIOStreams/Remux/Trellis playback was not comprehensively tested.
- External DNS rebinding / egress safety gate remains open in [Issue #27](https://github.com/olivergiangvu/xtream-vod-bridge/issues/27).
- Full new-hardware disaster recovery and post-cleanup offsite snapshot remain outside the closed migration phase.
