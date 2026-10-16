# Xtream VOD Unified v0.6.0 — HomeDocker Stable

**Scope:** Stable *source/documentation release* of the production-accepted Xtream VOD Unified stack for this private HomeDocker deployment. This release **does not ship a registry-built container image** and does **not** redeploy the host.

## Highlights
- Consolidates legacy Xtream Movie/Series Stremio/AIOStreams addon, HMAC-signed playback and Safari Owner/User admin workspace in **one Uvicorn runtime**.
- Personal Xtream/M3U source configuration, per-user addon manifests, role-based controls and encrypted provider credentials.
- Existing HTTPS listener :18450 retained: default-deny nginx proxy, protected `/admin/` routes and Safari `/admin-signin/`; signed public `/a/` and `/play/`.
- Canonical SHA-pinned Compose, immutable production image backup, nginx/SQLite DR runbook and security release checklist.
- Non-root JS asset read-permissions regression addressed in `Dockerfile.unified`. Legacy TLS probe hardened to TLS >=1.2; CI and CodeQL checks passed.
- HomeDocker phase cleanup removed 22 obsolete Xtream image tags and retired legacy/Canary containers, preserving the production volume and rollback artifacts.

## Deployment identity
Known-good production image ID: `sha256:7a00ea49da7ff90bcff1823c45b183a779c5ea46424331fa397308c3ab6e1ebd`.
Local convenience tag: `homedocker/xtream-vod-unified:0.6.0-stable`.
Runtime canonical Compose: `/opt/homedocker/stacks/xtream-vod-unified/compose.yml`, host loopback `127.0.0.1:18769`, nginx HTTPS :18450, existing external volume `xtream-vod-bridge_xtream_vod_index`.
All production env vars, Fernet `SOURCE_SECRETS_KEY` and IPTV credentials stay off GitHub.

## Assurance / known limits
- User acceptance verified Safari sign-in, Admin UI, legacy addon manifest and existing playback; not every personal-provider workflow is end-to-end tested.
- Locally patched production image is **not** claimed bitwise reproducible from a clean Git build; do not silently replace it.
- Encrypted OneDrive/restic snapshot `4cee1ca2` passed earlier repository integrity and selected remote read tests; post-cleanup rollback archives were created later and await the next **scheduled** backup. Full restore to different hardware remains untested.
- No live provider secrets, SQLite databases, backups or image tar files are distributed.

See [README](../../README.md), [CHANGELOG](../../CHANGELOG.md), [security policy](../../SECURITY.md), [runbook](../deployment/homedocker-v0.6.md), and [acceptance record](0.6-unified-stable-gates.md).
