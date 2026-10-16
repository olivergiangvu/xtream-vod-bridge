# Changelog

## 0.6.0 — 2026-10-16: HomeDocker operational Stable

- Unified Movie/Series addon, signed playback and Owner/User Web UI into one Uvicorn runtime.
- Existing HTTPS :18450 Safari gateway, legacy addon URL and playback compatibility retained.
- Multi-user encrypted Xtream/M3U personal sources and manifests introduced; full new personal-manifest playback acceptance still pending.
- Local JS asset permissions hotfix (non-root 0600 → 0644), now recorded in Dockerfile source.
- Nginx public catch-all replaced with explicit `/a/` and `/play/` allowlist and authenticated Admin paths.
- Canonical Compose migration, retirement of legacy and Canary containers, local archival of old SQLite checkpoints and images.
- Restic/OneDrive snapshot `4cee1ca2` passed repository integrity and selected remote read checks; post-cleanup offsite backup and full hardware DR drill remain pending.
- Running pinned image ID: `sha256:7a00ea49da7ff90bcff1823c45b183a779c5ea46424331fa397308c3ab6e1ebd`. A clean-source image replacement still requires independent verification.

### Repository housekeeping

- Replaced obsolete root two-service `compose.yaml` with the SHA-pinned Unified reference; archived the legacy Compose in `docs/archive/compose-legacy-two-service.yaml`.
- Public documentation deliberately excludes real nginx TLS material, `.env`, IPTV credentials and Fernet signing secrets.
