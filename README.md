# Xtream VOD Unified v0.6.0 — HomeDocker

**Status: operationally accepted on HomeDocker (16 October 2026).** Single-container Unified production, protected Safari sign-in, Owner/User Web UI, HTTPS legacy addon manifest and existing playback have been verified. This is not an independent security certification or a guarantee of portability to new hardware.

This replaces the original v0.3–v0.5 overview, preserved in [historical README](docs/archive/README-pre-v0.6.md). **Warning:** the root `compose.yaml` remains the retired two-service legacy template. Do **not** use it to recreate v0.6 production. Use the private canonical Compose deployed on HomeDocker.

## Features

- A single Uvicorn/FastAPI worker handles Xtream VOD indexing, Stremio/AIOStreams `/a/*` manifest and signed `/play/*` relay, and Admin/User interface.
- Movies, series/episodes, identity-based matching and compatible HTTP Range playback; no Live TV, EPG, transcoding or guessed fuzzy matching.
- Owner/System Administration, User/My Workspace, HTTPS Xtream or M3U personal sources, encrypted provider secrets and per-user private addon manifests.
- Safari-native username/password gateway with secure cookies, nonce, CSRF and RBAC; session-guarded Admin assets and APIs.
- `/live` O(1) liveness; `/ready` SQLite connection check; compatibility `/health` retained.

## Accepted topology

```text
Host nginx HTTPS :18450
  /a/*, /play/*   -> public signed addon endpoints
  /admin/*        -> nginx auth_request/session-protected Web UI
  /admin-signin/* -> Safari form/login gateway
  internal subrequest -> /api/auth/gate-check
  all other public fallback paths -> 404
          |
  127.0.0.1:18769 -> xtream-vod-unified:8767
          |
  external Docker volume xtream-vod-bridge_xtream_vod_index
```

Canonical management location: `/opt/homedocker/stacks/xtream-vod-unified/compose.yml`, with root-only `production.env`. Current known-good immutable image ID: `sha256:7a00ea49da7ff90bcff1823c45b183a779c5ea46424331fa397308c3ab6e1ebd`. The environment, OAuth-like private tokens, provider credentials, `SOURCE_SECRETS_KEY`, signing keys and SQLite content **must never be committed**.

**Image provenance:** production image was patched locally from a Canary artifact to fix non-root JS asset modes. `Dockerfile.unified` now includes this correction, but a new source-built image has **not** been shown byte-identical or equivalent to the accepted binary. Do not redeploy an unverified rebuilt image in place of `sha256:7a00ea49da7ff90bcff1823c45b183a779c5ea46424331fa397308c3ab6e1ebd`.

## Docs and recovery

- [v0.6 acceptance gates & incident record](docs/release/0.6-unified-stable-gates.md)
- [HomeDocker deployment & restore](docs/deployment/homedocker-v0.6.md)
- [Reference Unified Compose](deploy/compose.unified.example.yaml)
- [ADR-0005: single ASGI process](docs/adr/0005-unified-xtream-one-container.md)
- [Security](SECURITY.md) · [Changelog](CHANGELOG.md) · [Historical README](docs/archive/README-pre-v0.6.md)

OneDrive/restic snapshot `4cee1ca2` (2026-10-16 09:52 ICT) passed repository integrity and selected remote reads; staged canonical Compose/environment match production, the SQLite volume was included, and a ~150.8 MiB image archive exists. **New rollback archives created after that snapshot require a later backup. Full hardware replacement restore remains untested.**

## Developer checks (not deployment commands)

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
node --check admin/assets/app.js
node --check admin/assets/workspace.js
node tests/ui_workspace_smoke.js
python scripts/check_repo.py
```

Use only authorized content providers; observe connection limits and applicable copyright rules.
