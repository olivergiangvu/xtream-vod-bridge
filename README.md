# Xtream VOD Unified

[**Official v0.6.0 Stable source release**](https://github.com/olivergiangvu/xtream-vod-bridge/releases/tag/v0.6.0) · [Install / restore](docs/install.md) · [User guide](docs/usage.md) · [Operations / Dockhand](docs/operations.md) · [Migration](docs/migration-v060.md) · [Security](SECURITY.md)

Xtream VOD Unified is a private, self-hosted **Stremio/AIOStreams Movie & Series stream supplier** with a single FastAPI/Uvicorn container, signed playback relay, admin console and per-user Xtream/M3U VOD source workspace. It is not an AIOStreams metadata replacement or a live-TV/EPG system.

## Interface walkthrough

The screenshots below were supplied by the HomeDocker operator during **16 October 2026 acceptance**. They show real UI state, not a claim that every upstream provider or personal manifest flow has passed end-to-end testing.

| Workspace | Administration |
| --- | --- |
| ![My Sources & Addons screenshot from HomeDocker](docs/screenshots/ui-workspace.webp) | ![System Administration screenshot from HomeDocker](docs/screenshots/ui-admin.webp) |
| **My Workspace:** add/test/sync owned Xtream/M3U sources and manage personal manifest tokens | **System Administration:** Owner account management and catalog health |

![Dockhand Internal stack screenshot from HomeDocker](docs/screenshots/dockhand-internal.webp)

Dockhand **Source: Internal** confirms management registration of the single production stack without a production redeploy. It does not prove future one-click redeploy viability.

See the [illustrated usage guide](docs/usage.md) and [Dockhand operations guide](docs/operations.md) for screenshots and steps.

## Features

- Legacy and personal Stremio/AIOStreams manifest routing at `/a/*`, signed Movie/Series playback and HTTP Range relay at `/play/*`.
- One unified process with one SQLite-backed index; legacy and personal source isolation, identity-first IMDb/TMDb matching and configurable Series JIT.
- User-owned HTTPS Xtream Codes and M3U VOD source configuration; per-user private manifests with one-time shown URLs, rotation and revocation.
- Owner/Admin and User roles; Safari-compatible sign-in, session and CSRF validation; encrypted source credentials using private `SOURCE_SECRETS_KEY`.
- Hardened nginx HTTPS boundary: public addon endpoints only, session-gated `/admin/`, public login gateway `/admin-signin/`, default-deny other backend routes.

**Current production is a specifically accepted HomeDocker deployment**, not a published container registry image. The image is identified by immutable Docker image ID:

```text
sha256:7a00ea49da7ff90bcff1823c45b183a779c5ea46424331fa397308c3ab6e1ebd
```

The convenience local Docker tag `homedocker/xtream-vod-unified:0.6.0-stable` points to that image **on the existing HomeDocker only**; it is *not* a registry download URL. Production came from a locally patched Canary image. A new source rebuild is not proven image-equivalent and must be retested before substitution.

## HomeDocker production architecture

```text
Browser / AIOStreams / clients
    |
    v
Host nginx HTTPS :18450
  public  /a/* /play/*
  gated   /admin/*  (auth_request)
  login   /admin-signin/*
  deny    /, /api/*, /assets/*, /gateway/*, /console/*
    |
    v
127.0.0.1:18769 -> xtream-vod-unified:8767
    |
    v
external Docker volume xtream-vod-bridge_xtream_vod_index
```

Canonical server-only Compose: `/opt/homedocker/stacks/xtream-vod-unified/compose.yml`; private `production.env` stays mode `0600`. **Never deploy the two retired legacy services against the same volume**.

## Installation, usage and maintenance

| Guide | Purpose |
| --- | --- |
| [Install & recover](docs/install.md) | Prerequisites, verified image restore, source-build limitations, Compose and nginx |
| [User guide](docs/usage.md) | Sign-in, My Workspace, Source Test/Sync, manifest creation and Owner tools |
| [Operations & Dockhand](docs/operations.md) | Health, logs, SHA verification, Internal stack, least-privilege permissions |
| [v0.6 migration](docs/migration-v060.md) | Single-container transition, rollback archive and change-control boundaries |
| [Open issues / known limits](docs/issue-triage-v0.6.md) | Fixed/superseded work versus unresolved security and integration gates |
| [DR runbook](docs/deployment/homedocker-v0.6.md) | Full hardware restore prerequisites, data/key pairing, rollback risks |
| [Acceptance evidence](docs/release/0.6-unified-stable-gates.md) | Tested runtime, known image SHA and deferred full DR test |

## Verified and not verified

**Verified on 2026-10-16:** healthy single container, 0 restarts, correctly pinned image ID, loopback backend, secure HTTPS admin redirect, Safari Owner UI, legacy manifest/existing playback, canonical Compose ownership, Dockhand **Internal** registration, 22 old image tags removed without deleting the production volume.

**Not yet proven:** all personal Xtream/M3U providers end-to-end; full bare-metal restore; equivalence of a clean build to the locally patched stable image; complete DNS-rebinding proof for all outbound transports. Please see the open issues rather than assuming these gates are closed.

## Security

This repository is public; **never commit** `production.env`, Fernet `SOURCE_SECRETS_KEY`, provider URLs with credentials, signed addon URLs, manifest tokens, SQLite files, raw sessions, restic passwords or Docker exports. Read [SECURITY.md](SECURITY.md) before opening ports.

Use only authorized media sources and respect provider terms.
