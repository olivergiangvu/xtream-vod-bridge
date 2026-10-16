# Architecture — Xtream VOD Unified v0.6.0

See [README](../README.md), [installation](install.md), [usage](usage.md), [DR](deployment/homedocker-v0.6.md) and [ADR-0005](adr/0005-unified-xtream-one-container.md).

```text
Xtream/M3U HTTPS sources (authorized)
       |
       v
Unified FastAPI/Uvicorn :8767, host loopback :18769
  ├── Owner/User Admin UI, sessions/RBAC, encrypted personal source storage
  ├── Legacy/addon & personal Stremio manifest APIs, signed play relay
  ├── SQLite index and single background scheduler
  └── personal source/manifest scoping with exact identity matching
       |
       v
host nginx HTTPS :18450
  ├── /admin/* (session-gated) and /admin-signin/* (login)
  ├── /a/* and /play/* (public signed addon traffic)
  └── default deny unrelated backend paths
       |
       v
AIOStreams (addon aggregation/order) -> Remux / Trellis / player
```

### Boundaries

- AIOStreams and AIOMetadata, not this bridge, own search/ranking/metadata presentation. Bridge cannot guarantee playback-client sorting/priority.
- Personal sources are per-user and distinct from earlier proposed system-wide provider registry (#23). The legacy global provider may still exist.
- `/a` and `/play` URLs are private bearer/signature URLs; protect them. Signed URLs expire.
- SQLite persists in external Docker volume `xtream-vod-bridge_xtream_vod_index` and **requires matching Fernet `SOURCE_SECRETS_KEY`** for decrypting personal credentials.
- No Live TV, EPG, transcoding or automatic fuzzy media identity merge.
- Real upstream DNS rebinding/TOCTOU, personal new-provider end-to-end playback and full hardware DR are open verification gates (see [issue register](issue-triage-v0.6.md)).
