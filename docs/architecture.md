# Architecture and responsibilities

```text
Authenticated Xtream provider
  ├─ get_vod_streams -> movies inventory
  ├─ get_vod_info -> IMDb/TMDb keys, container extension
  ├─ get_series -> TV inventory
  └─ get_series_info -> IDs + episode list
         |
         v
    Xtream VOD Bridge (one Docker container)
    SQLite index + scheduled enrichment
    optional TMDb crosswalk
    Stremio /manifest.json, /stream/{movie,series}/...json
    signed /play HTTP relay
         |
         v
    AIOStreams (Custom Stremio addon)
    Addon-first sorting / provider priority
         |
         v
    Remux / Trellis / Jellyfin-compatible clients
```

`Xtream VOD Bridge` is an upstream stream **supplier**, not a replacement for AIOStreams metadata or playback clients. ID matching is strict. Library sync takes place independently from search, and search can return empty while enrichment is incomplete.

### Source ranking

Addon returns `Xtream VOD Bridge` as source name. **AIOStreams is responsible for ranking**; the bridge cannot guarantee pinning in a client that overrides sorting or filters HTTP streams. Put bridge first in addon order and set Addon as the primary sorting criterion separately for Movies/Series if configured.

### Isolation

Compose binds `127.0.0.1:18767 -> container:8767`, so it does not open another LAN/WAN listener. Nginx on HomeDocker owns HTTPS. SQLite uses `xtream_vod_index` and is the only persistent volume. `compose up -d --build` affects only the new stack.

### Operational limitations

Current playback relay is a byte proxy. Some upstream HLS or redirects require specialized handling. Signed URLs expire, so older cached AIOStreams results may fail until re-fetched. Bridge only supports one provider in this version.
