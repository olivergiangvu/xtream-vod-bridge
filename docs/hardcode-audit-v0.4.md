# Hard-code & configuration audit — v0.4 candidate

Scope: GitHub `app.py`, `ops.py`, Compose, Dockerfile, proxy snippet,
operational scripts and AIOStreams integration. This is a **static code review
and offline test scope**, not a penetration test or production certification.
Validated live on the prior v0.3.0 baseline: 3/3 Movie and 3/3 Series Range
206 PASS, plus three real Series in AIOStreams. v0.4 runtime needs separate
HomeDocker testing before promotion.

| Item | Current status | Decision |
| --- | --- | --- |
| Hard-coded `IPTV VOD` brand | Replaced by `source_label`, fallback `STREAM_SOURCE_LABEL` and persisted SQLite override | **Resolved** |
| On-demand toggle/timeouts/TTL/variant cap/series quota | Non-secret SQLite runtime overrides; validated allowlist/bounds | **Resolved** |
| Xtream/IMDb/TMDb credentials and API base URLs | Loaded only from `.env`, no default real service credentials | **Keep secrets outside UI** |
| Public domain / nginx TLS prefix | `PUBLIC_BASE_URL` in `.env`, no literal user domain in app; preflight now accepts both root-port `https://host:18450` and `/xtream-vod` prefix | **Fixed preflight hard-code** |
| Internal container ports `8767`, `8768`; host defaults `18767`, `18768` | Internal ports are constants shared between Compose, admin app and probes; host ports Compose-substitutable | **Intentional interface constants** |
| Metadata JIT semaphore of 2 | Fixed in app; prevents burst to unknown Xtream provider | **Security/rate policy, preserve** |
| `get_series_info` max 8 variants | UI override allowed 1–8 | **Configurable within cap** |
| `MAX_ENRICH_PER_SYNC` and `SYNC_HOURS` | Env-configured, Series quota UI capped by MAX | **Preserve bootstrap safeguards** |
| Bootstrap interval min 15m, batch max 50 | Env-configured and checked at startup; UI displays batch read-only, changing worker state requires restart | **Deliberate, defer live scheduler controls** |
| Enrichment throttle `0.25s` | Source constant inside background worker | **Review for dedicated provider limiter** |
| Xtream metadata request `45s`, connect `10s` | Hard-coded HTTPX settings; JIT request has its own 2–15s total deadline | **Potential future config / adaptive timeout** |
| TMDb lookup timeout `12s`, crosswalk cache 7d | Fixed TTL/timeouts, both external I/O | **Future tuning if metrics justify** |
| Last response stream cap 20 | Fixed result safety bound | **Preserve for predictable client performance** |
| Playback link lifespan | Configured by `PLAY_URL_HOURS`, default 48h | **Already configurable** |
| Redirect public-ip HTTP downgrade | Explicit opt-in `XTREAM_HTTP_REDIRECT_MODE`, public IPv4:80 only; upstream leg unencrypted | **Security review pending; do not loosen** |
| Private admin access | Separate loopback container 18768, SSH tunnel; Bearer admin token for all JSON APIs | **New v0.4 security boundary; must verify deploy** |
| Public `/health` | Exposes aggregate indexing counts and JIT metrics but not credentials | **Info-leak evaluation pending** |
| Provider list transient missing entries | Single nonempty listing can still prune absent Series (issue #18) | **Open; do not silently change production deletion policy** |
| Full Anime ID resolution | Only existing provider IMDb/TMDb/AniList/Kitsu/MAL exact tags; no general crosswalk | **Open issue #14** |
| UI/editing `.env` | Forbidden by design; avoids arbitrary edit of provider secrets/ports in Web UI | **Out of scope for v0.4** |
| Existing image version `0.3.0` | Stable branch pinned; candidate image `0.4.0` only after CI | **Two-phase rollout** |

## Follow-up work recommended

1. **Before stable v0.4 promotion:** verify admin is reachable only via SSH,
   unauthorized requests return 401, UI source-name change persists and Movie/
   Series playback is unaffected.
2. **Provider resilience:** implement grace-based Series pruning as tracked in
   issue #18, with rollback tests.
3. **Rate policy:** consolidate scheduled detail enrichment and JIT under a
   shared configurable provider request guard; account for 429 Retry-After.
4. **Observability:** add percentile latency and exact pipeline-stage timing
   without leaking URLs, credentials, individual watch history or token IDs.
5. **Build hardening:** pin base image digest/dependency versions; add regular
   vulnerability scanning before Internet-facing production promotion.

**Audit rule:** numeric constants for protocol security, signature format,
resource limits and internal port contracts are not automatically defects.
Treat only *environment-specific assumptions and repeated magic literals* as
hard-code remediation targets.
