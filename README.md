# Xtream VOD Bridge v0.4.0 — HomeDocker

**Status:** v0.3.0 is a functionally validated HomeDocker stable baseline (Movie/Series Range 206 and AIOStreams episode tests PASS); it is **not an independent security-certified public production release**. v0.4.0 remains a separate admin UI candidate pending a controlled HomeDocker pilot.

**Goal:** Turn an **authorized** Xtream Codes IPTV provider's VOD movies and TV episodes into standard Stremio addon `stream` results, then use AIOStreams **Custom Addon + Addon-first sorting** to put them above other sources. Works without editing AIOStreams/AIOMetadata, Remux, or Trellis.

## Architecture

```text
Xtream provider ──(get_vod_streams/get_vod_info; get_series/get_series_info)──┐
                                                                            │
TMDb API (optional but strongly recommended for IMDb↔TMDb mapping)───────────┤
                                                                            ▼
                              Xtream VOD Bridge (SQLite index, 6h sync)
                                  |                    |
                       Stremio manifest + streams   signed /play relay
                                  |                    |
                              AIOStreams ──────────────┤
                                  |                    |
                        Remux / Trellis / other clients
```

**No Live TV, EPG, channel lists, catalog browsing, or metadata replacement.** It only adds VOD sources for items that AIOStreams already searches. Movie IDs `tt1234567` / `tmdb:movie:603`, series IDs `tt1234567:1:2` / `tmdb:tv:1399:1:2`, and directly tagged `kitsu:`, `anilist:`, `mal:` movie/series IDs are supported. Anime can be either a movie or a TV series. **Anime-ID requests only work when the provider supplies corresponding IDs**; names alone do not create a reliable crosswalk. The stream URL is signed and Xtream username/password remain server-side.

### What Xtream metadata must contain

The playlist listing endpoints usually contain the title and numeric `stream_id`, but often **no IMDb/TMDb ID**. The bridge therefore requests details gradually and caches mappings in SQLite. `get_vod_info` / `get_series_info` need to contain `imdb_id` or `tmdb_id` for deterministic matching. TMDb API key enables translation in either direction. Title-only fuzzy matching is deliberately **not** enabled in this release because it can play the wrong film or wrong episode.

## v0.4.0 candidate: private admin console, Strand-style source label, diagnostics

**This is a release candidate, not the v0.3.0 stable baseline.** The tested
HomeDocker functional baseline is pinned at
[`stable/v0.3.0`](https://github.com/olivergiangvu/xtream-vod-bridge/tree/stable/v0.3.0)
(commit `2b297cce`). Do not deploy v0.4 until CI/CodeQL pass.

This release adds a **separate admin web service** at host loopback
`127.0.0.1:18768`, accessible via an SSH tunnel, never via public nginx.
It uses the existing `ADMIN_TOKEN` as bearer auth without browser storage.
It can rename the IPTV source (like Strand's provider name, e.g. `Meteor`),
and edit a strictly validated allowlist of **non-secret** JIT controls via
the existing SQLite volume, applied live on new stream requests. New events
record only status, request category, duration and stream count; no provider
URL, token, IP or media ID. Credentials and CDN security remain in protected
`.env`.

Read [admin deployment and SSH tunnel guide](docs/admin-console.md) and the
[hard-code audit](docs/hardcode-audit-v0.4.md). The actual baseline must be
verified again with three Movie, three Series Range 206 requests and a UI
rename test before promoting v0.4.

## v0.3.0: demand-first Series resolver (opt-in)

Instead of waiting days for full episode pre-indexing, an incoming Stremio `stream/series/tt...:season:episode` request can now hydrate a **cold Series** directly through Xtream `get_series_info(series_id)`. First read and write use the **existing persistent SQLite** episode tables. On the next query, the same episode is served from SQLite, including after process restarts.

Turn on only for a controlled HomeDocker pilot:

```dotenv
MOVIES_ONLY=0
SERIES_ON_DEMAND=1
SERIES_BOOTSTRAP_BATCH=0
SERIES_JIT_TIMEOUT_SECONDS=8
SERIES_JIT_TTL_HOURS=6
SERIES_JIT_RETRY_SECONDS=120
SERIES_JIT_MAX_VARIANTS=8
```

An already-hydrated Series returns immediately. For a cold Series, up to eight matching provider Series variants are considered (IMDb/TMDb/AniList/Kitsu exact-ID matches from the existing inventory). Fetches are bounded to **two concurrent** detail requests, use a separate per-Series single-flight lock, and have a **whole-request 8-second deadline**. Successful variants are returned even if other variants time out, preserving 4K and 1080p alternatives. Failed requests are locally cooled down for 120 seconds. Requests missing an episode after a successful fetch are negatively cached for 6 hours; newly released episodes may therefore take up to that period to become visible.

The request-time resolver never transmits Xtream username/password to AIOStreams. Signed HTTPS playback URLs, Range/206 relay, source names, mpv filename metadata, Movie VOD sorting and current databases remain unchanged. New nested Xtream episode shapes and season 0 are parsed by explicit episode numbers or SxxEyy filename patterns; missing ambiguous episode numbers are **not guessed**, to protect tracking accuracy.

The index/list scheduler is retained, but its 25/30-minute Series bootstrap is no longer required for playback. Set `SERIES_BOOTSTRAP_BATCH=0` to stop full-library sweeping during v0.3. Use `/health.series_on_demand` and `/health.jit` for request counts (cache hits, misses, fetch, timeouts, negative cache). These counters are per process; the SQLite episode cache persists.

**Limitations:** These are server-side implementation and offline test results, not live provider latency measurements. Full cross-provider Anime ID conversion, smart newly-released-episode TTL, provider cooldown based on Retry-After, and provider list grace-period pruning are separate tasks. The on-demand feature defaults **off**, so a binary-only upgrade preserves v0.2.2 behavior. Rollback simply disables `SERIES_ON_DEMAND` and recreates only the bridge. Never use `docker compose down -v`.

## v0.2.2: Series episode bootstrap without Movie starvation

A provider may expose thousands of Series already tagged with IMDb/TMDb IDs, but none of their episode streams are available until `get_series_info` has been called. Previously, `MAX_ENRICH_PER_SYNC` was one shared ordered queue; with ~29,000 Movies and ~8,000 Series, Movies consumed every slot and `episodes=0` persisted.

The normal `SYNC_HOURS` index refresh now gives Series a reserved detail quota **inside** the existing `MAX_ENRICH_PER_SYNC` provider budget. Example: `MAX_ENRICH_PER_SYNC=50`, `SERIES_ENRICH_PER_SYNC=40` means up to 40 Series + 10 Movies per regular sync while a Series backlog exists; once the Series queue is empty, all 50 slots can go to Movies. No extra API burst occurs just from upgrading.

An **optional** sequential Series bootstrap worker runs separately when `MOVIES_ONLY=0` and `SERIES_BOOTSTRAP_BATCH>0`. Example:
```dotenv
MAX_ENRICH_PER_SYNC=50
SERIES_ENRICH_PER_SYNC=40
SERIES_BOOTSTRAP_BATCH=25
SERIES_BOOTSTRAP_INTERVAL_MINUTES=30
MOVIES_ONLY=0
```
This adds at most 25 Series detail calls every 30 minutes, **in addition to** the ordinary 6-hour batch, with a minimum 15-minute interval and a hard maximum of 50 detail calls per batch. It waits for the startup listing refresh and uses the same in-process lock as normal sync to prevent overlapping workloads. Each successful detail updates SQLite `checked_at`, so a restart resumes rather than re-fetching completed Series. Failures are logged by error type without leaking URLs/passwords; invalid Series details remain unindexed until retried. Provider rate limits vary—start with conservative values and observe before increasing.

`/health` adds `series_progress.details_checked`, `with_episodes`, `pending_enrichment`, `batch_size`, `batch_interval_minutes`, last bootstrap status and per-kind last sync counts. `details_checked` includes failed detail attempts marked for deferred retry, so `with_episodes` is the more useful episode readiness metric. `series.total` is only the number of Series in the Xtream listing; it is not proof that all episodes are indexed. `series.mapped` counts provider-supplied IMDb/TMDb tags, not verified matches to every episode.

No database schema changes, stream URLs, codecs, nginx, sorting or movie playback behavior change in v0.2.2. To switch off the extra worker, set `SERIES_BOOTSTRAP_BATCH=0` and recreate this container. `MOVIES_ONLY=1` suppresses the Series worker and Series listing/enrichment. No `down -v`.

## v0.2.1: preserve Xtream source resolution tags

v0.2.0 cleaned provider prefixes such as `4K Zootopia 2 (2025)` out of the player filename but also removed the distinction between 4K and other versions in AIOStreams. v0.2.1 **preserves resolution cues in the Stremio stream name, title, description, behaviorHints.filename and signed playback basename**. Example for two otherwise equivalent provider entries:

- `4K Zootopia 2 (2025)` → `IPTV VOD 2160p`, filename `Zootopia.2.2025.2160p.mkv`
- `Zootopia 2 (2025)` → `IPTV VOD`, filename `Zootopia.2.2025.mkv`

This is a **provider-title-derived hint**, not a measured stream resolution or codec verification. Recognized 4K/UHD, 2160p, 1080p/FHD, 720p, 480p, and explicit HD/SD labels. Bare HD/SD retain their ambiguous labels rather than assuming 720p/480p. For series, episode-specific labels take priority over series title. Unknown quality stays unlabeled; it must not be assumed to be 1080p. The IMDb/TMDb ID path, URL signatures and existing index are unchanged; no SQLite migration or provider resync is required.

## v0.2.0: metadata identity survives into mpv/Jellyfin-compatible clients

Stremio `stream.title`, `stream.description` and `behaviorHints.filename` contain a readable title and episode code, while the **actual playback URL ends in the same clean filename** and carries IMDb/TMDb (or provider-supplied AniList/Kitsu/MAL) ID as a signed intermediate path component:

```text
https://your-domain:18450/play/movie/<stream_id>/tt1234567/<expiry>/<signature>/Zootopia.2.2025.mkv
https://your-domain:18450/play/series/<episode_stream_id>/tt7654321/<expiry>/<signature>/Example.Show.S01E02.mkv
```

The filenames are derived from **actual Xtream metadata** rather than guessed content; no provider credentials or `?exp=&sig=` query string is exposed at the tail of the filename. This helps consumers such as mpv's `filename` property, whose value otherwise may look like `28369.mkv?exp=...`. However, different metadata/tracking plugins use different heuristics; Stremio fields or human-readable URLs **do not guarantee** every client automatically obtains a Trakt target. A downstream integration may need to read the signed URL's ID path or the original Stremio content ID.

The old query-signed URLs remain valid until expiry for already-playing sessions, so upgrade does not immediately invalidate existing sessions. The SQLite migration only **adds nullable anime identifier columns**, retaining movie/episode indexes. No fuzzy title-based ID assignment is done.

### Rotating HTTP CDN IPs without hardcoding

`XTREAM_HTTP_REDIRECT_MODE=allowlist` (default) keeps the strict v0.1.3 behavior and supports the existing explicit `XTREAM_HTTP_REDIRECT_ALLOWED_IPS`. Providers with frequently rotating public-IP CDN redirects can use **explicit opt-in** `XTREAM_HTTP_REDIRECT_MODE=public-ip`, which accepts `HTTP:80` redirects **only to globally routable public IPv4 literals**. It rejects private, loopback, link-local, IPv6, hostname, userinfo, unexpected ports and non-HTTP schemes. This avoids tracking individual CDN IPs, but broadens trust to all public IPv4 destinations on port 80 if the provider sends a redirect: **upstream video and its CDN URL tokens are unencrypted**. Use only if you trust the source of redirects; HTTPS CDN is preferable. The public player-to-nginx leg remains HTTPS.

### Series and anime rollout

Keep `MOVIES_ONLY=1` initially, take a consistent backup of the SQLite named volume and `.env`, then set `MOVIES_ONLY=0` to begin indexing `get_series` and `get_series_info`. Episodes are matched strictly by season/episode, including season 0 specials. Some Xtream panels expose episodes as a season dictionary and others as a flat episode list; both are accepted. The existing `MAX_ENRICH_PER_SYNC` batch limit still applies to avoid provider rate bans; a large initial series library needs repeated refresh batches and its coverage should be measured rather than assumed. Names without IDs will not be matched. Legacy Stremio clients may use anime-specific IDs not available in Xtream; AniList/Kitsu/MAL **cross-provider lookup is not implemented**. Do not enable source priority for all clients until actual episode playback and watch tracking are tested.

## Files

- `app.py` — service, indexing, metadata matching, and byte-forwarding playback relay
- `compose.yaml` — separate Docker stack, single new container, named persistent volume, localhost-only port
- `.env.example` — configuration skeleton; copy to `.env` and add credentials **locally**
- `nginx-snippet.conf` — one location block added to an existing host nginx HTTPS server
- `tests/test_bridge.py` — isolated unit tests using fake IDs, no real provider needed

## Deployment (SSH to Linux HomeDocker)

1. Copy the extracted directory to the Linux host (for instance `/opt/xtream-vod-bridge`) using your preferred SSH/SCP workflow. Ensure only trusted admins can read the directory.
2. SSH, then:

```bash
cd /opt/xtream-vod-bridge
cp .env.example .env
chmod 600 .env
openssl rand -hex 32   # paste as ADDON_TOKEN
openssl rand -hex 32   # paste as ADMIN_TOKEN (different)
openssl rand -hex 32   # paste as PLAYBACK_SECRET (different)
nano .env
```

Set:
- `XTREAM_BASE_URL`, `XTREAM_USERNAME`, `XTREAM_PASSWORD` to your **authorized** provider credentials.
- `PUBLIC_BASE_URL=https://YOUR_WORKING_HTTPS_DOMAIN/xtream-vod` (not localhost, and avoid a trailing slash).
- `TMDB_API_KEY` if the provider uses TMDb identifiers or for IMDb↔TMDb conversion.
- `ADDON_TOKEN`, `ADMIN_TOKEN`, `PLAYBACK_SECRET`: **different**, random, >=32 characters.
- `MAX_ENRICH_PER_SYNC`: number of detail records queried in each background sync; defaults to 250 per 6h to protect the provider from a large burst. Initial warm-up of huge catalogs can take many syncs. Temporarily increasing this can speed up initial indexing, but requires verifying your provider's API limits.

3. Start **only the new service**:

```bash
sudo docker compose up -d --build
sudo docker compose ps
curl -fsS http://127.0.0.1:18767/health
sudo docker compose logs --tail=50 xtream-vod-bridge
```

4. Backup the existing host nginx config. Copy the `location` block from `nginx-snippet.conf` **inside** your existing HTTPS `server {}` block for the same domain. Check for a pre-existing `/xtream-vod/` location first. Adjust the port only if `18767` is already taken. Do not blindly replace nginx config files.

```bash
sudo nginx -t && sudo systemctl reload nginx
```

5. Test the **exact** public URL (the below is only a path example; put your own domain and random token):

```text
https://YOUR_WORKING_HTTPS_DOMAIN/xtream-vod/a/YOUR_ADDON_TOKEN/manifest.json
```

It must return JSON identifying `Xtream VOD Bridge`, `resources:["stream"]`, and supported movie/series types. Your clients should access this same HTTPS hostname from their own network; local success does not prove public connectivity.

6. In the existing **AIOStreams** config → `Addons` → `Custom Addon`, add the public manifest URL. Set the addon name exactly to **Xtream VOD Bridge** and, preferably, limit resources to `stream` if that option exists. **Do not delete or replace any installed addons.**

7. In AIOStreams `Sorting`:
   - Reorder the installed addons so **Xtream VOD Bridge is first**.
   - Insert **Addon** as the **first** primary sort criterion for `Global`, and explicitly for `Movies` and `Series` if they already have their own sort criteria.
   - Keep `Resolution`, `Quality`, `Language`, `Cached`, etc., **after** `Addon`. If `Cached` remains first it can split the result list and the IPTV result may not be on top. Prefer not to treat HTTP IPTV as debrid cached.
   - Keep other addons as fallbacks. Verify filters such as `Cached-only`, `HTTP excluded`, `Title matching`, `Episode matching`, and quality thresholds do not accidentally discard IPTV VOD; change them **only for this addon** when the UI supports per-addon settings.

**Expected:** If the movie is indexed, its IPTV result appears before other addons. If no mapped IPTV VOD exists, only your existing streams appear; other addons continue operating.

## Tests and troubleshooting

```bash
# Before deploying (requires Python + packages from requirements.txt):
python -m unittest discover -s tests -v

# Health stats: item counts, items with metadata IDs, episode count, last sync:
curl -sS http://127.0.0.1:18767/health

# Force another batch of enrichment (from Linux only; use your own admin token):
curl -sS -X POST http://127.0.0.1:18767/admin/refresh \
  -H 'X-Admin-Token: REPLACE_WITH_ADMIN_TOKEN'

# Query movie (substitute token/IMDb ID; show only a demo path):
curl -sS "http://127.0.0.1:18767/a/YOUR_ADDON_TOKEN/stream/movie/tt0133093.json"

# Query TV episode:
curl -sS "http://127.0.0.1:18767/a/YOUR_ADDON_TOKEN/stream/series/tt0944947:1:1.json"
```

If you get `{"streams":[]}`: verify (1) full initial index has warmed up, (2) `health.index.movie.mapped` (or `series.mapped`) is nonzero, (3) IPTV detail endpoints really expose IMDb/TMDb IDs, (4) TMDb key if only TMDb IDs exist, (5) exact season/episode mapping, and (6) AIOStreams filters. Empty results do **not** mean the provider has no VOD unless the index is complete.

## Safety, operation, backup, and rollback

- **Deployment state:** a **prototype**, packaged/tested locally without real Xtream credentials, upstream network, or AIOStreams end-to-end integration. Test with one movie and one TV episode before production.
- **Default: HTTPS→HTTP remains blocked.** Some legitimate IPTV Xtream panels respond with an HTTPS `302` to a **plain HTTP CDN IP**. For an explicitly verified, authorized provider only, `XTREAM_HTTP_REDIRECT_ALLOWED_IPS` permits an exact **public IPv4** destination on default HTTP port 80. This is a separate opt-in from `XTREAM_REDIRECT_ALLOWED_HOSTS` (HTTPS CDN hostnames). No private/loopback/link-local IPs, DNS hostnames, wildcards, unexpected ports or arbitrary redirect targets are permitted for HTTP downgrade. The opt-in is empty by default.
- **Security trade-off:** public client → nginx remains HTTPS and signed; however **HomeDocker → approved CDN IP uses unencrypted HTTP**, exposing media bytes and potentially stream URL tokens to networks along that hop. Never assume the redirect IP belongs to the provider without verification, and never insert your IPTV username/password into the allowlist. If this risk is unacceptable, ask the provider for an HTTPS CDN endpoint instead.
- An empty provider list response will preserve the existing index as an anti-data-loss safeguard. To intentionally clear an index, use an explicit maintenance procedure.
- Provider credentials are held in `.env` in the Docker environment. Only host administrators with Docker permissions should access it; a person with Docker socket access can inspect environment variables. Do not publish the `.env` file or add it to Git.
- An Xtream subscription may limit simultaneous connections or bind an IP; when using the byte-forwarding relay, the provider sees **HomeDocker's public egress IP**, not each remote device. Verify provider terms, rights, max sessions, and geographic limits.
- Playback is **relayed through HomeDocker** (not transcoded); internet traffic and bandwidth flow through the home connection and Docker container. `Range`/`206` responses pass through. Some provider-specific redirects (CDN hosts must be allowlisted), HLS playlists, headers, token-based DRM, and exotic formats may require additional handling. HLS segment URL rewriting is **not** implemented in v0.1.2.
- Use only with an IPTV provider and content you are authorized to access. Never proxy arbitrary target URLs supplied by users.
- Health metrics show catalog counts, not credentials. Admin refresh requires a separate `X-Admin-Token`. Stream links use short-lived HMAC signatures. `access_log off` in the nginx location prevents signed URLs entering normal access logs. Avoid exposing debug logs containing secrets.
- Backup/DR: include the named Docker volume `xtream_vod_index`, compose definition, nginx path config, and **`.env`/secrets** in your existing encrypted DR backup. SQLite hot copying is not consistent by default: quiesce the container or use SQLite backup API when staging. This is a **new app-specific backup policy**, not a change to Backrest/Restic/rclone.
- Version Center: this local image is tagged `homedocker/xtream-vod-bridge:0.3.0`. It is **not** linked to a public registry release feed. The current stack can be discovered, but upstream-version comparison needs an explicit custom source if/when the project is published. Keep monitor-only.
- Rollback: disable the Custom Addon in AIOStreams, remove the nginx location block, `sudo nginx -t && sudo systemctl reload nginx`, then `sudo docker compose down`. **Never run `down -v`** if you want to retain the indexed catalog.
- Upgrade base image: this prototype uses `python:3.12-slim`; pin an exact verified image digest and dependency lock in production before strict reproducible DR. `requirements.txt` has bounded major versions, not a fully locked build.

## Follow-up v0.2 hardening ideas

- Multi-provider failover/priority per provider, not just one account.
- Provider-list deltas/parallel throttled enrichment and progress UI for 10k+ items.
- Title+year fallback with human-approval queue, not silent fuzzy mapping.
- Per-title playback checks, optional direct-play mode versus secure relay.
- HLS manifest/segment rewriting if the provider uses `.m3u8`, plus more player compatibility tests.
- Image digests, migration-based schema versioning, `file`-based secrets, and automated end-to-end mocks.


## GitHub repository workflow

Repository: [`olivergiangvu/xtream-vod-bridge`](https://github.com/olivergiangvu/xtream-vod-bridge) (public source, **pre-production**). Public visibility does not make the streaming service safe to expose unauthenticated. This project does not ship provider playlists, credentials, stream URLs, or database exports. No open-source license has been granted yet; public visibility alone does not convey reuse rights. Default branch is `main`; require passing CI on pull requests where branch-protection features are available.

- Develop on a short-lived branch and submit a pull request; avoid direct edits on `main`.
- GitHub Actions runs syntax compilation and offline unit + mocked API/relay integration tests; it does **not** call the IPTV provider, perform deployment, or pull secrets from HomeDocker.
- `.env` and all provider credentials must remain only on HomeDocker, never inside GitHub, Actions logs or issue comments.
- No automatic CD and no image publication in this prototype. Release tags and GitHub Container Registry should be added after integration tests and image reproducibility work.
- Production checklist: see `docs/production-checklist.md`.

### Local smoke check after deployment (no credentials displayed)

The read-only `scripts/smoke_test.py` reads `ADDON_TOKEN` from local `.env` if
necessary, then checks `/health`, `/manifest.json`, and optional mapped streams
through `127.0.0.1:18767`. It never prints the manifest token or signed URLs.

```bash
python scripts/smoke_test.py --movie tt0133093 --episode tt7654321:1:2
```

Replace the test IDs with **actual matches from your authorized IPTV catalog**.
This script validates index and stream URL contracts, not playback-byte delivery.
For media playback, perform a separate controlled HEAD/Range test on a signed
URL without pasting that URL into GitHub issues, CI logs, or shell history.

## Code security / deployment gating

- Dependabot checks Python, Docker base images, and GitHub Actions **weekly**,
  and raises pull requests for review. There is no auto-merge, release, or CD.
- CodeQL scans Python and GitHub Actions on pushes, pull requests, and weekly.
  Security alerts and proposed dependency changes are not proof of production
  readiness. Review PR diffs and run tests before merging.
- Before touching the existing HomeDocker deployment, run the **read-only**
  [HomeDocker SSH preflight](docs/homedocker-preflight.md). It checks for port
  conflicts without disclosing IPTV secrets or changing system configuration.
