# Production readiness checklist

## Before GitHub publication

- [x] Separate public-source repository layout with README, CI, security policy, tests
- [x] `.env` ignored by Git and build context
- [x] Suppress Uvicorn access logs (addon tokens and signed links)
- [x] Suppress HTTPX INFO logs (Xtream query-parameter credentials)
- [x] Sanitize exception text exposed via `/health`
- [ ] Run GitHub Actions CI on first push (cannot be verified offline)
- [ ] Lock application dependencies and base-image digest for reproducible DR
- [ ] Decide public/private GHCR image publication and digest pinning after testing

## Before HomeDocker deployment

- [ ] Verify port `18767` and `/xtream-vod/` nginx location are free
- [ ] Verify HTTPS, DNS and reverse proxy configuration
- [ ] Confirm provider is authorized, test provider API and session constraints
- [ ] Install separate randomly-generated addon/admin/playback secrets locally
- [ ] Use first local test with `MOVIES_ONLY=1` if TV endpoint quality is uncertain
- [ ] Confirm metadata fields in `get_vod_info` and `get_series_info`
- [ ] Enforce conservative enrichment rate and avoid provider bans
- [ ] Test IMDb/TMDb mapping and episode SxxExx matching
- [ ] Test GET, HEAD, Range/206, redirects, provider format variants
- [ ] Harden outbound redirect policy and provider-bound traffic
- [ ] Add rate limits and verify client IP filtering / network exposure
- [ ] Check AIOStreams addon sorting and filters; maintain fallbacks
- [ ] Integrate volume + `.env` into encrypted Backrest/restic/OneDrive snapshot
- [ ] Test restore and rollback without changing existing stacks
- [ ] Register GitHub release mapping in existing Version Center (monitor-only)

## Release gate

Do not create a stable GitHub release or deploy automatically from CI until the integration and restore checks above have passed. GitHub is source control, not a source of production truth until validated.
