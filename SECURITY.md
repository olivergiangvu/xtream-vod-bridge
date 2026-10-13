# Security policy

This repository is a public-source **prototype**, not an audited streaming proxy. No real provider credentials, real playlist data, or signed streaming URLs are distributed.

## Never put in GitHub

- Xtream endpoint with embedded user/password or session credentials
- `.env`, `ADDON_TOKEN`, `ADMIN_TOKEN`, `PLAYBACK_SECRET`, TMDb keys
- Real provider responses that contain account details or signed playback URLs
- Full HTTP logs, Docker inspect output, database snapshots or backups

## Reporting

Raise security issues privately with the repository owner. Do not paste sensitive URL query strings in issues or PRs. Rotate affected keys immediately if accidentally exposed.

## Runtime controls

- Bind the service to `127.0.0.1` on HomeDocker and use an HTTPS reverse proxy.
- Protect addon and admin endpoints with independent random tokens.
- Stream relay URLs are HMAC-signed and time-limited; relay does not transcode.
- Disable Uvicorn access logs (they would expose the addon token and signed URL); suppress HTTPX request logs (they could expose Xtream query-string credentials).
- Limit Docker capabilities, run as non-root, do not mount Docker socket.
- Store `.env` with restrictive filesystem permissions, in encrypted DR snapshots only.
- Observe permitted content usage and provider connection limits.

## Known pre-production gaps

Unapproved provider redirects are rejected, and approved CDN redirects are host/port-restricted (mocked tests only). Remaining gaps: rate abuse of a publicly reachable streaming endpoint, DNS/egress policy for approved provider domains, hostile playlist contents, real provider integration tests, HLS playlist rewriting, and reproducible dependency lock. Do not publish as an unrestricted Internet service before addressing these limitations.

## Private admin console (v0.4 pilot)
The admin UI runs in a **separate** Docker service on `127.0.0.1:18768`, not behind public nginx on 18450. Connect using an SSH tunnel. Do not forward admin port on the router, proxy admin into public nginx, or expose `0.0.0.0:18768`.
API requests require `Authorization: Bearer <ADMIN_TOKEN>`; the UI never stores it in localStorage, cookies or the URL (memory only). It is invalidated on page refresh.
The UI changes only allowlisted **non-secret** runtime settings saved to the existing SQLite backup volume. Xtream credentials, API keys, CDN redirects, host ports and playback HMAC secrets stay in protected `.env`.
Diagnostic events are intentionally low-fidelity: event type, kind, status, response duration and number of streams, not filenames, media IDs, IP addresses, exception messages, provider URLs or credentials. They are bounded to 2000 rows. SQLite can contain user-specific library/watchable content; continue treating backups as private.
