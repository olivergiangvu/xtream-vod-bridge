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

No tested protections against malicious/untrusted provider redirects, rate abuse of a publicly reachable streaming endpoint, or hostile playlist contents. No provider integration tests or reproducible dependency lock. Do not publish as an unrestricted Internet service before addressing these limitations.
