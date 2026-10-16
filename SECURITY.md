# Security policy — Unified v0.6

Public source repository; **private self-hosted deployment**, not audited for unrestricted public Internet use.

**Never commit or paste:** `.env` / `production.env`, IPTV logins, private M3U URLs, `SOURCE_SECRETS_KEY`, `ADDON_TOKEN`, `ADMIN_TOKEN`, `PLAYBACK_SECRET`, TMDb keys, login cookies/nonces, signed addon or playback URLs, raw request logs, database snapshots, backup exports and Docker inspect dumps.

### Ingress
The existing nginx HTTPS listener :18450 allows only public `/a/*`, `/play/*`, explicitly authenticated `/admin/*`, `/admin-signin/*`, and nginx-internal session subrequest. **Do not forward private backend 18769**. Reject catch-all routes that expose `/`, `/console`, `/gateway/*`, `/api/*`, `/assets/*` outside the protected Admin prefix. Safari gateway remains accessible for login, but authenticated sessions, CSRF Origin, secure SameSite cookies and random nonce remain required. ASUS hairpin NAT may disguise WAN clients as LAN: do not rely on IP ACL alone.

### Runtime
Run UID/GID 10001, dropped capabilities, read-only rootfs, no privilege escalation and private Docker volume. One scheduler owns the writable SQLite index: never start retired legacy and Unified writers simultaneously. Keep provider credentials encrypted under the matching Fernet key and private signed manifests protected. Uvicorn access logs are disabled to avoid logging tokens embedded in URLs; upstream redirects must stay restricted to approved hosts/ports.

### Assurance boundary
2026-10-16 operational checks covered HTTPS auth, nginx default deny, legacy addon and playback, healthy runtime, selected OneDrive/restic read/integrity verification. Not tested: public penetration test, all M3U/Xtream sources, full bare-metal restore, resource abuse/rate limiting, reproducible dependency lock, or equivalence of a fresh GitHub image build to the locally patched production binary. Report issues privately without secrets.
