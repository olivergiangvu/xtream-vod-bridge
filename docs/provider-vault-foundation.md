# v0.5 Provider Vault — Phase 1 foundation

Status: **staged only; not yet connected to playback**. This branch adds encrypted storage for Xtream provider profiles plus provider-scoped database tables. Existing HomeDocker legacy-provider playback, environment configuration and SQLite tables remain unchanged.

The admin console adds a Providers section with name, HTTPS base URL, username, write-only password and priority. Every endpoint requires the existing ADMIN_TOKEN. List/read APIs show base URL, username, label and password_configured, but never an existing password or ciphertext. Profiles cannot yet be activated for streams, and the UI explicitly labels them "Staged · not streaming".

Storage uses Fernet authenticated encryption with a separately mounted encryption key at /run/secrets/xtream-provider.key. The private key must be 44-character URL-safe base64 representing 32 random bytes, owned by container user ID 10001 and readable only by that user. Provision it from a Linux SSH terminal without printing it. Back it up in the existing encrypted restic disaster-recovery plan independently of the SQLite database. Never save the key or plaintext provider credentials in GitHub, logs, browser local storage, or the SQLite database.

## Current API (admin only)

- GET /api/providers: safe profile list and key status
- POST /api/providers: create staged encrypted profile
- PATCH /api/providers/{id}: update URL, username, label, priority or replace password; omission keeps the existing password
- DELETE /api/providers/{id}: remove staged profile, preserving legacy index

The stage-one URL validator accepts HTTPS DNS hostnames without path/query/userinfo, and ports 443 or 8443. It does not perform outbound requests and **does not establish provider reachability**. Support for alternate ports/HTTP providers requires a later explicit provider-aware security policy, never a generic SSRF-prone URL fetch.

## Mandatory phase-two gates before HomeDocker deployment

1. Import or migrate existing .env primary provider non-destructively with an explicit rollback path.
2. Connect multiple providers to streaming; namespace item IDs and episode IDs by provider, and include provider ID in playback URL HMAC signatures.
3. Preserve v2 legacy URL compatibility only for the original provider until original expiration.
4. Add per-provider sync, on-demand cache, rate controls, CDN redirect guard, and failure isolation.
5. Test colliding numeric stream IDs, two providers with the same IMDb ID, 4K/1080p quality variants, password rotations and replaying signatures across providers.
6. Authenticate the admin UI via verified HTTPS on LAN before entering provider passwords from another device. **Do not expose the loopback HTTP port directly to LAN.**
7. Back up the real SQLite, .env and separate encryption key via DR, then validate restore on a staging copy. No docker compose down -v.

See issue #23 and pull requests #21/#24 for the v0.4 baseline, GUI and LAN TLS prerequisite. Do not activate new providers until all gates pass.
