# Safari on the original DDNS: normal Admin login, no HTTP Basic popup

**Candidate fix. Not yet installed on HomeDocker.** This replaces the
`nginx auth_basic` gateway v2 that Safari repeatedly rejects with
`password mismatch` despite Terminal curl successfully authenticating.

## Why

The user wants exactly:
`https://olivergiangvu.asuscomm.com:18450/admin/`

Do not disable iCloud Private Relay, enable broad Apple IP allowlists, change
ASUS forwarding, trust a local certificate, or move Admin to a .local name.

Safari's native HTTP Basic popup was a poor user experience and appears to
send wrong credentials. The 18450 SSL certificate itself is healthy, and the
public manifest/movie/series paths work.

## New end-to-end login

1. Browser requests `/admin/`. nginx issues an internal
   `auth_request /__xtream_admin_gate_check`, which forwards only the
   `xtream_admin_session` cookie to the loopback Admin server.
2. No valid cookie: redirect (302) to `/admin-signin/`, which serves a
   no-JavaScript HTML login form. No username/password in the URL.
3. User enters **existing Owner Admin password**, NOT the Basic Gateway
   password. Form POST must have expected HTTPS `Origin` and a nonce matching
   a short-lived `Secure; HttpOnly; SameSite=Strict` cookie.
4. The existing salted PBKDF2-SHA256 verifier enforces a global lockout:
   five bad attempts in 10 minutes → 15-minute pause.
5. On successful login, FastAPI creates the existing opaque hashed-server-side
   session, in `Secure; HttpOnly; SameSite=Strict; Path=/admin/` cookie, redirects
   to `/admin/`. The auth_request returns 204 and nginx proxies dashboard/API.
6. The page automatically restores the same session via `/admin/api/auth/session`.
   Existing Admin Lock invalidates it, and password reset revokes all sessions.

**Important:** `ADMIN_TOKEN` previously appeared in chat. This architecture
prevents that bearer token alone from accessing public `/admin/` without a
valid Owner session cookie (nginx gate-check only accepts sessions). Continue
to plan a separate token rotation after Safari login is stable. The exposed
addon/playback HMAC key MUST NOT be rotated as part of this fix.

## Security boundaries

- Public port 18450 keeps all existing TLS and manifest/play routes intact.
- No new exposed Docker port. Admin backend remains 127.0.0.1:18768.
- `/admin-signin/` is deliberately public, but exposes only a login form and
  enforces Origin, nonce, password hash and rate-limiting. Nginx disables
  `auth_basic` **only in the two reviewed admin/form locations**.
- Nginx's `/__xtream_admin_gate_check` location is `internal;`; no public
  caller may request it directly.
- All `/admin/` paths, including static assets, API and admin bearer route,
  require a valid session cookie.
- `ADMIN_TOKEN` remains a private, emergency tool for SSH-local Admin API.
- No IP/source range inference is used for Safari's Private Relay traffic.
- Existing 0.4.2 Owner password and SQLite auth database are reused as-is.
- Credentials are not copied to nginx or a new app.

## Rollout and rollback

1. GitHub CI and CodeQL must be green. Candidate is 0.4.2.1; main bridge
   container remains on current stable release.
2. Backup existing .env, compose.yaml and SQLite via sqlite3 backup API,
   plus v2 nginx config. Keep root-only backup permissions.
3. Checkout the reviewed pinned commit and build
   `homedocker/xtream-vod-bridge:0.4.2.1`. Recreate **only**
   `xtream-vod-admin`, not xtream-vod-bridge. Wait for health to be healthy.
4. Verify local backend:
   - `/gateway/` → 200
   - `/api/auth/gate-check` without cookie → 401
   - `/api/auth/session` → 200
5. Run `sudo python3 scripts/install_safari_form_gateway.py`.
   This requires exact installed Basic v2 marker and validates the public
   DDNS TLS certificate unchanged. The patch adds three locations INSIDE
   the existing nginx 18450 server and edits only the pre-existing /admin/.
   It backs up nginx and self-rolls back on failed tests.
6. Expected: Anonymous `/admin/`, `/admin/api/overview`, assets all return
   302 to `/admin-signin/`; unauthenticated `/admin-signin/` returns 200.
7. Open **the original DDNS URL** in Safari (Private Relay on), sign in with
   existing Owner password. There is NO nginx Basic `gateway` popup.
8. Validate reload of authenticated dashboard, Lock, new private window with
   no session, Edge access, and 3/3 Movie + Series HTTP Range playback.
9. If actual Safari login fails: stop; inspect HTTP statuses and container
   logs (redacted), do not loosen auth, bypass TLS or re-run v1/v2 scripts.

To manually rollback: restore the root-only vhost backup path printed on
success, delete the newly installed
`/etc/nginx/snippets/xtream-admin-form-gateway.conf`, run `nginx -t` and
reload. Recreate admin 0.4.2 from the previous pinned source/image.
Neither SQLite nor legacy streams require rollback after a UI-only change.

## Verification performed

- GitHub Python suite: 84 tests PASS.
- Standalone temporary local nginx 1.26.3 config using actual `auth_request`
  returned 302 for anonymous admin, assets and API, 200 for public login
  form, and 200 for Admin when mocked cookie was authenticated.
- **Not** a real Safari/ASUS Private Relay test; HomeDocker deployment and
  user acceptance are still required.
