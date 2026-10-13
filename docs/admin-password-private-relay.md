# v0.4.2 Candidate — Friendly Admin password and Safari with Private Relay intact

**Not deployed to HomeDocker yet.** The currently tested v0.4.1 Web Admin
and public Xtream VOD Bridge should remain the rollback baseline.

## Normal authentication

- User chooses an **Admin password** (at least 14 characters) ONCE via a
  protected, interactive SSH command on Linux. Never send it in chat, logs,
  Docker Compose, GitHub or the browser URL.
- A salted PBKDF2-SHA256 password hash (600,000 iterations) is saved in
  the existing private SQLite volume; the plaintext password is **not** saved.
- On successful HTTPS login the backend issues a random opaque browser
  session cookie with `HttpOnly`, `Secure`, `SameSite=Strict`,
  `Path=/admin/` and 12-hour expiry. Only its SHA-256 digest is stored
  in SQLite. Page refresh restores the login while it is valid; clicking
  **Lock** revokes it. Password rotation revokes all sessions.
- All cookie-authenticated changes require a per-session CSRF value and
  EXACT same-origin check. Login requires a HTTPS origin from explicit
  allowlist. Five failed attempts in a 10-minute window lock sign-in for
  15 minutes. No default password and no publicly editable username.
- The existing ADMIN_TOKEN still works as an emergency API bearer credential,
  including the old SSH-tunnel workflow, but is hidden under Advanced in UI.
  The password is NOT interchangeable with an IPTV password, Stremio token,
  or the underlying playback HMAC key.
- `ADMIN_PUBLIC_ORIGIN` is optional when `PUBLIC_BASE_URL` already uses
  the same public HTTPS host/port; the configured addon's origin is derived
  without its URL path. If the Admin uses another public host/port, set the
  explicit exact HTTPS origin. Browser password login fails closed if no
  acceptable HTTPS origin exists.
- No change to bridge metadata, indexing, movie/series URLs or nginx routing.

### Password setup / rotation (ON LINUX VIA SSH)

Only after checking out the reviewed pinned v0.4.2 commit and building the
new image, recreate **only the Admin** service, then run:

```sh
sudo docker exec -it xtream-vod-admin python -m admin_auth set-password
```

Enter and confirm a long passphrase when prompted; terminal input is hidden.
No password value is printed. The operation can also **rotate** the password,
which invalidates all browser logins. Existing bearer token remains a
recovery mechanism. If a password must be reset on replacement hardware,
restore SQLite or simply use the same CLI to set a new password.

Check without revealing credentials:

```sh
curl -fsS http://127.0.0.1:18768/api/auth/session |
python3 -c 'import sys,json; p=json.load(sys.stdin); print("PASSWORD_READY",p.get("password_ready"))'
```

A new `ADMIN_TOKEN` is NOT required. Do not print `.env` to the chat.

## Safari / Private Relay: LAN route, without disabling or editing it

Safari may reach `olivergiangvu.asuscomm.com` via a public Private Relay
egress IP that is *correctly denied* by HomeDocker's LAN ACL. Edge on
192.168.50.x is allowed. The server cannot safely infer that a relay IP
belongs to the Mac on the LAN. **Never whitelist Apple's entire relay range.**

Important: Apple's Private Relay documentation says a normal unencrypted
DNS server offered by a LAN is **not necessarily used for Safari/Private
Relay queries**. Therefore, an ASUS split-DNS entry alone is **not a proven
fix** for a PUBLIC DDNS hostname while Private Relay is active.

The safer optional Safari path is **a private `.local` hostname** that
Safari recognizes as a LOCAL network name, served using a separate trusted
LAN TLS certificate and SNI nginx vhost on the SAME port 18450:

```
Safari: https://homedocker.local:18450/admin/
 -> Bonjour/mDNS -> 192.168.50.153 (direct LAN)
 -> same host nginx port 18450, server_name homedocker.local
 -> LAN ACL -> 127.0.0.1:18768
```

The existing public address `https://olivergiangvu.asuscomm.com:18450`
remains **unchanged** for AIOStreams manifest and playback. HTTPS to .local
requires a leaf certificate with SAN DNS:homedocker.local which the user
explicitly trusts on the Mac; do NOT bypass TLS verification or blindly trust
a broad self-signed CA. Avoid installing a broad CA on other devices.

The reviewed but **not installed** nginx template is
`nginx-admin-safari-local.example.conf`. Only enable it after:
- Confirm Bonjour name resolution on Mac and Linux, and Nginx SNI matching.
- Issue a *dedicated* self-signed local server **leaf** certificate and
  explicitly trust only that leaf for SSL on the Mac; review renewal/expiry.
- Add `ADMIN_LAN_ORIGIN=https://homedocker.local:18450` to the Admin env.
- Confirm WAN is blocked, HTTPS certificate accepted, `/admin/` 200,
  `/admin/assets/app.js` 200 and `/admin/api/overview` 401 without auth.
- Keep `iCloud Private Relay` and `Limit IP Address Tracking` untouched.
- Preserve 3/3 Movie and 3/3 Series HTTP Range playback probes.

This path is a **candidate** based on Apple's documented local-network
exclusion, not a claim that a Safari browser test already passed. Validate
with Safari before considering the local route complete.

Alternative if the user needs EXACTLY the same public DDNS hostname
inside Safari: an audited encrypted DNS resolver/profile or an explicitly
approved Internet-accessible auth gateway with additional access factors
would be needed. Do not silently expose /admin to all WAN IPs.

## Rollback

- Restart the previously pinned 0.4.1 Admin image only; do NOT restart the
  main bridge to undo UI login changes.
- Existing SQLite auth tables can remain unused and have no bearing on
  signed playback or Xtream index.
- Never run `docker compose down -v` or remove the shared SQLite volume.
- Do not modify Private Relay, ASUS port forwarding or unrelated nginx sites.
