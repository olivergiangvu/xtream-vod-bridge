# v0.4.3 — Manifest Copy + independent Admin Users (developer candidate)

**Status: offline candidate; not deployed to HomeDocker.** Base: PR #29
(password-first sessions), currently running HomeDocker v0.4.1 remains the
rollback baseline. This patch does NOT enable multi-Xtream streaming
providers and does not modify the Movie/Series index, HMAC, existing
addon URL, nginx 18450, or iCloud Private Relay.

## Copy manifest from the Admin console

A new AIOStreams Manifest card appears after login:
- Exact URL is generated on the server from
  `PUBLIC_BASE_URL` + `/a/` + `ADDON_TOKEN` + `/manifest.json`.
- `GET /api/manifest` requires Owner or Admin authentication. Viewer is
  denied (403), anonymous is denied (401). The response has Cache-Control:
  no-store and Referrer-Policy: no-referrer. Tokens never appear in
  pre-login HTML, files in Git, analytics, or query parameter auth.
- UI keeps the URL in JS memory only after login; masked by default.
  Explicit Show/Hide and Copy manifest; Lock clears it.
- Paste into AIOStreams → Addons → Custom Addon → Manifest URL. Refrain from
  publishing or screenshotting the full private URL.

This follows the usability pattern of HomeDocker Trakt Bridge
(`olivergiangvu/homedocker-trakt-bridge`:
`src/server.mjs` manifest-copy-row), without adopting its
URL-key authentication approach for the Admin console.

## Multiple human accounts are NOT IPTV providers

- **Owner**: built-in account, username `owner`, same Admin password
  provisioned with `python -m admin_auth set-password`. May create, revoke,
  delete human Admin Users. Cannot be deleted.
- **Admin**: independent username and password; read diagnostics, copy the
  private manifest, modify runtime settings, but cannot create other Admin
  Users.
- **Viewer**: independent username and password; read status/diagnostics
  only. Cannot copy manifest, change settings or manage users.

UI now includes Admin Users Owner-only panel, create account, enable/disable,
reset password with a MASKED form, and remove account. 14+ printable-character
passwords are individually salted+hashed using PBKDF2-SHA256, not plaintext.
Account changes and password rotation revoke affected sessions immediately.
Admin Users are stored in new SQLite table `admin_users`; legacy password
`owner` remains in `admin_password`. Sessions add a backward-compatible
username column; existing cookie sessions are migrated to built-in owner.
No Xtream URL, username or IPTV password is stored in this module.

The emergency ADMIN_TOKEN still authorizes all API operations as Owner via
Bearer; keep that token in the server's protected .env and avoid pasting it
into URLs or screenshots.

## Safe pilot plan: admin service only

Do not deploy until CI/CodeQL are green. Create a root-only backup of .env,
Compose, and a CONSISTENT SQLite snapshot using the SQLite backup API:
simply copying a live WAL SQLite file may not produce a complete backup.
Keep the current running bridge container/image unchanged while building
the new shared image and recreating only the `xtream-vod-admin` service.

After building pinned 0.4.3, verify:
1. `docker inspect xtream-vod-admin --format '{{.Config.Image}}'` is
   `homedocker/xtream-vod-bridge:0.4.3`.
2. No-auth Admin API `/api/overview` is 401. Admin UI `/admin/` and JS
   return 200 via existing HTTPS 18450; public addon manifest works unchanged.
3. If first password login, provision once using
   `sudo docker exec -it xtream-vod-admin python -m admin_auth set-password`.
   No password appears in terminal history, chat or Git.
4. Login as owner; Copy manifest, verify it matches the existing installed
   AIOStreams addon URL WITHOUT publishing it.
5. Create one Viewer, one Admin; verify permissions, revocation and Lock.
6. Retest Movie 3/3 and Series 3/3 Range, seek and live AIOStreams.
7. Revert admin image to pinned 0.4.1 if needed; legacy index and
   signed playback remain intact. Never `docker compose down -v`.

## Safari 403: separate network/TLS workstream

Safari uses iCloud Private Relay on the public DDNS hostname, while Edge
works on the LAN. September 16 previous workaround involved changing
Limit IP Address Tracking, which the user now expressly forbids.
**Do not reuse that workaround or whitelist Apple relay egress IPs.**

Apple's WWDC21 documentation says local-network/private domain traffic does
not use iCloud Private Relay. Candidate approach: `homedocker.local` via
Bonjour/mDNS to 192.168.50.153 and a separately trusted HTTPS *leaf* TLS
certificate, using an SNI vhost on the SAME port 18450 (reference:
`nginx-admin-safari-local.example.conf`). Do not enable it or install
trust certificates without verifying local name resolution first. The
public DDNS/AIOStreams address remains intact. Split DNS for a public
hostname is not automatically effective under Safari Private Relay.

Read-only preflight:
On Linux SSH: `hostnamectl --static`, `systemctl is-active avahi-daemon`.
On Mac (local Terminal): `dns-sd -G v4 homedocker.local` and verify it resolves
to 192.168.50.153. If not, **stop** before touching certificates or nginx.

Finally verify HTTPS and WAN access from a genuine 4G/5G network.
This branch makes NO router, nginx or Private Relay change.
