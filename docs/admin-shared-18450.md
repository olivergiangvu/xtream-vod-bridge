# Shared 18450 HTTPS admin UI — HomeDocker v0.4.1

This is an admin routing/frontend patch ONLY. It changes no Xtream provider
configuration, SQLite schema, playback signature, public manifest route,
ASUS port forward or TLS certificate. The admin backend still listens
on the host at 127.0.0.1:18768.

| Browser URL | Nginx upstream | Access |
| --- | --- | --- |
| https://olivergiangvu.asuscomm.com:18450/admin/ | http://127.0.0.1:18768/ | LAN IP ACL + ADMIN_TOKEN |
| .../admin/api/overview | http://127.0.0.1:18768/api/overview | LAN IP ACL + Bearer token |
| .../admin/assets/app.js | http://127.0.0.1:18768/assets/app.js | LAN IP ACL |
| Existing .../a/... and .../play/... | Existing bridge at 127.0.0.1:18767 | UNCHANGED |

Frontend HTML references assets relatively. JS resolves API URLs relative to
document.baseURI. Thus both /admin/ via public nginx and / directly through a
local SSH tunnel continue to work. Trailing slash on proxy_pass is required.

## Security warning: 18450 is public

A source-IP allowlist on a public listener is NOT a guaranteed LAN-only
boundary if ASUS WAN forwarding/hairpin rewrites a WAN request's source IP
into 192.168.50.0/24 (for example to the LAN router IP). A genuine WAN
client getting HTTP 401 from /admin/api/overview means nginx has ALLOWED the
admin path; only the Bearer token blocked access. This is insufficient as
the sole boundary for sensitive provider-password editing. Prefer a second
independent auth layer (nginx Basic Auth with a different password, VPN,
mTLS, or a dedicated LAN-only listener) if router SNAT behavior is unknown.
Do not bind the admin container to 0.0.0.0 or add a new router forward.

## A. Read-only inspection of the exact nginx 18450 vhost

~~~bash
sudo nginx -t
sudo nginx -T 2>/dev/null |
  awk '/^# configuration file /{file=$0}
       /^[[:space:]]*listen[[:space:]].*18450([ ;]|$)/ {
         print file
         print "LISTEN_18450=" $0
       }'
sudo openssl x509 -in /etc/nginx/ssl/olivergiangvu.asuscomm.com/fullchain.pem -noout -checkhost olivergiangvu.asuscomm.com
sudo openssl x509 -in /etc/nginx/ssl/olivergiangvu.asuscomm.com/fullchain.pem -noout -checkend 0
~~~

Only share config filenames and listen lines, NOT entire nginx -T output:
other vhosts may contain signed paths and private configuration.

## B. Deploy the admin-only frontend after passing CI

Backup the original Compose, .env and the exact nginx 18450 vhost to a
root-only directory before editing. Checkout a reviewed pinned commit
from this feature and verify Compose. The Compose image tag is 0.4.1.

~~~bash
cd /opt/xtream-vod-bridge || exit 1
sudo docker compose config --quiet
sudo docker compose build xtream-vod-bridge
sudo docker compose up -d --no-deps xtream-vod-admin
curl -sS -o /dev/null -w 'LOCAL_ADMIN_401=%{http_code}\n' http://127.0.0.1:18768/api/overview
~~~

The bridge image is built but the running Movie/Series bridge is NOT
recreated, and the localhost Docker admin port remains unchanged.

## C. Install the two nginx locations inside the existing 18450 server

Copy nginx-admin-18450.location.conf's two location blocks INSIDE the
existing server { listen 18450 ssl; ... } only, NOT into a new server.
Leave existing /, /a/... and /play/... locations unchanged.
Run nginx -t, then systemctl reload nginx. If validation fails,
restore the previous vhost and rerun nginx -t; never reload invalid nginx.

From a LAN host, validate TLS without bypassing certificate checks:

~~~bash
curl -sS --resolve olivergiangvu.asuscomm.com:18450:192.168.50.153 -o /dev/null -w 'ADMIN_API=%{http_code}\n' https://olivergiangvu.asuscomm.com:18450/admin/api/overview
curl -sS --resolve olivergiangvu.asuscomm.com:18450:192.168.50.153 -o /dev/null -w 'ADMIN_UI=%{http_code}\n' https://olivergiangvu.asuscomm.com:18450/admin/
~~~

Expected from an allowed LAN client: API 401, UI 200.
Test actual WAN through a mobile cellular connection with Wi-Fi and VPN
disabled: the admin request must be blocked at nginx (403) or by an
independent authentication boundary. A WAN 401 indicates that the
nginx allowlist was bypassed, e.g. via router SNAT. Do NOT proceed to
password edits if that happens.

Check Movie and Series playback using existing probe_playback.py
(samples=3) afterwards. All manifest URLs remain unchanged.

For a LAN browser whose DDNS hostname resolves to WAN IP, use split DNS
to point the same TLS hostname to 192.168.50.153 on the LAN. Don't bypass
TLS warnings or forward any extra ports.

## Rollback

Restore the nginx 18450 vhost backup, test and reload nginx. Restore
the prior Compose file/image for xtream-vod-admin independently. The
main bridge can remain running throughout; never use down -v.
Multi-provider provider/password management remains a separate draft v0.5
task requiring encryption-key DR and provider-aware playback safety gates.
