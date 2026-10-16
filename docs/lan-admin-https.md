# LAN access to HomeDocker Xtream Admin, without exposing credentials

**Alternate plan superseded for this HomeDocker deployment:** the user selected
the existing HTTPS port 18450 and a relative /admin/ path instead of a new
18769 listener. See [admin-shared-18450.md](admin-shared-18450.md). This
18769 document remains a more strongly network-isolated fallback if the
public port's LAN ACL can be bypassed by WAN source NAT. Do not deploy both
nginx templates by default.

The v0.4 pilot admin currently runs on `127.0.0.1:18768`, and an unauthenticated
call to `/api/overview` returned **401**. Keep this safe default unchanged.

**Do not** change Docker admin ports to `0.0.0.0:18768` for browser convenience,
because the UI uses `Authorization: Bearer ADMIN_TOKEN` and will eventually
accept provider passwords. Plain `http://192.168.50.153:18768` sends those
secrets unencrypted over the LAN.

## Recommended LAN route (native nginx on Linux host)

```text
Laptop / Apple TV / phone on 192.168.50.0/24
    HTTPS to lan-admin.example.net:18769
       ↓
  HOST nginx listener 192.168.50.153:18769 (TLS + LAN allowlist)
       ↓
  127.0.0.1:18768 (Docker admin, unmodified)
       ↓
  admin bearer auth API; bridge at Docker service port 8767
```

A TLS certificate must cover the **actual LAN-resolvable DNS name** used by the
browser. Existing public DDNS hostname + certificate can be reused *only if*
that hostname resolves to `192.168.50.153` inside the LAN (split-horizon
DNS/hosts entry) and its certificate matches. A certificate for a DNS hostname
does not automatically validate the raw IP. Avoid telling users to bypass
certificate warnings.

Before editing native nginx, discover the installed certificate path and
chosen LAN name **privately** via SSH. Never post the private key or `.env`.

## Read-only preflight (once hostname/cert/key paths are known)

```sh
sudo python3 scripts/preflight_lan_admin.py \
  --lan-ip 192.168.50.153 \
  --hostname YOUR_VALID_LAN_DNS_NAME \
  --cert /path/to/fullchain.pem \
  --key /path/to/privkey.pem \
  --allow-cidr 192.168.50.0/24 \
  --https-port 18769
```

The preflight prints only safe booleans, numeric port and access status, not
actual paths/hostnames/cert contents. `ready_for_review=true` means only
that prereqs look plausible; verify nginx/firewall and WAN in person.

Fill placeholders in `nginx-lan-admin.example.conf`, then copy the
generated config into the native nginx location manually; NEVER deploy
a placeholder file. In an existing vhost environment prefer a new, narrow,
LAN-only site that does not alter or share the existing public service on
18450. Run `sudo nginx -t` before `sudo systemctl reload nginx`.
Allow LAN subnet using nginx plus host firewall, and ensure ASUS router
does not forward 18769 from WAN.

## Acceptance gates

1. `sudo ss -ltnp` shows host nginx binding only
   `192.168.50.153:18769`, Docker admin remains loopback-only on 18768.
2. In browser on LAN, `https://LAN_DNS_NAME:18769/` opens with **valid
   HTTPS**; certificate errors are not bypassed.
3. `https://LAN_DNS_NAME:18769/api/overview` returns 401 without token,
   200 only with valid `Authorization`; malicious cross-origin browser
   fetch must not gain access.
4. From an external network the admin is inaccessible (no router forward).
5. Existing Movie and Series 3/3 HTTP Range probes continue to PASS.
6. Existing SSH tunnel to loopback 18768 remains a fallback.
7. Confirm no sensitive headers/paths are written to nginx logs.

**Future multi-provider credentials** must not be enabled in this UI until
LAN HTTPS authentication and provider encryption-at-rest have passed their
own security tests. See GitHub issue #23.
