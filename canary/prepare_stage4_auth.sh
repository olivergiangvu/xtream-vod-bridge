#!/usr/bin/env bash
# Stage 4A — SAFE Canary Admin-only authentication preparation.
# Overlays ONLY Canary Admin. No nginx, playback, production or DB changes.
set -euo pipefail

ROOT=/opt/xtream-vod-canary
BASE_COMPOSE="$ROOT/src/canary/compose.yaml"
OVERRIDE="$ROOT/ui-override.yaml"
REVIEWED_SHA="e153b327b49f7fe5ab7fdf71045ed229348ee47b"
UI_IMAGE="homedocker/xtream-vod-canary-admin:0.5d-d5375d8ae602"
SHORT_SHA=$(printf '%.12s' "$REVIEWED_SHA")
NEW_IMAGE="homedocker/xtream-vod-canary-admin:0.5e-cookie-$SHORT_SHA"
CANARY_BASE_IMAGE="homedocker/xtream-vod-canary:5c2f02233a0f"
ORIGIN="https://olivergiangvu.asuscomm.com:18451"
BASE="https://raw.githubusercontent.com/olivergiangvu/xtream-vod-bridge/$REVIEWED_SHA"

test -f "$BASE_COMPOSE" && test -f "$OVERRIDE" || {
  echo "STOP: expected Stage 3 Canary files not found"; exit 1;
}
for tool in git curl docker sudo python3; do
  command -v "$tool" >/dev/null || { echo "STOP: missing $tool"; exit 1; }
done
PROD_A=$(sudo docker inspect -f '{{.Id}}' xtream-vod-admin)
PROD_P=$(sudo docker inspect -f '{{.Id}}' xtream-vod-bridge)
CANARY_P=$(sudo docker inspect -f '{{.Id}}' xtream-vod-canary-playback)
CANARY_A=$(sudo docker inspect -f '{{.Id}}' xtream-vod-canary-admin)
ACTIVE_IMAGE=$(sudo docker inspect -f '{{.Config.Image}}' xtream-vod-canary-admin)
test "$ACTIVE_IMAGE" = "$UI_IMAGE" || {
  echo "STOP: unexpected Canary Admin image; no changes made"; exit 1;
}
sudo docker image inspect "$UI_IMAGE" >/dev/null
sudo docker image inspect "$CANARY_BASE_IMAGE" >/dev/null

# Refuse if local override has drifted: never overwrite unknown settings.
python3 - "$OVERRIDE" "$UI_IMAGE" <<'PY'
import sys
from pathlib import Path
actual = Path(sys.argv[1]).read_text()
expected = f"services:\n  xtream-vod-admin:\n    image: {sys.argv[2]}\n"
if actual != expected:
    raise SystemExit("STOP: Canary UI override differs from Stage 3 baseline")
print("CANARY_OVERRIDE_BASELINE=PASS")
PY

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
for FILE in admin_auth.py admin_ui.py; do
  curl -fsSL --retry 3 --max-time 30 "$BASE/$FILE" -o "$TMP/$FILE"
done
test "$(git hash-object "$TMP/admin_auth.py")" = \
  "734665cd182a408172ec38797a08c273c0b4e3ba" || {
    echo "STOP: auth source integrity mismatch"; exit 1;
  }
test "$(git hash-object "$TMP/admin_ui.py")" = \
  "62771e719e695f623b2c7130292b94cdc1b082b6" || {
    echo "STOP: gateway source integrity mismatch"; exit 1;
  }
python3 - "$TMP" <<'PY'
import ast, pathlib, sys
for file in ("admin_auth.py", "admin_ui.py"):
    p = pathlib.Path(sys.argv[1]) / file
    ast.parse(p.read_text(), filename=file)
print("CANARY_AUTH_SOURCE_AND_SYNTAX=PASS")
PY

# Build inherits previous v0.5D UI and exact backend, replacing only auth files.
cat > "$TMP/Dockerfile" <<EOF
FROM $UI_IMAGE
COPY admin_auth.py admin_ui.py /srv/
EOF
sudo docker build --pull=false -t "$NEW_IMAGE" "$TMP" >/dev/null
echo "CANARY_AUTH_IMAGE_BUILD=PASS"

BACKUP="$ROOT/ui-override.yaml.bak-stage4a-$(date +%Y%m%d-%H%M%S)"
cp -a "$OVERRIDE" "$BACKUP"
rollback() {
  echo "ROLLBACK_CANARY_ADMIN_STARTED"
  cp -a "$BACKUP" "$OVERRIDE"
  sudo env CANARY_DIR="$ROOT" CANARY_IMAGE="$CANARY_BASE_IMAGE" \
    docker compose --project-name xtream-vod-canary \
    -f "$BASE_COMPOSE" -f "$OVERRIDE" \
    up -d --no-deps --no-build --force-recreate xtream-vod-admin
  echo "CANARY_ADMIN_ROLLBACK_REQUESTED"
}
cat > "$OVERRIDE" <<EOF
services:
  xtream-vod-admin:
    image: $NEW_IMAGE
    environment:
      XTREAM_SESSION_COOKIE: xtream_canary_admin_session
      XTREAM_LOGIN_NONCE_COOKIE: xtream_canary_login_nonce
      XTREAM_GATEWAY_REFERRER_POLICY: same-origin
      ADMIN_PUBLIC_ORIGIN: $ORIGIN
      PUBLIC_BASE_URL: $ORIGIN
EOF
compose() {
  sudo env CANARY_DIR="$ROOT" CANARY_IMAGE="$CANARY_BASE_IMAGE" \
    docker compose --project-name xtream-vod-canary \
    -f "$BASE_COMPOSE" -f "$OVERRIDE" "$@"
}
if ! compose config -q; then
  echo "STOP: Canary Compose invalid"; rollback; exit 1;
fi
if ! compose up -d --no-deps --no-build --force-recreate xtream-vod-admin; then
  rollback; exit 1;
fi
HEALTH=starting
for _ in $(seq 1 45); do
  HEALTH=$(sudo docker inspect -f \
    '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
    xtream-vod-canary-admin)
  test "$HEALTH" = healthy && break
  test "$HEALTH" = unhealthy && break
  sleep 2
done
if test "$HEALTH" != healthy; then
  echo "CANARY_ADMIN_HEALTH=$HEALTH"; rollback; exit 1;
fi
if ! sudo docker exec -i xtream-vod-canary-admin python - <<'PY'
import admin_auth, admin_ui, app, urllib.request
origin = "https://olivergiangvu.asuscomm.com:18451"
assert admin_auth.PUBLIC_ORIGIN == origin
assert app.PUBLIC == origin
assert admin_auth.COOKIE == "xtream_canary_admin_session"
assert admin_ui.GATE_LOGIN_COOKIE == "xtream_canary_login_nonce"
assert admin_ui.GATEWAY_REFERRER_POLICY == "same-origin"

with urllib.request.urlopen("http://127.0.0.1:8768/gateway/", timeout=8) as r:
    assert r.status == 200
    assert r.headers.get("Referrer-Policy") == "same-origin"
    nonce = r.headers.get("Set-Cookie", "")
    assert "xtream_canary_login_nonce=" in nonce
    assert "Secure" in nonce and "HttpOnly" in nonce
with urllib.request.urlopen("http://127.0.0.1:8768/", timeout=8) as r:
    html = r.read(200000).decode()
    assert 'id="personalWorkspace"' in html
    assert 'id="adminWorkspace"' in html

print("CANARY_AUTH_COOKIE_ORIGIN_HTTP=PASS")
print("CANARY_V05D_UI_PRESERVED=PASS")
PY
then
  echo "STOP: Canary Admin auth smoke failed"; rollback; exit 1;
fi
test "$(sudo docker inspect -f '{{.Id}}' xtream-vod-admin)" = "$PROD_A"
test "$(sudo docker inspect -f '{{.Id}}' xtream-vod-bridge)" = "$PROD_P"
test "$(sudo docker inspect -f '{{.Id}}' xtream-vod-canary-playback)" = "$CANARY_P"
test "$(sudo docker inspect -f '{{.Id}}' xtream-vod-canary-admin)" != "$CANARY_A"
echo "PRODUCTION_CONTAINER_IDS_UNCHANGED=PASS"
echo "CANARY_PLAYBACK_UNCHANGED=PASS"
echo "CANARY_ADMIN_AUTH_STAGE4A=PASS"
echo "NGINX_OR_FIREWALL_CHANGES=NONE"
echo "CANARY_PUBLIC_INGRESS=NONE"
echo "ROLLBACK_COMPOSE_OVERRIDE_BACKUP=$BACKUP"
