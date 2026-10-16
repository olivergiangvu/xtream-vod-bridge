#!/usr/bin/env bash
# HomeDocker v0.5g: Canary containers ONLY. Does not modify nginx or production.
set -Eeuo pipefail
ROOT=/opt/xtream-vod-canary
BASE="$ROOT/src/canary/compose.yaml"
OVERRIDE="$ROOT/ui-override.yaml"
SHA="206cf27063b8939fbd5880a61ff31aa7c2352985"
OLD_ADMIN="homedocker/xtream-vod-canary-admin:0.5e-cookie-e153b327b49f"
PLAY_IMAGE="homedocker/xtream-vod-canary:5c2f02233a0f"
NEW_ADMIN="homedocker/xtream-vod-canary-admin:0.5g-prefix-$(printf '%.12s' "$SHA")"
ORIGIN="https://olivergiangvu.asuscomm.com:18450"
URL="https://raw.githubusercontent.com/olivergiangvu/xtream-vod-bridge/$SHA"
test -f "$BASE" && test -f "$OVERRIDE"
for tool in sudo docker git curl python3; do command -v "$tool" >/dev/null; done

PROD_A=$(sudo docker inspect -f '{{.Id}}' xtream-vod-admin)
PROD_P=$(sudo docker inspect -f '{{.Id}}' xtream-vod-bridge)
test "$(sudo docker inspect -f '{{.Config.Image}}' xtream-vod-canary-admin)" = "$OLD_ADMIN"
test "$(sudo docker inspect -f '{{.Config.Image}}' xtream-vod-canary-playback)" = "$PLAY_IMAGE"

# Exact-known Stage 4A override is the only acceptable migration baseline.
python3 - "$OVERRIDE" "$OLD_ADMIN" <<'PY'
from pathlib import Path
import sys
expected = (
    "services:\n  xtream-vod-admin:\n"
    "    image: " + sys.argv[2] + "\n"
    "    environment:\n"
    "      XTREAM_SESSION_COOKIE: xtream_canary_admin_session\n"
    "      XTREAM_LOGIN_NONCE_COOKIE: xtream_canary_login_nonce\n"
    "      XTREAM_GATEWAY_REFERRER_POLICY: same-origin\n"
    "      ADMIN_PUBLIC_ORIGIN: https://olivergiangvu.asuscomm.com:18451\n"
    "      PUBLIC_BASE_URL: https://olivergiangvu.asuscomm.com:18451\n"
)
if Path(sys.argv[1]).read_text() != expected:
    raise SystemExit("STOP: Canary Compose override drifted; no changes made")
print("STAGE4A_BASELINE=PASS")
PY

TMP=$(mktemp -d)
BACKUP=""
ROLLBACK=0
cleanup() {
  code=$?
  trap - EXIT
  if [ "$code" -ne 0 ] && [ "$ROLLBACK" -eq 1 ]; then
    echo "ROLLBACK_CANARY_STARTED"
    set +e
    cp -a "$BACKUP" "$OVERRIDE"
    sudo env CANARY_DIR="$ROOT" CANARY_IMAGE="$PLAY_IMAGE" \
      docker compose -p xtream-vod-canary -f "$BASE" -f "$OVERRIDE" \
      up -d --no-deps --no-build --force-recreate xtream-vod-bridge xtream-vod-admin
    echo "ROLLBACK_CANARY_ATTEMPTED"
  fi
  rm -rf "$TMP"
  exit "$code"
}
trap cleanup EXIT

while read -r FILE HASH; do
  mkdir -p "$TMP/$(dirname "$FILE")"
  curl -fsSL --retry 3 --max-time 30 "$URL/$FILE" -o "$TMP/$FILE"
  if [ "$(git hash-object "$TMP/$FILE")" != "$HASH" ]; then
    echo "STOP: Canary source hash mismatch"; exit 1
  fi
done <<'BLOBS'
route_paths.py d313f86ce81ae3906ce93b21235329d085048fa3
admin_auth.py b52948bf4e333a5baab468ad82badf926db900c5
admin_ui.py 9a67edac8838cb0a6d279498fbc8f672a73df9aa
admin/assets/app.js 123ea2c3e076e64ca826320710ba7e202f98ffbb
admin/assets/workspace.js 114bb4ef43afc463d5fe57b723ef2e0cec802611
BLOBS

python3 - "$TMP" <<'PY'
from pathlib import Path
import ast, sys
for path in ("route_paths.py", "admin_auth.py", "admin_ui.py"):
    ast.parse((Path(sys.argv[1]) / path).read_text(), filename=path)
print("SAME_PORT_SOURCE_INTEGRITY_AND_SYNTAX=PASS")
PY
if command -v node >/dev/null; then
  node --check "$TMP/admin/assets/app.js"
  node --check "$TMP/admin/assets/workspace.js"
  echo "SAME_PORT_JS_SYNTAX=PASS"
fi

cat > "$TMP/Dockerfile" <<EOF
FROM $OLD_ADMIN
COPY route_paths.py admin_auth.py admin_ui.py /srv/
COPY admin/assets/app.js admin/assets/workspace.js /srv/admin/assets/
EOF
sudo docker build --network none --pull=false -t "$NEW_ADMIN" "$TMP" >/dev/null
echo "SAME_PORT_ADMIN_IMAGE_BUILD=PASS"

BACKUP="$ROOT/ui-override.yaml.bak-stage5-$(date +%Y%m%d-%H%M%S)-$$"
cp -a "$OVERRIDE" "$BACKUP"
cat > "$OVERRIDE" <<EOF
services:
  xtream-vod-bridge:
    environment:
      PUBLIC_BASE_URL: $ORIGIN/canary
  xtream-vod-admin:
    image: $NEW_ADMIN
    environment:
      XTREAM_URL_PREFIX: /canary
      XTREAM_SESSION_COOKIE: xtream_canary_admin_session
      XTREAM_LOGIN_NONCE_COOKIE: xtream_canary_login_nonce
      XTREAM_GATEWAY_REFERRER_POLICY: same-origin
      ADMIN_PUBLIC_ORIGIN: $ORIGIN
      PUBLIC_BASE_URL: $ORIGIN/canary
EOF
ROLLBACK=1

compose() {
  sudo env CANARY_DIR="$ROOT" CANARY_IMAGE="$PLAY_IMAGE" \
    docker compose -p xtream-vod-canary -f "$BASE" -f "$OVERRIDE" "$@"
}
compose config --quiet
compose up -d --no-deps --no-build --force-recreate xtream-vod-bridge
for i in $(seq 1 45); do
  HEALTH=$(sudo docker inspect -f '{{.State.Health.Status}}' xtream-vod-canary-playback)
  if [ "$HEALTH" = healthy ]; then break; fi
  if [ "$HEALTH" = unhealthy ]; then echo "CANARY_PLAYBACK_UNHEALTHY"; exit 1; fi
  sleep 2
done
test "$HEALTH" = healthy
compose up -d --no-deps --no-build --force-recreate xtream-vod-admin
for i in $(seq 1 45); do
  HEALTH=$(sudo docker inspect -f '{{.State.Health.Status}}' xtream-vod-canary-admin)
  if [ "$HEALTH" = healthy ]; then break; fi
  if [ "$HEALTH" = unhealthy ]; then echo "CANARY_ADMIN_UNHEALTHY"; exit 1; fi
  sleep 2
done
test "$HEALTH" = healthy

sudo docker exec -i xtream-vod-canary-admin python - <<'PY'
import app, admin_auth, admin_ui, route_paths, urllib.request
origin = "https://olivergiangvu.asuscomm.com:18450"
assert app.PUBLIC == origin + "/canary"
assert admin_auth.PUBLIC_ORIGIN == origin
assert route_paths.LOGIN_PATH == "/canary/admin-signin/"
assert route_paths.ADMIN_PATH == "/canary/admin/"
assert admin_auth.COOKIE == "xtream_canary_admin_session"
assert admin_auth.COOKIE_PATH == "/canary/admin/"
assert admin_ui.GATE_LOGIN_COOKIE == "xtream_canary_login_nonce"
with urllib.request.urlopen("http://127.0.0.1:8768/gateway/", timeout=8) as r:
    assert r.status == 200
    assert 'action="/canary/admin-signin/"' in r.read().decode()
    assert "Path=/canary/admin-signin/" in r.headers.get("Set-Cookie", "")
with urllib.request.urlopen("http://127.0.0.1:8768/", timeout=8) as r:
    assert 'id="personalWorkspace"' in r.read().decode()
print("CANARY_PREFIX_ADMIN_UI_AND_COOKIES=PASS")
PY
sudo docker exec -i xtream-vod-canary-playback python - <<'PY'
import app
assert app.PUBLIC == "https://olivergiangvu.asuscomm.com:18450/canary"
print("CANARY_PREFIX_PLAYBACK_URLS=PASS")
PY
test "$(sudo docker inspect -f '{{.Id}}' xtream-vod-admin)" = "$PROD_A"
test "$(sudo docker inspect -f '{{.Id}}' xtream-vod-bridge)" = "$PROD_P"
echo "PRODUCTION_CONTAINERS_UNCHANGED=PASS"
echo "CANARY_SAME_PORT_CONTAINERS=PASS"
echo "NGINX_AND_FIREWALL_UNCHANGED=PASS"
echo "ROLLBACK_BACKUP=$BACKUP"
ROLLBACK=0
