#!/usr/bin/env bash
# v0.5D Canary-only static UI overlay: never edit HomeDocker production.
set -euo pipefail

ROOT="/opt/xtream-vod-canary"
BASE_COMPOSE="$ROOT/src/canary/compose.yaml"
UI_SHA="d5375d8ae60289d5129898eb34d05afdf4f9ce36"
BASE_IMAGE="homedocker/xtream-vod-canary:5c2f02233a0f"
UI_IMAGE="homedocker/xtream-vod-canary-admin:0.5d-$(printf '%.12s' "$UI_SHA")"
UI_ROOT="$ROOT/ui-release-$(printf '%.12s' "$UI_SHA")"
OVERRIDE="$ROOT/ui-override.yaml"
URL="https://raw.githubusercontent.com/olivergiangvu/xtream-vod-bridge/$UI_SHA"

for tool in docker git python3 curl sudo; do
  command -v "$tool" >/dev/null || { echo "STOP: missing $tool"; exit 1; }
done
test -f "$BASE_COMPOSE"
test ! -e "$OVERRIDE" || { echo "STOP: Canary UI override exists"; exit 1; }
test ! -e "$UI_ROOT" || { echo "STOP: Canary UI release exists"; exit 1; }
PROD_A=$(sudo docker inspect -f '{{.Id}}' xtream-vod-admin)
PROD_P=$(sudo docker inspect -f '{{.Id}}' xtream-vod-bridge)
CANARY_P=$(sudo docker inspect -f '{{.Id}}' xtream-vod-canary-playback)
CURRENT_ADMIN=$(sudo docker inspect -f '{{.Config.Image}}' xtream-vod-canary-admin)
test "$CURRENT_ADMIN" = "$BASE_IMAGE" || {
  echo "STOP: Unexpected Canary Admin image $CURRENT_ADMIN"; exit 1;
}
sudo docker image inspect "$BASE_IMAGE" >/dev/null
echo "CANARY_BASELINE=PASS"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
for FILE in admin/index.html admin/assets/app.js admin/assets/workspace.js admin/assets/style.css; do
  mkdir -p "$TMP/$(dirname "$FILE")"
  curl -fsSL --retry 3 --max-time 30 "$URL/$FILE" -o "$TMP/$FILE"
  case "$FILE" in
    admin/index.html) EXPECTED="8c28f47900ec22d29c2135bb2cd34266f1d81a9c";;
    admin/assets/app.js) EXPECTED="c23cdade73cfe181bfc3d323f5fa313e5711a83c";;
    admin/assets/workspace.js) EXPECTED="10b8307113004d32b7987a99f62e4490a03a6caa";;
    admin/assets/style.css) EXPECTED="bde37ed6830d6551243869c0d1d0f19c76ae372c";;
    *) echo "STOP: unexpected file"; exit 1;;
  esac
  test "$(git hash-object "$TMP/$FILE")" = "$EXPECTED" || {
    echo "STOP: UI source hash mismatch"; exit 1;
  }
done
echo "CANARY_UI_ASSETS_VERIFIED=PASS"
if command -v node >/dev/null; then
  node --check "$TMP/admin/assets/app.js"
  node --check "$TMP/admin/assets/workspace.js"
  echo "CANARY_JS_SYNTAX=PASS"
fi

mkdir -m 0750 "$UI_ROOT"
cp -a "$TMP/admin" "$UI_ROOT/"
cat > "$UI_ROOT/Dockerfile" <<EOF
FROM $BASE_IMAGE
COPY admin/index.html /srv/admin/index.html
COPY admin/assets/app.js /srv/admin/assets/app.js
COPY admin/assets/workspace.js /srv/admin/assets/workspace.js
COPY admin/assets/style.css /srv/admin/assets/style.css
EOF
sudo docker build --pull=false -t "$UI_IMAGE" "$UI_ROOT" >/dev/null
echo "CANARY_ADMIN_UI_IMAGE_BUILD=PASS"
cat > "$OVERRIDE" <<EOF
services:
  xtream-vod-admin:
    image: $UI_IMAGE
EOF

compose() {
  sudo env CANARY_DIR="$ROOT" CANARY_IMAGE="$BASE_IMAGE" \
    docker compose --project-name xtream-vod-canary \
      -f "$BASE_COMPOSE" -f "$OVERRIDE" "$@"
}
rollback() {
  echo "ROLLBACK_CANARY_ADMIN_STARTED"
  rm -f "$OVERRIDE"
  sudo env CANARY_DIR="$ROOT" CANARY_IMAGE="$BASE_IMAGE" \
    docker compose --project-name xtream-vod-canary \
      -f "$BASE_COMPOSE" up -d --no-deps --no-build --force-recreate xtream-vod-admin
  echo "CANARY_ADMIN_PREVIOUS_IMAGE_RESTORED"
}
if ! compose config -q; then
  rm -f "$OVERRIDE"
  echo "STOP: Canary Compose validation failed"; exit 1
fi
if ! compose up -d --no-deps --no-build --force-recreate xtream-vod-admin; then
  rollback; exit 1
fi
HEALTH=starting
for _ in $(seq 1 45); do
  HEALTH=$(sudo docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' xtream-vod-canary-admin)
  test "$HEALTH" = healthy && break
  test "$HEALTH" = unhealthy && break
  sleep 2
done
if [ "$HEALTH" != healthy ]; then
  echo "CANARY_ADMIN_HEALTH=$HEALTH"; rollback; exit 1
fi
if ! sudo docker exec -i xtream-vod-canary-admin python - <<'PY'
import urllib.request
base = "http://127.0.0.1:8768/"
def get(path):
    with urllib.request.urlopen(base + path, timeout=8) as response:
        assert response.status == 200
        return response.read(200000).decode()
html = get("")
javascript = get("assets/workspace.js")
assert 'id="personalWorkspace"' in html
assert 'id="adminWorkspace"' in html
assert 'id="personalSourceForm"' in html
assert 'id="personalManifestForm"' in html
assert "window.VODWorkspace = {" in javascript
print("CANARY_ADMIN_UI_HTTP=PASS")
PY
then
  echo "STOP: Canary Admin static smoke failed"; rollback; exit 1
fi
test "$(sudo docker inspect -f '{{.Id}}' xtream-vod-bridge)" = "$PROD_P"
test "$(sudo docker inspect -f '{{.Id}}' xtream-vod-admin)" = "$PROD_A"
test "$(sudo docker inspect -f '{{.Id}}' xtream-vod-canary-playback)" = "$CANARY_P"
echo "PRODUCTION_CONTAINER_IDS_UNCHANGED=PASS"
echo "CANARY_PLAYBACK_UNCHANGED=PASS"
echo "CANARY_ADMIN_HEALTH=healthy"
echo "CANARY_UI_STAGE=READY_OFFLINE"
echo "CANARY_INGRESS=NONE"
echo "CANARY_SECRETS=UNCHANGED"
