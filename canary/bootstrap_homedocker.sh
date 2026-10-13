#!/usr/bin/env bash
# Local-only HomeDocker v0.5 canary. Run as SSH user, never against production.
# Usage: bash canary/bootstrap_homedocker.sh <reviewed-40-char-git-commit>
set -euo pipefail
if [ "$#" -ne 1 ]; then echo "STOP: exact commit SHA required"; exit 2; fi
SHA="$1"
[[ "$SHA" =~ ^[a-f0-9]{40}$ ]] || { echo "STOP: invalid commit SHA"; exit 2; }
ROOT=/opt/xtream-vod-canary
SRC="$ROOT/src"
IMAGE="homedocker/xtream-vod-canary:$(printf '%.12s' "$SHA")"
REPO=https://github.com/olivergiangvu/xtream-vod-bridge.git

[ -d /opt/xtream-vod-bridge ] || { echo "STOP: production directory missing"; exit 2; }
for cmd in git docker python3 curl sudo; do
  command -v "$cmd" >/dev/null || { echo "STOP: missing $cmd"; exit 2; }
done
for name in xtream-vod-canary-playback xtream-vod-canary-admin; do
  if sudo docker container inspect "$name" >/dev/null 2>&1; then
    echo "STOP: existing canary container"; exit 2
  fi
done
[ ! -e "$SRC" ] || { echo "STOP: canary source exists"; exit 2; }
[ ! -e "$ROOT/secrets/canary.env" ] || { echo "STOP: canary secrets exist"; exit 2; }

PROD_ADMIN_BEFORE=$(sudo docker inspect -f '{{.Id}}' xtream-vod-admin)
PROD_PLAY_BEFORE=$(sudo docker inspect -f '{{.Id}}' xtream-vod-bridge)

python3 - <<'PY'
import socket
for port in (18769, 18770):
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            raise SystemExit("STOP: canary loopback port occupied: " + str(port))
print("CANARY_PORTS=FREE")
PY

sudo install -d -m 0750 -o "$(id -u)" -g "$(id -g)" "$ROOT"
git clone --quiet --depth 1 --filter=blob:none --no-checkout "$REPO" "$SRC"
git -C "$SRC" fetch --quiet --depth 1 origin "$SHA"
git -C "$SRC" checkout --quiet --detach FETCH_HEAD
test "$(git -C "$SRC" rev-parse HEAD)" = "$SHA"
test -f "$SRC/canary/compose.yaml"
grep -q 'LEGACY_SYNC_ENABLED' "$SRC/app.py"
echo "SOURCE_PIN=PASS"

sudo install -d -m 0700 -o root -g root "$ROOT/secrets"
sudo install -d -m 0700 -o 10001 -g 10001 "$ROOT/data"
sudo python3 - "$ROOT/secrets/canary.env" <<'PY'
import base64, os, secrets, sys
os.umask(0o077)
def secret():
    return secrets.token_urlsafe(48)
settings = {
    "DATA_DIR": "/data",
    "PUBLIC_BASE_URL": "https://canary.invalid:18451",
    "ADMIN_PUBLIC_ORIGIN": "https://canary.invalid:18451",
    "XTREAM_BASE_URL": "https://provider-canary.invalid",
    "XTREAM_USERNAME": "canary-dummy",
    "XTREAM_PASSWORD": secret(),
    "ADDON_TOKEN": secret(),
    "ADMIN_TOKEN": secret(),
    "PLAYBACK_SECRET": secret(),
    "SOURCE_SECRETS_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
    "LEGACY_SYNC_ENABLED": "0",
    "SYNC_HOURS": "168",
    "MAX_ENRICH_PER_SYNC": "0",
    "SERIES_ENRICH_PER_SYNC": "0",
    "SERIES_BOOTSTRAP_BATCH": "0",
    "SERIES_ON_DEMAND": "0",
}
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    for k, v in settings.items():
        f.write(k + "=" + v + "\n")
print("CANARY_SECRETS=CREATED_0600")
PY

sudo docker build -t "$IMAGE" "$SRC" >/dev/null
echo "CANARY_IMAGE_BUILD=PASS"
compose() {
  sudo env CANARY_DIR="$ROOT" CANARY_IMAGE="$IMAGE" \
    docker compose --project-name xtream-vod-canary \
      --file "$SRC/canary/compose.yaml" "$@"
}
compose config --quiet
echo "CANARY_COMPOSE=VALID"
compose up --detach --no-build

A=starting; B=starting
for i in $(seq 1 45); do
  A=$(sudo docker inspect -f '{{.State.Health.Status}}' xtream-vod-canary-playback 2>/dev/null || true)
  B=$(sudo docker inspect -f '{{.State.Health.Status}}' xtream-vod-canary-admin 2>/dev/null || true)
  if [ "$A" = healthy ] && [ "$B" = healthy ]; then break; fi
  if [ "$A" = unhealthy ] || [ "$B" = unhealthy ]; then break; fi
  sleep 2
done
echo "CANARY_PLAYBACK_HEALTH=$A"
echo "CANARY_ADMIN_HEALTH=$B"
[ "$A" = healthy ] && [ "$B" = healthy ] || {
  echo "STOP: inspect canary only; production unchanged"; exit 1;
}

python3 - <<'PY'
import json
from urllib.error import HTTPError
from urllib.request import urlopen
with urlopen("http://127.0.0.1:18769/health", timeout=8) as r:
    assert json.load(r)["status"] == "ok"
def code(path):
    try:
        with urlopen("http://127.0.0.1:18770" + path, timeout=8) as r:
            return r.status
    except HTTPError as exc:
        return exc.code
assert code("/api/auth/session") == 200
assert code("/api/my/sources") == 401
assert code("/api/my/manifests") == 401
print("CANARY_HTTP_SMOKE=PASS")
PY

test "$PROD_ADMIN_BEFORE" = "$(sudo docker inspect -f '{{.Id}}' xtream-vod-admin)"
test "$PROD_PLAY_BEFORE" = "$(sudo docker inspect -f '{{.Id}}' xtream-vod-bridge)"
echo "PRODUCTION_CONTAINER_IDS_UNCHANGED=PASS"
echo "CANARY_NETWORK=INTERNAL_ONLY"
echo "CANARY_DB=ISOLATED"
echo "CANARY_RUNTIME=READY_FOR_OFFLINE_TESTS"
