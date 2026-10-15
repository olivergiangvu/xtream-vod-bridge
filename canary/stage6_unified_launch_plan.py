#!/usr/bin/env python3
"""Stage M3.1 - read-only plan for ONE temporary unified Canary container.

Validate the locally built immutable image, stopped 2-service Canary, unchanged
Production, strict resource/egress/network isolation, isolated data snapshot
feasibility and effective Compose. NO Docker mutation, no secret disclosure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from urllib.request import Request, build_opener, ProxyHandler

REF = "14aaad4e705bb0f2fc28b2bbbd8280c5e19cd86c"
COMPOSE_BLOB = "32da1db31ac09e746245eebdf10b8f18ebe54da3"
COMPOSE_PATH = "canary/unified-compose.yaml"

ROOT = Path("/opt/xtream-vod-canary")
SOURCE_DATA = ROOT / "data"
TARGET_DATA = ROOT / "unified-data"
IMAGE = "homedocker/xtream-vod-unified-canary:0.6.0-cab39cd806cd"
NAME = "xtream-vod-unified-canary"
PROJECT = "xtream-vod-unified-canary"
NETWORK = PROJECT + "_unified_private"
OLD = {
    "xtream-vod-canary-admin":
        "homedocker/xtream-vod-canary-admin:0.5e-cookie-e153b327b49f",
    "xtream-vod-canary-playback":
        "homedocker/xtream-vod-canary:5c2f02233a0f",
}
PROD = {
    "xtream-vod-admin": "homedocker/xtream-vod-admin:0.4.3-manifest",
    "xtream-vod-bridge": "homedocker/xtream-vod-bridge:0.4.0",
}
PINNED = {
    "/opt/xtream-vod-canary/src/canary/compose.yaml":
        "bbbc26eaf33fd8005aff5f1e0e58ae4912bed6cd56fe96cb407b1ce4ea9de354",
    "/opt/xtream-vod-canary/ui-override.yaml":
        "eab5db9b32c81dd7d22ddfbd00c86b2fec9d927e8281120eafe2628025927bda",
    "/etc/nginx/conf.d/xtream-vod-bridge-18450.conf":
        "8746edfcc5b899ee8c4381c0890d203b0dd3aada33390eab0d389cc54faedd35",
}
MAX_COPY_BYTES = 512 * 1024 * 1024
MAX_COPY_FILES = 10000


def require(value: bool, code: str) -> None:
    if not value:
        raise ValueError(code)


def run(argv, env=None, timeout=40):
    proc = subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=timeout, env=env
    )
    require(proc.returncode == 0, "COMMAND_FAILED_" + argv[0])
    return proc.stdout


def inspect(name: str):
    items = json.loads(run(["docker", "inspect", name]))
    require(len(items) == 1, "INSPECT_COUNT_INVALID_" + name)
    return items[0]


def git_blob(raw: bytes):
    return hashlib.sha1(
        b"blob " + str(len(raw)).encode() + b"\x00" + raw
    ).hexdigest()


def check_protected():
    for name, expected in PINNED.items():
        path = Path(name)
        require(path.is_file() and not path.is_symlink(),
                "PINNED_FILE_MISSING_" + path.name)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        require(digest == expected, "PINNED_FILE_CHANGED_" + path.name)
    print("LEGACY_COMPOSE_OVERRIDE_AND_NGINX=UNCHANGED")


def check_containers():
    ids = {}
    for name, image in PROD.items():
        obj = inspect(name)
        state = obj["State"]
        require(obj["Config"]["Image"] == image, "PRODUCTION_IMAGE_CHANGED")
        require(state.get("Running") and
                (state.get("Health") or {}).get("Status") == "healthy",
                "PRODUCTION_NOT_HEALTHY_" + name)
        ids[name] = obj["Id"]
    print("PRODUCTION_IDS_AND_HEALTH=VERIFIED")

    for name, image in OLD.items():
        obj = inspect(name)
        require(obj["Config"]["Image"] == image, "OLD_CANARY_IMAGE_CHANGED")
        require(not obj["State"]["Running"], "OLD_CANARY_RUNNING")
        require(obj["Config"].get("Labels", {}).get(
            "com.docker.compose.project") == "xtream-vod-canary",
            "OLD_CANARY_PROJECT_CHANGED")
    print("OLD_CANARY_BOTH_STOPPED=PASS")

    existing = subprocess.run(
        ["docker", "container", "inspect", NAME],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20
    )
    require(existing.returncode != 0, "UNIFIED_CANARY_CONTAINER_ALREADY_EXISTS")
    existing_net = subprocess.run(
        ["docker", "network", "inspect", NETWORK],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20
    )
    require(existing_net.returncode != 0, "UNIFIED_NETWORK_ALREADY_EXISTS")
    print("UNIFIED_CANARY_NAME_AND_NETWORK=AVAILABLE")
    return ids


def verify_image():
    data = json.loads(run(["docker", "image", "inspect", IMAGE]))
    require(len(data) == 1, "UNIFIED_IMAGE_NOT_UNIQUE")
    info = data[0]
    cmd = info.get("Config", {}).get("Cmd") or []
    require("unified_app:application" in cmd, "UNIFIED_IMAGE_ENTRYPOINT_NOT_UNIFIED")
    require("8767" in cmd, "UNIFIED_IMAGE_PORT_INVALID")
    env = info.get("Config", {}).get("Env") or []
    require("XTREAM_UNIFIED_MODE=1" in env, "UNIFIED_MODE_NOT_ENABLED")
    print("UNIFIED_LOCAL_IMAGE_AND_ONE_PROCESS_CMD=VERIFIED")


def source_snapshot_inventory():
    require(SOURCE_DATA.is_dir() and not SOURCE_DATA.is_symlink(),
            "SOURCE_DATA_DIR_INVALID")
    require(not TARGET_DATA.exists() and not TARGET_DATA.is_symlink(),
            "UNIFIED_DATA_TARGET_ALREADY_EXISTS")
    size = 0
    count = 0
    for directory, subdirs, files in os.walk(SOURCE_DATA, followlinks=False):
        for name in subdirs + files:
            path = Path(directory) / name
            mode = path.lstat().st_mode
            require(stat.S_ISDIR(mode) or stat.S_ISREG(mode),
                    "SOURCE_DATA_UNSAFE_SPECIAL_OR_LINK")
            if stat.S_ISREG(mode):
                size += path.stat().st_size
                count += 1
                require(size <= MAX_COPY_BYTES and count <= MAX_COPY_FILES,
                        "SOURCE_DATA_EXCEEDS_BOUNDED_CLONE")
    require((ROOT / "secrets/canary.env").is_file(),
            "CANARY_ENV_SOURCE_MISSING")
    print("ISOLATED_CANARY_DATA_COPY=FEASIBLE")
    print("SOURCE_CANARY_DATA_SIZE_MIB=" + str(round(size / 1048576, 2)))
    print("SOURCE_CANARY_FILE_COUNT=" + str(count))
    return size


def download_compose(folder: Path):
    url = ("https://raw.githubusercontent.com/olivergiangvu/xtream-vod-bridge/"
           + REF + "/" + COMPOSE_PATH)
    opener = build_opener(ProxyHandler({}))
    with opener.open(Request(url), timeout=30) as response:
        raw = response.read(100000)
    require(git_blob(raw) == COMPOSE_BLOB, "UNIFIED_COMPOSE_GIT_SHA_MISMATCH")
    source = folder / "unified-compose.yaml"
    source.write_bytes(raw)
    source.chmod(0o600)
    print("UNIFIED_COMPOSE_IMMUTABLE_SOURCE=PASS")
    return source


def effective(source: Path):
    env = os.environ.copy()
    env["CANARY_DIR"] = str(ROOT)
    env["CANARY_UNIFIED_IMAGE"] = IMAGE
    cmd = [
        "docker", "compose", "-p", PROJECT,
        "--project-directory", str(ROOT), "-f", str(source),
        "config", "--format", "json",
    ]
    return json.loads(run(cmd, env=env, timeout=45))


def check_effective(cfg):
    services = cfg.get("services")
    require(isinstance(services, dict) and set(services) == {"xtream-unified"},
            "COMPOSE_NOT_EXACTLY_ONE_SERVICE")
    svc = services["xtream-unified"]
    require(svc.get("container_name") == NAME and svc.get("image") == IMAGE,
            "COMPOSE_CONTAINER_OR_IMAGE_MISMATCH")
    require(svc.get("restart") == "no" and svc.get("pull_policy") == "never",
            "COMPOSE_RESTART_OR_PULL_POLICY_UNSAFE")
    require(not svc.get("ports") and not svc.get("network_mode") and
            not svc.get("privileged"), "COMPOSE_EXTERNAL_EXPOSURE")
    require(svc.get("read_only") is True, "COMPOSE_NOT_READ_ONLY")
    require("ALL" in svc.get("cap_drop", []), "COMPOSE_CAPS_NOT_DROPPED")
    require(any("no-new-privileges:true" == str(x)
                for x in svc.get("security_opt", [])),
            "COMPOSE_PRIVILEGE_PROTECTION_MISSING")
    require(float(svc.get("cpus", 0)) == 0.5, "COMPOSE_CPU_CAP_MISMATCH")
    require(str(svc.get("mem_limit")) in ("256m", "268435456"),
            "COMPOSE_RAM_CAP_MISMATCH")
    require(int(svc.get("pids_limit", 0)) == 64, "COMPOSE_PIDS_CAP_MISMATCH")
    command = svc.get("command") or []
    require("unified_app:application" in command and "8767" in command,
            "COMPOSE_UNIFIED_COMMAND_INVALID")
    health = svc.get("healthcheck") or {}
    require("/live" in " ".join(str(x) for x in health.get("test", [])),
            "COMPOSE_HEALTH_NOT_CONSTANT_TIME")
    require(not svc.get("depends_on"), "COMPOSE_HAS_EXTRA_SERVICE")
    env = svc.get("environment") or {}
    expected_env = {
        "XTREAM_UNIFIED_MODE": "1",
        "LEGACY_SYNC_ENABLED": "0",
        "XTREAM_URL_PREFIX": "/canary",
        "XTREAM_SESSION_COOKIE": "xtream_canary_admin_session",
        "XTREAM_LOGIN_NONCE_COOKIE": "xtream_canary_login_nonce",
        "ADMIN_PUBLIC_ORIGIN": "https://olivergiangvu.asuscomm.com:18450",
        "PUBLIC_BASE_URL": "https://olivergiangvu.asuscomm.com:18450/canary",
    }
    for key, value in expected_env.items():
        require(env.get(key) == value, "COMPOSE_REQUIRED_ENV_INVALID_" + key)
    volumes = svc.get("volumes") or []
    require(len(volumes) == 1 and
            volumes[0].get("type") == "bind" and
            volumes[0].get("source") == str(TARGET_DATA) and
            volumes[0].get("target") == "/data",
            "COMPOSE_DATA_MOUNT_NOT_ISOLATED")
    networks = svc.get("networks") or {}
    require(set(networks) == {"unified_private"}, "COMPOSE_EXTRA_NETWORK")
    network = (cfg.get("networks") or {}).get("unified_private") or {}
    require(network.get("internal") is True and
            network.get("name") == NETWORK, "COMPOSE_NETWORK_NOT_PRIVATE")
    print("UNIFIED_COMPOSE_ONE_SERVICE_ONLY=PASS")
    print("UNIFIED_CPU_CAP=0.5_CORE")
    print("UNIFIED_RAM_CAP=256_MIB")
    print("UNIFIED_HEALTHCHECK=LIVE_ONLY")
    print("UNIFIED_NETWORK_PRIVATE_INTERNAL=PASS")
    print("UNIFIED_PUBLISHED_HOST_PORTS=NONE")
    print("UNIFIED_SEPARATE_DATA_MOUNT=PASS")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", action="store_true",
                        help="read-only; this script has no apply mode")
    parser.parse_args()
    require(os.geteuid() == 0, "REQUIRES_SUDO")
    check_protected()
    baseline = check_containers()
    verify_image()
    source_snapshot_inventory()
    with tempfile.TemporaryDirectory(prefix="unified-canary-plan-") as temp:
        folder = Path(temp)
        folder.chmod(0o700)
        source = download_compose(folder)
        cfg = effective(source)
        check_effective(cfg)
    for name, original in baseline.items():
        require(inspect(name)["Id"] == original, "PRODUCTION_ID_DRIFT")
    print("PRODUCTION_UNCHANGED_AFTER_PLAN=PASS")
    print("M3_UNIFIED_LAUNCH_PLAN=PASS")
    print("LIVE_CONTAINERS_COMPOSE_NGINX_MODIFIED=NONE")
    print("RECREATE_OR_START_APPROVAL=NO")
    print("NEXT=REVIEW_SEPARATE_ONE_CANARY_ATOMIC_APPLY_AND_ROLLBACK")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print("STOP: M3 unified launch: " + str(exc))
        raise SystemExit(1) from None
