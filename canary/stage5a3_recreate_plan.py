#!/usr/bin/env python3
"""Stage 5A.3 Canary recreate candidate / rollback readiness, read-only.

No Compose edits, backups, container starts/stops/recreate, Docker builds,
nginx reloads or provider requests. Never print effective Compose, env or
SQLite contents. The proposed override is held in a private temporary file.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

ROOT = Path("/opt/xtream-vod-canary")
BASE = ROOT / "src/canary/compose.yaml"
OVERRIDE = ROOT / "ui-override.yaml"
VHOST = Path("/etc/nginx/conf.d/xtream-vod-bridge-18450.conf")
ROLLBACK_BASE = Path(
    "/etc/homedocker-backup/xtream-canary-compose-stage4f/"
    "compose-1791997336938636057-before-ports.yaml"
)
BASE_SHA = "bbbc26eaf33fd8005aff5f1e0e58ae4912bed6cd56fe96cb407b1ce4ea9de354"
OVERRIDE_SHA = "eab5db9b32c81dd7d22ddfbd00c86b2fec9d927e8281120eafe2628025927bda"
VHOST_SHA = "8746edfcc5b899ee8c4381c0890d203b0dd3aada33390eab0d389cc54faedd35"
ROLLBACK_BASE_SHA = "79d4cb76db03ae881769339e4e2b851e1c68c1e1bb6133a62661dbdbca49a42e"
PLAY_IMAGE = "homedocker/xtream-vod-canary:5c2f02233a0f"
OLD_ADMIN = "homedocker/xtream-vod-canary-admin:0.5e-cookie-e153b327b49f"
NEW_ADMIN = "homedocker/xtream-vod-canary-admin:0.5g-prefix-206cf27063b8"
ORIGIN = "https://olivergiangvu.asuscomm.com:18450"
CANARY_PUBLIC = ORIGIN + "/canary"
NETWORK = "xtream-vod-canary_private_canary"
EXPECTED_IMAGES = {
    "xtream-vod-admin": "homedocker/xtream-vod-admin:0.4.3-manifest",
    "xtream-vod-bridge": "homedocker/xtream-vod-bridge:0.4.0",
    "xtream-vod-canary-admin": OLD_ADMIN,
    "xtream-vod-canary-playback": PLAY_IMAGE,
}
CANDIDATE = (
    "services:\n"
    "  xtream-vod-bridge:\n"
    "    environment:\n"
    "      PUBLIC_BASE_URL: " + CANARY_PUBLIC + "\n"
    "  xtream-vod-admin:\n"
    "    image: " + NEW_ADMIN + "\n"
    "    environment:\n"
    "      XTREAM_URL_PREFIX: /canary\n"
    "      XTREAM_SESSION_COOKIE: xtream_canary_admin_session\n"
    "      XTREAM_LOGIN_NONCE_COOKIE: xtream_canary_login_nonce\n"
    "      XTREAM_GATEWAY_REFERRER_POLICY: same-origin\n"
    "      ADMIN_PUBLIC_ORIGIN: " + ORIGIN + "\n"
    "      PUBLIC_BASE_URL: " + CANARY_PUBLIC + "\n"
)
APPROVED_ENV_CHANGES = {
    "xtream-vod-admin": {
        "XTREAM_URL_PREFIX": "/canary",
        "XTREAM_SESSION_COOKIE": "xtream_canary_admin_session",
        "XTREAM_LOGIN_NONCE_COOKIE": "xtream_canary_login_nonce",
        "XTREAM_GATEWAY_REFERRER_POLICY": "same-origin",
        "ADMIN_PUBLIC_ORIGIN": ORIGIN,
        "PUBLIC_BASE_URL": CANARY_PUBLIC,
    },
    "xtream-vod-bridge": {"PUBLIC_BASE_URL": CANARY_PUBLIC},
}


def stop(reason):
    raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def run(*command, env=None, timeout=35):
    result = subprocess.run(
        command, capture_output=True, text=True, env=env, timeout=timeout
    )
    if result.returncode:
        stop("Read-only command failed: " + command[0])
    return result.stdout


def check_files():
    for path, expected in (
        (BASE, BASE_SHA),
        (OVERRIDE, OVERRIDE_SHA),
        (VHOST, VHOST_SHA),
        (ROLLBACK_BASE, ROLLBACK_BASE_SHA),
    ):
        if not path.is_file() or path.is_symlink():
            stop("Expected file missing/symlink: " + path.name)
        if sha(path.read_bytes()) != expected:
            stop("File SHA256 changed: " + path.name)
    backup = ROLLBACK_BASE.stat()
    if backup.st_uid != 0 or stat.S_IMODE(backup.st_mode) & 0o077:
        stop("Stage4F backup ownership/permissions unsafe")
    if not (ROOT / "data").is_dir():
        stop("Canary data bind path missing")


def config(override_path):
    env = os.environ.copy()
    env.update(CANARY_DIR=str(ROOT), CANARY_IMAGE=PLAY_IMAGE)
    return json.loads(run(
        "docker", "compose", "-p", "xtream-vod-canary",
        "--project-directory", str(BASE.parent),
        "-f", str(BASE), "-f", str(override_path),
        "config", "--format", "json", env=env
    ))


def check_composed(before, after):
    if not isinstance(before, dict) or not isinstance(after, dict):
        stop("Invalid Compose JSON")
    services = {"xtream-vod-admin", "xtream-vod-bridge"}
    if set(before.get("services", {})) != services or set(after.get("services", {})) != services:
        stop("Unexpected Compose service inventory")
    if set(before.get("networks", {})) != {"private_canary"}:
        stop("Unexpected original network inventory")
    net = before["networks"]["private_canary"]
    if net.get("internal") is not True or net.get("external"):
        stop("Original Canary network not internal")
    if net.get("name") != NETWORK:
        stop("Unexpected Canary network name")

    predicted = copy.deepcopy(before)
    for service in services:
        old = before["services"][service]
        new = after["services"][service]
        desired_image = OLD_ADMIN if service == "xtream-vod-admin" else PLAY_IMAGE
        if old.get("image") != desired_image:
            stop("Canary Compose source image mismatch: " + service)
        if new.get("ports") or old.get("ports") or new.get("publish_all_ports"):
            stop("Canary host ports would be exposed: " + service)
        if new.get("network_mode") or old.get("network_mode"):
            stop("Canary network mode differs: " + service)
        for conf in (new, old):
            networks = conf.get("networks") or {}
            if set(networks) != {"private_canary"}:
                stop("Canary service attached to unexpected network: " + service)
            if conf.get("read_only") is not True or "ALL" not in (conf.get("cap_drop") or []):
                stop("Canary service missing filesystem/cap security: " + service)
            if conf.get("privileged") or conf.get("devices") or conf.get("pid") == "host":
                stop("Privileged Canary service not allowed: " + service)
            if not any(
                str(x).replace("=", ":") == "no-new-privileges:true"
                for x in conf.get("security_opt", [])
            ):
                stop("Canary no-new-privileges missing: " + service)
        if service == "xtream-vod-admin":
            predicted["services"][service]["image"] = NEW_ADMIN
        old_env = old.get("environment")
        if not isinstance(old_env, dict):
            stop("Canary environment missing; stop without logging secrets")
        values = APPROVED_ENV_CHANGES[service]
        predicted["services"][service]["environment"].update(values)
    if predicted != after:
        stop("Candidate changes fields beyond the approved image and environment keys")
    return True


def check_container(name, image):
    objects = json.loads(run("docker", "inspect", name))
    if len(objects) != 1:
        stop("Unexpected container inventory: " + name)
    item = objects[0]
    if item.get("Config", {}).get("Image") != image:
        stop("Container image drift: " + name)
    if item.get("State", {}).get("Health", {}).get("Status") != "healthy":
        stop("Unhealthy container: " + name)
    return item


def check_live():
    ids = {}
    for name, image in EXPECTED_IMAGES.items():
        obj = check_container(name, image)
        ids[name] = obj["Id"]
        if name.startswith("xtream-vod-canary-"):
            labels = obj.get("Config", {}).get("Labels") or {}
            if labels.get("com.docker.compose.project") != "xtream-vod-canary":
                stop("Canary Compose ownership mismatch")
            joined = obj.get("NetworkSettings", {}).get("Networks") or {}
            if set(joined) != {NETWORK}:
                stop("Canary runtime network membership drift")
            actual_ports = obj.get("NetworkSettings", {}).get("Ports") or {}
            if any(port is not None for port in actual_ports.values()):
                stop("Canary has live host port publication")
            if run("docker", "port", name).strip():
                stop("Canary runtime reports host port publication")
            for values in (obj.get("HostConfig", {}).get("PortBindings") or {}).values():
                for binding in values or []:
                    try:
                        if not ipaddress.ip_address(binding["HostIp"]).is_loopback:
                            stop("Canary dormant binding is not loopback")
                    except (KeyError, ValueError, TypeError) as exc:
                        raise ValueError("Malformed Canary dormant port binding") from exc
    nets = json.loads(run("docker", "network", "inspect", NETWORK))
    if len(nets) != 1 or nets[0].get("Internal") is not True:
        stop("Canary live Docker network not internal")
    for img in (NEW_ADMIN, OLD_ADMIN, PLAY_IMAGE):
        image = json.loads(run("docker", "image", "inspect", img, timeout=20))
        if len(image) != 1:
            stop("Docker image absent: " + img)
    return ids


def psi10():
    data = Path("/proc/pressure/cpu").read_text()
    m = re.search(r"(?m)^some\s+avg10=([0-9.]+)", data)
    return float(m.group(1)) if m else None


def main():
    if os.geteuid() != 0:
        stop("Run read-only plan under sudo to inspect root-owned Compose and Docker")
    check_files()
    before = config(OVERRIDE)
    with tempfile.TemporaryDirectory(prefix="xtream-stage5a3-") as directory:
        os.chmod(directory, 0o700)
        candidate = Path(directory) / "ui-override.yaml"
        candidate.write_text(CANDIDATE, encoding="utf-8")
        candidate.chmod(0o600)
        after = config(candidate)
        check_composed(before, after)
    ids = check_live()
    print("STAGE5A3_RECREATE_PLAN=PASS")
    print("BASE_COMPOSE_STAGE4F_SHA=PASS")
    print("OVERRIDE_STAGE4A_SHA=PASS")
    print("PRODUCTION_NGINX_SHA=PASS")
    print("CANARY_OLD_AND_NEW_IMAGES=LOCAL")
    print("ROLLBACK_BASE_BACKUP=VERIFIED")
    print("PROPOSED_OVERRIDE_SHA256=" + sha(CANDIDATE.encode("utf-8")))
    print("EFFECTIVE_CONFIG_ONLY_ALLOWLISTED_CHANGES=PASS")
    print("PROPOSED_EFFECTIVE_HOST_PORTS=NONE")
    print("CANARY_NETWORK_PRIVATE_INTERNAL=PASS")
    print("PRODUCTION_AND_CANARY_HEALTH=PASS")
    print("CPU_PSI_AVG10_NOW=" + (
        f"{psi10():.2f}" if psi10() is not None else "UNKNOWN"
    ))
    print("CONTAINER_ID_BASELINE_RECORDED_IN_MEMORY=PASS")
    print("ROLLBACK_REQUIREMENTS=BACKUP_OVERRIDE_AND_CHECK_HEALTH_AFTER_RECREATE")
    print("NGINX_RELOAD_OR_DOCKER_RECREATE=NONE")
    print("RECREATE_APPROVAL=NO")
    print("NEXT=REVIEW_STAGE5A3_ATOMIC_RECREATE_AND_VERIFIED_ROLLBACK")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print("STOP: Stage 5A.3 read-only plan failed: " + str(error))
        raise SystemExit(1) from None
