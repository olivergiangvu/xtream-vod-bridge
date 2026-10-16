#!/usr/bin/env python3
"""HomeDocker Stage 5A readiness: read-only, fail-closed.

Checks the post-Stage4F Canary Compose, the original rollback image+backup,
live isolated Docker runtime and current CPU pressure. No edits/restarts/builds.
Never prints decrypted environment, private files, credentials or nginx source.
"""
from __future__ import annotations
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time

ROOT = Path("/opt/xtream-vod-canary")
BASE = ROOT / "src/canary/compose.yaml"
OVERRIDE = ROOT / "ui-override.yaml"
VHOST = Path("/etc/nginx/conf.d/xtream-vod-bridge-18450.conf")
BACKUP = Path("/etc/homedocker-backup/xtream-canary-compose-stage4f/compose-1791997336938636057-before-ports.yaml")
EXPECTED_SHA = {
    BASE: "bbbc26eaf33fd8005aff5f1e0e58ae4912bed6cd56fe96cb407b1ce4ea9de354",
    OVERRIDE: "eab5db9b32c81dd7d22ddfbd00c86b2fec9d927e8281120eafe2628025927bda",
    VHOST: "8746edfcc5b899ee8c4381c0890d203b0dd3aada33390eab0d389cc54faedd35",
    BACKUP: "79d4cb76db03ae881769339e4e2b851e1c68c1e1bb6133a62661dbdbca49a42e",
}
PLAY_IMAGE = "homedocker/xtream-vod-canary:5c2f02233a0f"
ADMIN_IMAGE = "homedocker/xtream-vod-canary-admin:0.5e-cookie-e153b327b49f"
NETWORK = "xtream-vod-canary_private_canary"
CONTAINERS = {
    "xtream-vod-canary-admin": ADMIN_IMAGE,
    "xtream-vod-canary-playback": PLAY_IMAGE,
    "xtream-vod-admin": "homedocker/xtream-vod-admin:0.4.3-manifest",
    "xtream-vod-bridge": "homedocker/xtream-vod-bridge:0.4.0",
}
SERVICES = {
    "xtream-vod-admin": ("xtream-vod-canary-admin", ADMIN_IMAGE),
    "xtream-vod-bridge": ("xtream-vod-canary-playback", PLAY_IMAGE),
}
OVERRIDE_BASELINE = (
    "services:\n  xtream-vod-admin:\n"
    + "    image: " + ADMIN_IMAGE + "\n"
    + "    environment:\n"
    + "      XTREAM_SESSION_COOKIE: xtream_canary_admin_session\n"
    + "      XTREAM_LOGIN_NONCE_COOKIE: xtream_canary_login_nonce\n"
    + "      XTREAM_GATEWAY_REFERRER_POLICY: same-origin\n"
    + "      ADMIN_PUBLIC_ORIGIN: https://olivergiangvu.asuscomm.com:18451\n"
    + "      PUBLIC_BASE_URL: https://olivergiangvu.asuscomm.com:18451\n"
)

def stop(problem):
    raise ValueError(problem)

def execute(*args, env=None):
    process = subprocess.run(args, capture_output=True, text=True,
                             timeout=30, env=env)
    if process.returncode:
        stop("Read-only command failed: " + str(args[0]))
    return process.stdout

def check_files():
    for path, expected in EXPECTED_SHA.items():
        if not path.is_file() or path.is_symlink():
            stop("Missing or symlinked trusted file: " + path.name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            stop("File SHA drift: " + path.name)
    if OVERRIDE.read_text(encoding="utf-8") != OVERRIDE_BASELINE:
        stop("Stage 4A Canary override drifted")
    backup = BACKUP.stat()
    if backup.st_uid != 0 or stat.S_IMODE(backup.st_mode) & 0o077:
        stop("Stage4F backup must be root-owned and not group/world-readable")
    return True

def check_effective_compose(cfg):
    if not isinstance(cfg, dict):
        stop("Effective Docker Compose invalid")
    services = cfg.get("services")
    nets = cfg.get("networks")
    if not isinstance(services, dict) or set(services) != set(SERVICES):
        stop("Compose service set differs")
    if not isinstance(nets, dict) or set(nets) != {"private_canary"}:
        stop("Unexpected Compose networks")
    network = nets["private_canary"]
    if not isinstance(network, dict) or network.get("internal") is not True:
        stop("Effective Canary network is not internal")
    if network.get("external") or network.get("name") != NETWORK:
        stop("Effective Canary network name/isolation changed")

    for service, (name, image) in SERVICES.items():
        conf = services[service]
        if conf.get("image") != image or conf.get("container_name") != name:
            stop("Compose image/name drift: " + service)
        if conf.get("ports") or conf.get("publish_all_ports"):
            stop("Canary Compose still publishes ports: " + service)
        members = conf.get("networks")
        if isinstance(members, dict):
            members = set(members)
        elif isinstance(members, list):
            members = set(members)
        else:
            members = set()
        if members != {"private_canary"} or conf.get("network_mode"):
            stop("Canary Compose network membership differs: " + service)
        if conf.get("read_only") is not True or "ALL" not in (conf.get("cap_drop") or []):
            stop("Canary filesystem/capability protection changed: " + service)
        if not any(str(option).replace("=", ":") == "no-new-privileges:true"
                   for option in conf.get("security_opt", [])):
            stop("Canary no-new-privileges missing: " + service)
        if conf.get("privileged") or conf.get("devices") or conf.get("pid") == "host":
            stop("Canary unexpectedly privileged: " + service)
        if conf.get("restart") not in (None, "no"):
            stop("Canary restart policy changed: " + service)
        volumes = conf.get("volumes")
        if not isinstance(volumes, list) or len(volumes) != 1:
            stop("Unexpected Canary mounts: " + service)
        mount = volumes[0]
        if (mount.get("type") != "bind"
            or mount.get("target") != "/data"
            or Path(mount.get("source", "/missing")).resolve()
               != (ROOT / "data").resolve()):
            stop("Canary Compose mount not restricted to data: " + service)
    return True

def check_live_ports(obj, name):
    actual = obj.get("NetworkSettings", {}).get("Ports") or {}
    if not isinstance(actual, dict) or any(v is not None for v in actual.values()):
        stop("Canary currently has published host port: " + name)
    if execute("docker", "port", name).strip():
        stop("Docker port reports published host port: " + name)
    configured = obj.get("HostConfig", {}).get("PortBindings") or {}
    if not isinstance(configured, dict):
        stop("Canary PortBindings invalid: " + name)
    count = 0
    for port, values in configured.items():
        if not re.fullmatch(r"\d{1,5}/(?:tcp|udp)", port):
            stop("Malformed Canary configured port: " + name)
        if values is None:
            continue
        if not isinstance(values, list):
            stop("Malformed Canary PortBindings: " + name)
        for bind in values:
            if not isinstance(bind, dict):
                stop("Malformed Canary binding: " + name)
            host_ip = bind.get("HostIp")
            host_port = bind.get("HostPort")
            try:
                if not ipaddress.ip_address(host_ip).is_loopback:
                    raise ValueError()
                if not isinstance(host_port, str) or not host_port.isascii():
                    raise ValueError()
                if not host_port.isdecimal() or not 1 <= int(host_port) <= 65535:
                    raise ValueError()
            except (ValueError, TypeError):
                stop("Unsafe dormant Canary host bind: " + name)
            count += 1
    return count

def inspect_live():
    objects = {}
    for name, expected in CONTAINERS.items():
        matches = json.loads(execute("docker", "inspect", name))
        if len(matches) != 1:
            stop("Missing Docker container: " + name)
        item = matches[0]
        if item.get("Config", {}).get("Image") != expected:
            stop("Running Docker image drift: " + name)
        if item.get("State", {}).get("Health", {}).get("Status") != "healthy":
            stop("Running Docker health not ready: " + name)
        objects[name] = item
    net = json.loads(execute("docker", "network", "inspect", NETWORK))
    if len(net) != 1 or net[0].get("Internal") is not True:
        stop("Live Canary Docker network is not internal")
    dormant = 0
    for name in ("xtream-vod-canary-admin", "xtream-vod-canary-playback"):
        item = objects[name]
        labels = item.get("Config", {}).get("Labels") or {}
        if labels.get("com.docker.compose.project") != "xtream-vod-canary":
            stop("Canary Compose project ownership drift: " + name)
        attached = item.get("NetworkSettings", {}).get("Networks") or {}
        if set(attached) != {NETWORK}:
            stop("Canary attached to unexpected Docker network: " + name)
        ip = attached[NETWORK].get("IPAddress")
        try:
            if ipaddress.ip_address(ip).version != 4:
                raise ValueError()
        except ValueError:
            stop("Canary lacks expected Docker IPv4: " + name)
        dormant += check_live_ports(item, name)
    for image in (ADMIN_IMAGE, PLAY_IMAGE):
        _ = json.loads(execute("docker", "image", "inspect", image))
    return dormant

def pressure_avg10():
    row = next(
        (line for line in Path("/proc/pressure/cpu").read_text().splitlines()
         if line.startswith("some ")), ""
    )
    match = re.search(r"\bavg10=([0-9.]+)", row)
    return float(match.group(1)) if match else None

def main():
    check_files()
    docker_env = os.environ.copy()
    docker_env.update(CANARY_DIR=str(ROOT), CANARY_IMAGE=PLAY_IMAGE)
    effective = json.loads(execute(
        "docker", "compose", "-p", "xtream-vod-canary",
        "-f", str(BASE), "-f", str(OVERRIDE),
        "config", "--format", "json", env=docker_env))
    check_effective_compose(effective)
    dormant = inspect_live()

    first = pressure_avg10()
    time.sleep(10)
    last = pressure_avg10()
    # Sustained PSI >30% caused intermittent 5-second Docker health timeouts
    # on this 2-vCPU host. Prevent build/recreate until contention subsides.
    cpu_ready = (first is not None and last is not None
                 and first < 30 and last < 30)
    print("STAGE5A_READONLY_PREFLIGHT=PASS")
    print("STAGE4F_BASE_SHA256=PASS")
    print("STAGE4A_OVERRIDE_AND_BACKUP=PASS")
    print("PRODUCTION_VHOST_SHA256_UNCHANGED=PASS")
    print("EFFECTIVE_COMPOSE_PUBLIC_PORTS=NONE")
    print("EFFECTIVE_CANARY_NETWORK=PRIVATE_INTERNAL")
    print("CANARY_ROLLBACK_IMAGES_LOCAL=PASS")
    print("PRODUCTION_AND_CANARY_HEALTH=PASS")
    print("CANARY_LIVE_HOST_PORTS=NONE")
    print("DORMANT_PRE_RECREATE_PORT_BINDINGS=" + str(dormant))
    print("CPU_PSI_AVG10_FIRST=" + (f"{first:.2f}" if first is not None else "UNKNOWN"))
    print("CPU_PSI_AVG10_LAST=" + (f"{last:.2f}" if last is not None else "UNKNOWN"))
    print("CPU_READY_FOR_BUILD_AND_RECREATE=" + ("YES" if cpu_ready else "NO"))
    print("PRODUCTION_OR_CANARY_MODIFICATIONS=NONE")
    print("APPROVAL_FOR_RECREATE=NO")
    print("NEXT=" + (
        "REVIEW_UPGRADE_ROLLBACK_AND_GET_RECREATE_APPROVAL"
        if cpu_ready else "CPU_PRESSURE_NOT_READY_PAUSE_IMAGE_BUILD"
    ))

if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print("STOP: Stage 5A read-only preflight failed: " + str(exc))
        raise SystemExit(1) from None
