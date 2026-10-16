#!/usr/bin/env python3
"""Stage 4E HomeDocker Canary Compose review: read-only, no secrets printed.

Reads the EXACT two Compose inputs and resolved effective Compose JSON.
Does not start, stop, pull, create, build, edit or reload anything.
Never prints resolved environment, env_file, nginx contents or tokens.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path("/opt/xtream-vod-canary")
BASE = ROOT / "src/canary/compose.yaml"
OVERRIDE = ROOT / "ui-override.yaml"
BASE_GIT_BLOB = "ae9970661ae7d6f3f48a9717652d797fbf50a8c7"
NGINX = Path("/etc/nginx/conf.d/xtream-vod-bridge-18450.conf")
NGINX_SHA = "8746edfcc5b899ee8c4381c0890d203b0dd3aada33390eab0d389cc54faedd35"
NETWORK = "xtream-vod-canary_private_canary"
PLAY_IMAGE = "homedocker/xtream-vod-canary:5c2f02233a0f"
ADMIN_IMAGE = "homedocker/xtream-vod-canary-admin:0.5e-cookie-e153b327b49f"
PROD_IMAGES = {
    "xtream-vod-admin": "homedocker/xtream-vod-admin:0.4.3-manifest",
    "xtream-vod-bridge": "homedocker/xtream-vod-bridge:0.4.0",
}
CANARY_IMAGES = {
    "xtream-vod-canary-admin": ADMIN_IMAGE,
    "xtream-vod-canary-playback": PLAY_IMAGE,
}
SERVICES = {
    "xtream-vod-admin": ("xtream-vod-canary-admin", ADMIN_IMAGE),
    "xtream-vod-bridge": ("xtream-vod-canary-playback", PLAY_IMAGE),
}
STAGE4A_OVERRIDE = (
    "services:\n  xtream-vod-admin:\n"
    "    image: " + ADMIN_IMAGE + "\n"
    "    environment:\n"
    "      XTREAM_SESSION_COOKIE: xtream_canary_admin_session\n"
    "      XTREAM_LOGIN_NONCE_COOKIE: xtream_canary_login_nonce\n"
    "      XTREAM_GATEWAY_REFERRER_POLICY: same-origin\n"
    "      ADMIN_PUBLIC_ORIGIN: https://olivergiangvu.asuscomm.com:18451\n"
    "      PUBLIC_BASE_URL: https://olivergiangvu.asuscomm.com:18451\n"
)


def stop(message):
    raise ValueError(message)


def run(args, *, env=None):
    p = subprocess.run(args, capture_output=True, text=True, timeout=35, env=env)
    if p.returncode:
        stop("Inspection command failed: " + args[0])
    return p.stdout


def git_blob(data):
    return hashlib.sha1(
        b"blob " + str(len(data)).encode() + b"\x00" + data
    ).hexdigest()


def validate_effective_config(cfg):
    """Return service safety markers without returning config or secrets."""
    if not isinstance(cfg, dict):
        stop("Effective Compose JSON is malformed")
    services = cfg.get("services")
    if not isinstance(services, dict) or set(services) != set(SERVICES):
        stop("Unexpected Compose services; review manually")
    nets = cfg.get("networks")
    if not isinstance(nets, dict) or set(nets) != {"private_canary"}:
        stop("Compose network model differs from private-only baseline")
    net = nets["private_canary"]
    if not isinstance(net, dict) or net.get("internal") is not True:
        stop("Compose private network is not internal")
    if net.get("external") or (net.get("name") not in (None, NETWORK)):
        stop("Compose private network external or renamed")

    for service_name, (container_name, image) in SERVICES.items():
        svc = services[service_name]
        if not isinstance(svc, dict):
            stop("Malformed Compose service " + service_name)
        if svc.get("image") != image or svc.get("container_name") != container_name:
            stop("Compose image/container identity drift: " + service_name)
        if svc.get("ports") or svc.get("publish_all_ports"):
            stop("Compose would publish host ports: " + service_name)
        if svc.get("network_mode") not in (None, ""):
            stop("Compose network_mode is not isolated: " + service_name)
        membership = svc.get("networks")
        if isinstance(membership, list):
            names = set(membership)
        elif isinstance(membership, dict):
            names = set(membership)
        else:
            names = set()
        if names != {"private_canary"}:
            stop("Compose service joined a non-Canary network: " + service_name)
        if svc.get("read_only") is not True:
            stop("Compose service root filesystem is not read-only: " + service_name)
        if svc.get("privileged") or svc.get("devices") or svc.get("pid") == "host":
            stop("Compose service has unexpectedly privileged settings: " + service_name)
        if "ALL" not in (svc.get("cap_drop") or []):
            stop("Compose service does not drop all capabilities: " + service_name)
        if not any(str(x).replace("=", ":") == "no-new-privileges:true"
                   for x in svc.get("security_opt", [])):
            stop("Compose no-new-privileges is missing: " + service_name)
        if svc.get("restart") not in (None, "no"):
            stop("Compose restart policy drift: " + service_name)
        mounts = svc.get("volumes")
        if not isinstance(mounts, list) or len(mounts) != 1:
            stop("Compose bind mount count changed: " + service_name)
        mount = mounts[0]
        if (not isinstance(mount, dict)
            or mount.get("type") != "bind"
            or mount.get("target") != "/data"
            or Path(mount.get("source", "/invalid")).resolve() != (ROOT / "data").resolve()):
            stop("Compose mount escaped Canary data: " + service_name)
    return True


def port_state(obj, name):
    """Active published ports must be zero. Dormant bindings must be loopback."""
    actual = obj.get("NetworkSettings", {}).get("Ports") or {}
    if not isinstance(actual, dict) or any(v is not None for v in actual.values()):
        stop("Active Canary published host port: " + name)
    if run(["docker", "port", name]).strip():
        stop("docker port reports an active publication: " + name)
    old = obj.get("HostConfig", {}).get("PortBindings") or {}
    if not isinstance(old, dict):
        stop("Malformed Canary PortBindings: " + name)
    count = 0
    for key, ports in old.items():
        if not re.fullmatch(r"\d{1,5}/(?:tcp|udp)", key):
            stop("Invalid configured Canary port: " + name)
        if ports is None:
            continue
        if not isinstance(ports, list):
            stop("Malformed configured Canary binding: " + name)
        for binding in ports:
            if not isinstance(binding, dict):
                stop("Malformed binding entry: " + name)
            ip, port = binding.get("HostIp"), binding.get("HostPort")
            try:
                if not isinstance(ip, str) or not ipaddress.ip_address(ip).is_loopback:
                    raise ValueError()
                if not isinstance(port, str) or not port.isascii() or not port.isdecimal():
                    raise ValueError()
                if not 1 <= int(port) <= 65535:
                    raise ValueError()
            except ValueError:
                stop("Unsafe dormant configured host bind: " + name)
            count += 1
    return count


def cpu_pressure():
    try:
        row = next(
            x for x in Path("/proc/pressure/cpu").read_text().splitlines()
            if x.startswith("some ")
        )
        m = re.search(r"\bavg10=([0-9.]+)", row)
        if not m:
            return None
        return float(m.group(1))
    except (OSError, ValueError, StopIteration):
        return None


def main():
    for p in (BASE, OVERRIDE):
        if not p.is_file() or p.is_symlink():
            stop("Expected Canary Compose file missing or symlink: " + p.name)
    if git_blob(BASE.read_bytes()) != BASE_GIT_BLOB:
        stop("Canary base Compose SHA drifted; do not recreate")
    baseline_match = OVERRIDE.read_text(encoding="utf-8") == STAGE4A_OVERRIDE
    if not NGINX.is_file() or hashlib.sha256(NGINX.read_bytes()).hexdigest() != NGINX_SHA:
        stop("Production nginx vhost SHA drifted since Stage 4D")

    env = os.environ.copy()
    env.update({"CANARY_DIR": str(ROOT), "CANARY_IMAGE": PLAY_IMAGE})
    # Compose fully resolves env_file into JSON here; keep it in RAM, never log.
    config = json.loads(run([
        "docker", "compose", "-p", "xtream-vod-canary",
        "-f", str(BASE), "-f", str(OVERRIDE),
        "config", "--format", "json"
    ], env=env))
    validate_effective_config(config)

    # Verify running containers are from the intended project and never
    # inspect or print any environment values or sensitive mount contents.
    dormant = 0
    for name, image in {**PROD_IMAGES, **CANARY_IMAGES}.items():
        objs = json.loads(run(["docker", "inspect", name]))
        if len(objs) != 1:
            stop("Container inventory count mismatch: " + name)
        obj = objs[0]
        if obj.get("Config", {}).get("Image") != image:
            stop("Container image identity mismatch: " + name)
        if name in CANARY_IMAGES:
            labels = obj.get("Config", {}).get("Labels") or {}
            if labels.get("com.docker.compose.project") != "xtream-vod-canary":
                stop("Canary compose ownership mismatch: " + name)
            attached = obj.get("NetworkSettings", {}).get("Networks") or {}
            if set(attached) != {NETWORK}:
                stop("Canary currently attached to another Docker network: " + name)
            dormant += port_state(obj, name)

    network_obj = json.loads(run(["docker", "network", "inspect", NETWORK]))
    if len(network_obj) != 1 or not network_obj[0].get("Internal"):
        stop("Live Docker Canary network is no longer internal")

    psi = cpu_pressure()
    print("STAGE4E_READONLY_COMPOSE_AUDIT=PASS")
    print("PRODUCTION_NGINX_SHA_UNCHANGED=PASS")
    print("CANARY_BASE_COMPOSE_GIT_BLOB=PASS")
    print("CANARY_EFFECTIVE_SERVICES=2")
    print("CANARY_EFFECTIVE_PORTS=NONE")
    print("CANARY_EFFECTIVE_NETWORK=PRIVATE_INTERNAL")
    print("CANARY_EFFECTIVE_CAP_DROP_AND_READONLY=PASS")
    print("CANARY_EFFECTIVE_BIND_MOUNTS=CANARY_DATA_ONLY")
    print("CANARY_PRODUCTION_IMAGES=UNCHANGED")
    print("DORMANT_LOOPBACK_HOST_BINDINGS=" + str(dormant))
    print("UPGRADE_SCRIPT_STAGE4A_BASELINE_MATCH=" + ("YES" if baseline_match else "NO"))
    if psi is None:
        print("CPU_PRESSURE_AVG10=UNKNOWN")
        cpu_ok = False
    else:
        print("CPU_PRESSURE_AVG10_PERCENT=" + f"{psi:.2f}")
        cpu_ok = psi < 30
    print("CPU_READY_FOR_CONTAINER_RECREATE=" + ("YES" if cpu_ok else "NO"))
    print("CANARY_RECREATE_APPROVED=NO")
    print("NGINX_RELOAD_APPROVED=NO")
    print("STAGE4E_NO_CHANGES=TRUE")
    if not baseline_match:
        print("NEXT=REVIEW_OVERRIDE_BASELINE_BEFORE_UPGRADE")
    elif not cpu_ok:
        print("NEXT=REVIEW_CPU_PRESSURE_BEFORE_CANARY_RECREATE")
    else:
        print("NEXT=REVIEW_ROLLBACK_AND_SEPARATE_CANARY_UPGRADE_APPROVAL")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired) as exc:
        print("STOP: Stage 4E Compose review failed: " + str(exc))
        raise SystemExit(1) from None
