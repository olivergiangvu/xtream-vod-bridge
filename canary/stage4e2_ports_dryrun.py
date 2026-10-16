#!/usr/bin/env python3
"""HomeDocker Stage 4E.2 — dry-run removal of exactly two Canary port bindings.

Never writes Compose, Docker, nginx, Portainer, firewall or any live service.
Creates only a private temporary candidate for docker compose config and
deletes it afterwards. Never prints resolved config or env file contents.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.request import build_opener, ProxyHandler, Request

ROOT = Path("/opt/xtream-vod-canary")
BASE = ROOT / "src/canary/compose.yaml"
OVERRIDE = ROOT / "ui-override.yaml"
NGINX = Path("/etc/nginx/conf.d/xtream-vod-bridge-18450.conf")
EXPECTED_SHA = {
    BASE: "79d4cb76db03ae881769339e4e2b851e1c68c1e1bb6133a62661dbdbca49a42e",
    OVERRIDE: "eab5db9b32c81dd7d22ddfbd00c86b2fec9d927e8281120eafe2628025927bda",
    NGINX: "8746edfcc5b899ee8c4381c0890d203b0dd3aada33390eab0d389cc54faedd35",
}
REFERENCE = (
    "https://raw.githubusercontent.com/olivergiangvu/xtream-vod-bridge/"
    "2908052ab538534370a3dcb0b937997c7e60ce7b/canary/compose.yaml"
)
REFERENCE_BLOB = "ae9970661ae7d6f3f48a9717652d797fbf50a8c7"
PLAY_IMAGE = "homedocker/xtream-vod-canary:5c2f02233a0f"
EXPECTED_PORTS = {
    "xtream-vod-bridge": ("18769", "8767"),
    "xtream-vod-admin": ("18770", "8768"),
}
EXPECTED_IMAGES = {
    "xtream-vod-bridge": PLAY_IMAGE,
    "xtream-vod-admin": "homedocker/xtream-vod-canary-admin:0.5e-cookie-e153b327b49f",
}


def refuse(reason):
    raise ValueError(reason)


def git_blob(raw):
    return hashlib.sha1(
        b"blob " + str(len(raw)).encode() + b"\x00" + raw
    ).hexdigest()


def significant(value):
    """Compare functional YAML text while tolerating only comment/blank drift."""
    return [
        line.rstrip() for line in value.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def preview_remove_ports(source):
    """Remove two fixed two-line stanzas; refuse every other stanza layout."""
    lines = source.splitlines(keepends=True)
    output = []
    removed = []
    current_service = None
    seen = set()
    i = 0
    while i < len(lines):
        line = lines[i]
        header = re.fullmatch(r"  (xtream-vod-admin|xtream-vod-bridge):\s*\n", line)
        if header:
            current_service = header.group(1)
        elif re.fullmatch(r"(?:networks|volumes|secrets|configs):\s*\n", line):
            current_service = None
        if line.startswith("    ports:"):
            if current_service not in EXPECTED_PORTS or current_service in seen:
                refuse("Unexpected or repeated Canary ports stanza")
            if line.strip() != "ports:" or i + 1 >= len(lines):
                refuse("Unexpected Canary ports stanza layout")
            published, internal = EXPECTED_PORTS[current_service]
            portline = lines[i + 1].strip()
            pattern = (
                r"-\s*['\"]?127\.0\.0\.1:"
                + re.escape(published) + ":" + re.escape(internal)
                + r"(?:/tcp)?['\"]?"
            )
            if not re.fullmatch(pattern, portline):
                refuse("Canary ports stanza does not match approved loopback mapping")
            removed.append((current_service, line + lines[i + 1], len(output)))
            seen.add(current_service)
            i += 2
            continue
        output.append(line)
        i += 1
    if seen != set(EXPECTED_PORTS):
        refuse("Exactly two known Canary host port stanzas required")
    candidate = "".join(output)

    # Reinsert original blocks to prove the patch is exactly reversible.
    reconstructed = output[:]
    offset = 0
    for _service, block, position in sorted(removed, key=lambda item: item[2]):
        reconstructed.insert(position + offset, block)
        offset += 1
    if "".join(reconstructed) != source:
        refuse("Byte-exact roundtrip restoration failed")
    return candidate


def compose_config(base_file):
    env = os.environ.copy()
    env.update(CANARY_DIR=str(ROOT), CANARY_IMAGE=PLAY_IMAGE)
    cmd = [
        "docker", "compose", "-p", "xtream-vod-canary",
        "--project-directory", str(BASE.parent),
        "-f", str(base_file), "-f", str(OVERRIDE),
        "config", "--format", "json",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=40, env=env)
    if result.returncode:
        refuse("Compose config read-only validation failed")
    return json.loads(result.stdout)


def validate_config_pair(before, after):
    if not isinstance(before, dict) or not isinstance(after, dict):
        refuse("Compose result is not an object")
    if set(before.get("services", {})) != set(EXPECTED_PORTS):
        refuse("Unexpected Canary services in Compose")
    if set(after.get("services", {})) != set(EXPECTED_PORTS):
        refuse("Candidate alters Compose service inventory")
    if set(after.get("networks", {})) != {"private_canary"}:
        refuse("Candidate contains an unexpected network")
    if after["networks"]["private_canary"].get("internal") is not True:
        refuse("Candidate Canary network not internal")
    clean_before = copy.deepcopy(before)
    for service, (published, internal) in EXPECTED_PORTS.items():
        old = before["services"][service]
        new = after["services"][service]
        if old.get("image") != EXPECTED_IMAGES[service]:
            refuse("Compose image identity changed: " + service)
        port_list = old.get("ports")
        if not isinstance(port_list, list) or len(port_list) != 1:
            refuse("Expected exactly one existing loopback port: " + service)
        binding = port_list[0]
        if not isinstance(binding, dict) or any((
            str(binding.get("published")) != published,
            binding.get("host_ip") != "127.0.0.1",
            str(binding.get("target")) != internal,
            binding.get("protocol", "tcp") != "tcp",
        )):
            refuse("Unexpected effective Docker port mapping: " + service)
        if new.get("ports"):
            refuse("Candidate still publishes ports: " + service)
        clean_before["services"][service].pop("ports", None)
    if clean_before != after:
        refuse("Candidate changes settings beyond the two ports stanzas")
    return True


def main():
    for path, sha in EXPECTED_SHA.items():
        if not path.is_file() or path.is_symlink():
            refuse("Unexpected file/symlink: " + path.name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != sha:
            refuse("Live file SHA256 drifted: " + path.name)

    # Fetch only a public, immutable, SHA-verified source baseline.
    opener = build_opener(ProxyHandler({}))
    with opener.open(Request(REFERENCE), timeout=15) as resp:
        reference_raw = resp.read(20000)
    if git_blob(reference_raw) != REFERENCE_BLOB:
        refuse("Reference Compose integrity mismatch")

    original = BASE.read_bytes().decode("utf-8")
    candidate = preview_remove_ports(original)
    if significant(candidate) != significant(reference_raw.decode("utf-8")):
        refuse("Canary Compose has functional drift beyond the two ports")
    if not candidate.endswith("\n"):
        refuse("Candidate newline formatting is unexpected")

    original_config = compose_config(BASE)
    with tempfile.TemporaryDirectory(prefix="xtream-stage4e2-", dir="/tmp") as folder:
        temp_file = Path(folder) / "compose.yaml"
        os.chmod(folder, 0o700)
        temp_file.write_text(candidate, encoding="utf-8")
        temp_file.chmod(0o600)
        candidate_config = compose_config(temp_file)
        validate_config_pair(original_config, candidate_config)

    print("STAGE4E2_PORT_REMOVAL_PREVIEW=PASS")
    print("CANARY_BASE_SHA256_VERIFIED=PASS")
    print("CANARY_OVERRIDE_SHA256_VERIFIED=PASS")
    print("NGINX_PRODUCTION_SHA256_VERIFIED=PASS")
    print("PORT_DECLARATIONS_TO_REMOVE=2")
    print("PORTS_18769_18770_REMOVED_FROM_CANDIDATE=TRUE")
    print("CANDIDATE_EFFECTIVE_PORTS=NONE")
    print("CANDIDATE_EFFECTIVE_INTERNAL_NETWORK=TRUE")
    print("CANDIDATE_OTHER_COMPOSE_SETTINGS=BYTE_UNCHANGED")
    print("CANDIDATE_SHA256=" + hashlib.sha256(candidate.encode()).hexdigest())
    print("ORIGINAL_ROUNDTRIP_BYTE_EXACT=PASS")
    print("PRODUCTION_AND_CANARY_RUNNING_SERVICES_CHANGED=NONE")
    print("COMPOSE_AND_NGINX_LIVE_FILES_CHANGED=NONE")
    print("APPLY_APPROVED=NO")
    print("NEXT=REVIEW_BACKUP_AND_ATOMIC_CANARY_BASE_PORT_REMOVAL")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired) as exc:
        print("STOP: Stage 4E.2 dry-run failed: " + str(exc))
        raise SystemExit(1) from None
