#!/usr/bin/env python3
"""Safely provision an Xtream provider vault key on a Linux Docker host.

Uses only stdlib and NEVER prints the key. Refuses overwrite and symlinks.
Run manually as root after planning DR key backup and volume mounting.
"""
import argparse
import base64
import os
from pathlib import Path
import secrets
import stat


def provision(path: Path, uid: int = 10001):
    if os.geteuid() != 0:
        raise RuntimeError("Run with sudo on the Linux Docker host")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise RuntimeError("Key directory must be private (mode 0700)")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o400)
    try:
        os.fchown(fd, uid, uid)
        os.fchmod(fd, 0o400)
        data = base64.urlsafe_b64encode(secrets.token_bytes(32))
        total = 0
        while total < len(data):
            total += os.write(fd, data[total:])
        os.fsync(fd)
    except Exception:
        os.close(fd)
        path.unlink(missing_ok=True)
        raise
    else:
        os.close(fd)
    return "PROVIDER_KEY_CREATED=True (value never displayed)"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default="/etc/homedocker-secrets/xtream-provider.key")
    parser.add_argument("--uid", type=int, default=10001)
    args = parser.parse_args()
    if args.uid < 1:
        parser.error("Unprivileged container UID required")
    try:
        print(provision(Path(args.path), args.uid))
    except (OSError, RuntimeError) as exc:
        raise SystemExit("STOP: key creation not completed or key already exists") from None


if __name__ == "__main__":
    main()
