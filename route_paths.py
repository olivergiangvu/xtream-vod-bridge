"""Narrow route-prefix support for same-port Canary behind existing nginx.

Nginx strips /canary/ before forwarding; only generated public redirects and
cookie paths use this prefix. Production defaults to original root paths.
Unsupported values fail closed, preventing auth/cookie path confusion.
"""
import os

PREFIX = os.getenv("XTREAM_URL_PREFIX", "")
if PREFIX not in ("", "/canary"):
    raise RuntimeError("Unsupported XTREAM_URL_PREFIX (expected empty or /canary)")


def public_path(path):
    """Canonical external path; path must be absolute and without // prefix."""
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise ValueError("Invalid public path")
    return PREFIX + path


ADMIN_PATH = public_path("/admin/")
LOGIN_PATH = public_path("/admin-signin/")
SESSION_COOKIE_PATH = ADMIN_PATH
NONCE_COOKIE_PATH = LOGIN_PATH
