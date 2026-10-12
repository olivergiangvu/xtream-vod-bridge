"""CI preflight: keep local credentials and runtime data out of Git."""
import subprocess
from pathlib import PurePosixPath

paths = subprocess.check_output(["git", "ls-files", "-z"]).decode().split("\0")
bad = []
for path in filter(None, paths):
    segments = PurePosixPath(path).parts
    name = segments[-1]
    if ("secrets" in segments or "data" in segments or
        name == ".env" or (name.startswith(".env.") and name != ".env.example") or
        name.endswith((".sqlite", ".db", ".pem", ".key"))):
        bad.append(path)
if bad:
    raise SystemExit("STOP: sensitive paths tracked: " + ", ".join(bad))
print("Tracked-file secret path preflight: PASS")
