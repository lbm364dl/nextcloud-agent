#!/usr/bin/env python3
"""Offline checks of the guard rails: no server, no rclone, no password needed.

Run: python3 tests/selfcheck.py
"""

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "plugins" / "nextcloud" / "scripts" / "nextcloud.py"

home = tempfile.mkdtemp()
os.environ["HOME"] = home
spec = importlib.util.spec_from_file_location("nextcloud", SCRIPT)
nc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nc)

fails = 0


def check(label, cond):
    global fails
    print(("ok   " if cond else "FAIL ") + label)
    fails += 0 if cond else 1


def dies(fn, *a):
    try:
        fn(*a)
    except SystemExit as e:
        return str(e)
    return None


# a profile, without any server
nc.CONF_DIR.mkdir(parents=True)
pw = nc.CONF_DIR / "t.app-password"
pw.write_text("aaaaa-bbbbb-ccccc-ddddd-eeeee")
os.chmod(pw, 0o600)
nc.save_conf({"default": "t", "profiles": {"t": {
    "url": "https://cloud.example.org", "user": "jdoe", "password_file": str(pw),
    "write_allowed": ["agents/", "Team folder/"]}}})

# paths
check("'..' is refused", dies(nc.clean, "agents/../secret") is not None)
check("leading slash stripped", nc.clean("/agents/x") == "agents/x")

# write guard
check("write into agents/ allowed", dies(nc.require_writable, "agents/run/x.csv") is None)
check("write into a folder with spaces allowed", dies(nc.require_writable, "Team folder/x") is None)
check("write elsewhere refused", dies(nc.require_writable, "Documents/x") is not None)
check("prefix trick refused (agents-evil/)", dies(nc.require_writable, "agents-evil/x") is not None)

# secret detection
for p in ["x/.env", "x/github_pat.md", "x/google_cloud_key.json", "x/id_rsa", "x/server.pem",
          "x/my_token.txt", "x/passwords.csv"]:
    check(f"secret-looking blocked: {p}", bool(nc.SECRET_PAT.search(p)))
for p in ["x/report.pdf", "x/data.parquet", "x/keyboard_layout.csv", "x/patterns.R"]:
    check(f"ordinary file allowed: {p}", not nc.SECRET_PAT.search(p))

# approval guard
class A: approved = False
check("share without --approved refused", dies(nc._approved, A(), "Share x") is not None)
A.approved = True
check("share with --approved passes the guard", dies(nc._approved, A(), "Share x") is None)

# password file permissions
os.chmod(pw, 0o644)
check("world-readable password file refused", dies(nc.password) is not None)
os.chmod(pw, 0o600)
check("private password file accepted", nc.password().startswith("aaaaa"))

# share-link credentials
cred = Path(home) / "share"
cred.write_text("https://cloud.example.org/s/AbC123xyz\nsecretpw\n")
base, h = nc._ext(cred)
check("share link -> public DAV base", base == "https://cloud.example.org/public.php/dav/files/AbC123xyz/")
check("X-Requested-With header set", h.get("X-Requested-With") == "XMLHttpRequest")
check("anonymous basic auth set", h.get("Authorization", "").startswith("Basic "))

# put: never report an upload that did not happen
class P:
    overwrite = False
    def __init__(self, local, path): self.local, self.path = local, path
src = Path(home) / "out.csv"
src.write_text("a,b\n1,2\n")
calls = []
state = {}
def fake_stat(path): return state.get(path)
def fake_rclone(*args):
    calls.append(args)
    if args[0] == "copyto":
        state[args[-1].split(":", 1)[1]] = {"Size": state.get("_upload_size", src.stat().st_size)}
    if args[0] == "hashsum":
        return ""
    return ""
nc.remote_stat, nc.rclone = fake_stat, fake_rclone
nc.remote_md5 = lambda path, size: None

check("put of a new file uploads", dies(nc.cmd_put, P(str(src), "agents/run/")) is None
      and any(c[0] == "copyto" for c in calls))
calls.clear()
msg = dies(nc.cmd_put, P(str(src), "agents/run/"))
check("put onto an existing file without --overwrite is refused", msg is not None and "--overwrite" in msg)
check("...and nothing is copied", not any(c[0] == "copyto" for c in calls))
o = P(str(src), "agents/run/"); o.overwrite = True
check("put --overwrite replaces it", dies(nc.cmd_put, o) is None and any(c[0] == "copyto" for c in calls))
check("copyto always transfers (--ignore-times)", all("--ignore-times" in c for c in calls if c[0] == "copyto"))
state["_upload_size"] = 1
msg = dies(nc.cmd_put, o)
check("put fails when the server size does not match", msg is not None and "could not be verified" in msg)
state.pop("_upload_size")
nc.remote_md5 = lambda path, size: "0" * 32
msg = dies(nc.cmd_put, o)
check("put fails when the server content does not match", msg is not None and "differs" in msg)
nc.remote_md5 = lambda path, size: None
state["_upload_size"] = src.stat().st_size
state.pop("_upload_size")
state["agents/dir"] = {"IsDir": True}
check("put onto a folder path without '/' is refused", dies(nc.cmd_put, P(str(src), "agents/dir")) is not None)

# no desktop client -> network only
check("no local sync client -> no local roots", nc.local_roots() == [])

print(f"\n{'all checks passed' if not fails else f'{fails} check(s) FAILED'}")
sys.exit(1 if fails else 0)
