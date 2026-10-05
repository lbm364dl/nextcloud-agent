#!/usr/bin/env python3
"""Nextcloud access for AI agents: files, search, sharing, with guard rails.

Works on any Nextcloud server, over the network (no sync client needed).
Files go through rclone's WebDAV backend; sharing through the OCS share API.
Each profile (server + account) authenticates with an app password kept in a
private file (mode 600). Passwords are never passed on the command line.

  nextcloud.py setup --profile P --url URL --user LOGIN [--password-file F]
  nextcloud.py profiles                    list configured profiles
  nextcloud.py check                       test the connection
  nextcloud.py ls [PATH]                   list a folder
  nextcloud.py tree PATH [--depth N]       list recursively
  nextcloud.py index [PATH]                refresh the file index (cache)
  nextcloud.py find PATTERN [--in PATH]    search file names in the index
  nextcloud.py get PATH [--to DIR]         identical local synced copy, else download
  nextcloud.py where PATH                  is there an identical local copy?
  nextcloud.py put LOCAL PATH [--overwrite]  upload; only into allowed folders;
                                           refuses an existing file unless --overwrite
  nextcloud.py mkdir PATH                  create a folder; only in allowed folders
  nextcloud.py shares [--mine]             shared with me (or by me)
  nextcloud.py who NAME                    find users/groups to share with
  nextcloud.py share PATH --with LOGIN [--group] [--perm LEVEL] --approved
  nextcloud.py email-share PATH --email ADDR --expire YYYY-MM-DD [--perm LEVEL] --approved
  nextcloud.py link PATH --expire YYYY-MM-DD [--perm LEVEL] --approved
  nextcloud.py unshare SHARE_ID            remove a share (no approval needed)
  nextcloud.py ext-ls  --cred FILE [PATH]  browse a share someone SENT you (no account)
  nextcloud.py ext-get --cred FILE PATH    download from it
  nextcloud.py ext-put --cred FILE LOCAL [PATH] [--overwrite]  upload into it, if allowed

Global: --profile NAME (or env NEXTCLOUD_PROFILE); default from the config.
Levels: read | drop (upload only) | contribute (no delete) | edit.

Rules: never deletes or moves files; writes only inside each profile's
"write_allowed" folders; anything that gives someone new access requires
--approved, which an agent may pass only after the human approved that exact
share; credential-looking files are not downloaded without --allow-secret.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CONF_DIR = Path.home() / ".config" / "nextcloud-agent"
CONF_FILE = CONF_DIR / "config.json"
CACHE_ROOT = Path.home() / ".cache" / "nextcloud-agent"
NC_CLIENT_CFG = Path.home() / ".config" / "Nextcloud" / "nextcloud.cfg"

# Nextcloud permission bits: 1 read, 2 update, 4 create, 8 delete, 16 reshare.
PERMS = {
    "read": 1,        # view and download
    "drop": 4,        # upload only; cannot see the folder (file drop)
    "contribute": 7,  # read + add + change, never delete
    "edit": 15,       # everything incl. delete (no resharing)
}

SECRET_PAT = re.compile(
    r"(^|/)(\.env(\..*)?|.*(secret|token|passw|credential|apikey|api_key|_pat|pat\.|"
    r"private[_-]?key|\.pem$|\.key$|id_rsa|id_ed25519|.*key.*\.json$))", re.IGNORECASE)

PROFILE = None  # set in main()


# -- configuration -------------------------------------------------------------


def die(msg):
    sys.exit(f"nextcloud: {msg}")


def load_conf():
    if CONF_FILE.exists():
        return json.loads(CONF_FILE.read_text())
    return {"default": None, "profiles": {}}


def save_conf(c):
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    CONF_FILE.write_text(json.dumps(c, indent=2))
    os.chmod(CONF_FILE, 0o600)


def profile_name():
    c = load_conf()
    name = PROFILE or os.environ.get("NEXTCLOUD_PROFILE") or c.get("default")
    if not name:
        die("no profile configured; run `nextcloud.py setup --profile NAME --url URL --user LOGIN`")
    if name not in c.get("profiles", {}):
        die(f"unknown profile '{name}'; configured: {sorted(c.get('profiles', {}))}")
    return name


def prof():
    p = dict(load_conf()["profiles"][profile_name()])
    p.setdefault("write_allowed", ["agents/"])
    return p


VERIFY_MAX = 100 * 1024 * 1024  # read uploads back up to this size to compare content


def remote():
    return f"nc-{profile_name()}"


def cache():
    d = CACHE_ROOT / profile_name()
    d.mkdir(parents=True, exist_ok=True)
    return d


def password():
    f = Path(prof()["password_file"]).expanduser()
    if not f.exists():
        die(f"no app password at {f}. Create one in Nextcloud (Personal settings > "
            "Security > Devices & sessions > Create new app password) and save it "
            "there with mode 600.")
    if f.stat().st_mode & 0o077:
        die(f"{f} is readable by others; run: chmod 600 '{f}'")
    return f.read_text().strip()


def log(action, detail):
    with open(cache() / "actions.log", "a") as f:
        f.write(f"{dt.datetime.now().isoformat(timespec='seconds')} {action} {detail}\n")


def rclone(*args):
    try:
        res = subprocess.run(["rclone", *args], capture_output=True, text=True,
                             stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        die("rclone is not installed (https://rclone.org/install/); put it on PATH")
    if res.returncode != 0:
        die(f"rclone {args[0]} failed: {(res.stderr or '').strip()[-600:]}")
    return res.stdout


def remote_stat(path):
    """The server's lsjson entry for PATH, or None when nothing is there."""
    try:
        res = subprocess.run(["rclone", "lsjson", "--stat", "--no-mimetype", f"{remote()}:{path}"],
                             capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        die("rclone is not installed (https://rclone.org/install/); put it on PATH")
    if res.returncode != 0:
        if "not found" in (res.stderr or "").lower():
            return None
        die(f"rclone lsjson failed: {(res.stderr or '').strip()[-600:]}")
    return json.loads(res.stdout)


def remote_md5(path, size):
    """MD5 of the server copy of PATH. Uses the server's own hash when it reports one;
    otherwise reads the file back if it is at most VERIFY_MAX bytes. None if neither works."""
    try:
        res = subprocess.run(["rclone", "hashsum", "md5", f"{remote()}:{path}"],
                             capture_output=True, text=True, stdin=subprocess.DEVNULL)
        out = res.stdout.split() if res.returncode == 0 else []
        if out and len(out[0]) == 32:
            return out[0]
        if size > VERIFY_MAX:
            return None
        res = subprocess.run(["rclone", "cat", f"{remote()}:{path}"],
                             capture_output=True, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        die("rclone is not installed (https://rclone.org/install/); put it on PATH")
    return hashlib.md5(res.stdout).hexdigest() if res.returncode == 0 else None


def clean(path):
    """A server path: no leading slash, no '..'."""
    p = str(path or "").strip().lstrip("/")
    if ".." in Path(p).parts:
        die("paths with '..' are not allowed")
    return p


def require_writable(path):
    p = clean(path)
    allowed = prof()["write_allowed"]
    if not any(p == a.rstrip("/") or p.startswith(a.rstrip("/") + "/") for a in allowed):
        die(f"writing to '{p}' is not allowed. Allowed folders: {allowed}. "
            f"Ask the human to add one ({CONF_FILE}, profile '{profile_name()}').")
    return p


def ocs(method, endpoint, data=None):
    p = prof()
    url = p["url"].rstrip("/") + "/ocs/v2.php/apps/files_sharing/api/v1/" + endpoint
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method)
    token = base64.b64encode(f"{p['user']}:{password()}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    req.add_header("OCS-APIRequest", "true")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)["ocs"]["data"]
    except urllib.error.HTTPError as e:
        die(f"server API {e.code}: {e.read().decode(errors='replace')[:400]}")


# -- setup / status -------------------------------------------------------------


def cmd_setup(a):
    global PROFILE
    c = load_conf()
    name = a.profile_opt or PROFILE
    if not name:
        die("pass --profile NAME (e.g. the server's short name)")
    p = dict(c.get("profiles", {}).get(name, {}))
    for k in ("url", "user"):
        if getattr(a, k):
            p[k] = getattr(a, k)
    if not p.get("url") or not p.get("user"):
        die("pass --url (e.g. https://cloud.example.org) and --user (your login)")
    p["password_file"] = a.password_file or p.get("password_file") or str(CONF_DIR / f"{name}.app-password")
    p.setdefault("write_allowed", ["agents/"])
    c.setdefault("profiles", {})[name] = p
    if not c.get("default") or a.make_default:
        c["default"] = name
    save_conf(c)
    PROFILE = name
    obscured = subprocess.run(["rclone", "obscure", "-"], input=password(),
                              capture_output=True, text=True).stdout.strip()
    dav = f"{p['url'].rstrip('/')}/remote.php/dav/files/{urllib.parse.quote(p['user'])}/"
    rclone("config", "create", remote(), "webdav", f"url={dav}", "vendor=nextcloud",
           f"user={p['user']}", f"pass={obscured}", "--non-interactive")
    cfg = Path(rclone("config", "file").strip().splitlines()[-1])
    os.chmod(cfg, 0o600)
    print(f"profile '{name}' -> {dav} (rclone remote '{remote()}', config mode 600)")
    cmd_check(a)


def cmd_profiles(a):
    c = load_conf()
    for n, p in c.get("profiles", {}).items():
        mark = "*" if n == c.get("default") else " "
        print(f"{mark} {n}\t{p.get('url')}\t{p.get('user')}\twrite: {p.get('write_allowed')}")


def cmd_check(a):
    q = json.loads(rclone("about", f"{remote()}:", "--json"))
    gb = lambda b: f"{(b or 0) / 1e9:.0f} GB"
    print(f"[{profile_name()}] connected: used {gb(q.get('used'))}" +
          (f" of {gb(q.get('total'))}" if q.get("total") else ""))
    top = rclone("lsf", f"{remote()}:", "--max-depth", "1")
    print("top level:", " | ".join(top.splitlines()[:30]))


# -- browse / search -------------------------------------------------------------


def cmd_ls(a):
    print(rclone("lsf", f"{remote()}:{clean(a.path)}", "--format", "pst", "--separator", "\t"), end="")


def cmd_tree(a):
    print(rclone("lsf", "-R", "--max-depth", str(a.depth), f"{remote()}:{clean(a.path)}"), end="")


def cmd_index(a):
    rows = json.loads(rclone("lsjson", "-R", "--files-only", "--no-mimetype", f"{remote()}:{clean(a.path)}"))
    base = clean(a.path)
    idx = cache() / "index.jsonl"
    tmp = idx.with_suffix(".tmp")
    with open(tmp, "w") as f:
        for r in rows:
            p = f"{base}/{r['Path']}" if base else r["Path"]
            f.write(json.dumps({"path": p, "size": r.get("Size"), "mtime": r.get("ModTime")}) + "\n")
    tmp.replace(idx)
    print(f"indexed {len(rows)} files, {sum(r.get('Size') or 0 for r in rows) / 1e9:.1f} GB -> {idx}")


def cmd_find(a):
    idx = cache() / "index.jsonl"
    if not idx.exists():
        die("no index yet; run `nextcloud.py index` (takes a few minutes)")
    age_h = (dt.datetime.now().timestamp() - idx.stat().st_mtime) / 3600
    pat = a.pattern if any(ch in a.pattern for ch in "*?[") else f"*{a.pattern}*"
    within = clean(a.within) if a.within else ""
    n = 0
    with open(idx) as f:
        for line in f:
            r = json.loads(line)
            if within and not r["path"].startswith(within):
                continue
            if fnmatch.fnmatch(r["path"].lower(), pat.lower()):
                print(f"{r['path']}\t{(r['size'] or 0) / 1e6:.1f} MB\t{(r['mtime'] or '')[:10]}")
                n += 1
                if n >= a.limit:
                    break
    print(f"({n} shown; index is {age_h:.0f} h old)", file=sys.stderr)


# -- optional local synced copy ----------------------------------------------------


def local_roots():
    """(server_prefix, local_dir) pairs from the Nextcloud desktop client for
    this profile's account. Empty when there is no client: everything then goes
    over the network, which is the normal case."""
    if os.environ.get("NEXTCLOUD_NO_LOCAL") or not NC_CLIENT_CFG.exists():
        return []
    p = prof()
    host = urllib.parse.urlparse(p["url"]).netloc
    txt = NC_CLIENT_CFG.read_text(errors="replace")
    roots = []
    for n, user in re.findall(r"^(\d+)\\dav_user=(.+)$", txt, re.M):
        url = (re.search(rf"^{n}\\url=(.+)$", txt, re.M) or [None, ""])[1]
        if user.strip() != p["user"] or urllib.parse.urlparse(url.strip()).netloc != host:
            continue
        get = lambda key: dict(re.findall(rf"^{n}\\Folders\\(\d+)\\{key}=(.+)$", txt, re.M))
        locs, tgts, vfs, paused = get("localPath"), get("targetPath"), get("virtualFilesMode"), get("paused")
        for k, loc in locs.items():
            if vfs.get(k, "off").strip() != "off" or paused.get(k, "false").strip() == "true":
                continue  # placeholder files or paused sync: not real/current
            roots.append((clean(tgts.get(k, "/")), Path(loc.strip())))
    return roots


def local_copy(path, size=None):
    for prefix, root in local_roots():
        if prefix and not (path == prefix or path.startswith(prefix.rstrip("/") + "/")):
            continue
        cand = root / (path[len(prefix):].lstrip("/") if prefix else path)
        if cand.is_file() and (size is None or cand.stat().st_size == size):
            return cand
    return None


def remote_size(path):
    return json.loads(rclone("lsjson", "--stat", "--no-mimetype", f"{remote()}:{path}")).get("Size")


def cmd_where(a):
    p = clean(a.path)
    size = remote_size(p)
    loc = local_copy(p, size)
    print(f"server: {p} ({(size or 0) / 1e6:.1f} MB)")
    if loc:
        print(f"identical local synced copy: {loc}")
    elif local_roots():
        print("a local sync exists, but this file has no identical local copy")
    else:
        print("no local sync client for this account: network only")


def cmd_get(a):
    p = clean(a.path)
    if SECRET_PAT.search(p) and not a.allow_secret:
        die(f"'{p}' looks like a credential (key, token, password, .env). Agents do not "
            "download those. Only if the human explicitly asks for this exact file, rerun "
            "with --allow-secret, and never print its contents.")
    if not a.remote and not a.to:
        loc = local_copy(p, remote_size(p))
        if loc:
            print(loc)
            return
    dest = Path(a.to) if a.to else cache() / "files" / Path(p).parent
    dest.mkdir(parents=True, exist_ok=True)
    rclone("copy", f"{remote()}:{p}", str(dest))
    print(dest / Path(p).name)


# -- write ----------------------------------------------------------------------


def cmd_put(a):
    p = require_writable(a.path)
    src = Path(a.local)
    if not src.is_file():
        die(f"{src} does not exist or is not a file")
    target = p + src.name if p.endswith("/") else p
    before = remote_stat(target)
    if before is not None and before.get("IsDir"):
        die(f"'{target}' is a folder on the server; give a file path or end the folder path with '/'")
    if before is not None and not a.overwrite:
        die(f"'{target}' already exists on the server, so nothing was uploaded. To replace it, "
            "rerun with --overwrite (Nextcloud keeps the old file in its version history).")
    # --ignore-times: always transfer, never skip on matching size and time.
    rclone("copyto", "--ignore-times", str(src), f"{remote()}:{target}")
    size = src.stat().st_size
    after = remote_stat(target)
    if after is None or after.get("Size") != size:
        got = "nothing" if after is None else f"{after.get('Size')} bytes"
        die(f"upload of '{target}' could not be verified: the server has {got}, "
            f"the local file has {size} bytes")
    server_md5 = remote_md5(target, size)
    if server_md5 is not None and server_md5 != hashlib.md5(src.read_bytes()).hexdigest():
        die(f"upload of '{target}' could not be verified: the server's copy differs from the local file")
    checked = "size and content" if server_md5 is not None else "size only (file too large to read back)"
    verb = "replaced" if before is not None else "uploaded"
    log("put", f"{src} -> {target} ({verb}, {size} bytes)")
    print(f"{verb} {target} ({size} bytes; server copy checked: {checked}; private unless that folder is shared)")


def cmd_mkdir(a):
    p = require_writable(a.path)
    rclone("mkdir", f"{remote()}:{p}")
    log("mkdir", p)
    print(f"created {p}")


# -- sharing ----------------------------------------------------------------------


def _approved(a, what):
    if not a.approved:
        die(f"giving access needs the human's explicit OK. Ask them: '{what}?' "
            "and only then rerun with --approved.")


def cmd_shares(a):
    data = ocs("GET", "shares" if a.mine else "shares?shared_with_me=true")
    kinds = {0: "user", 1: "group", 3: "link", 4: "email", 6: "federated", 10: "talk"}
    for s in data:
        who = s.get("share_with_displayname") or s.get("share_with") or (s.get("url") or "")
        print(f"{s.get('id')}\t{s.get('path')}\t{kinds.get(s.get('share_type'), s.get('share_type'))}\t"
              f"{who}\tby {s.get('displayname_owner')}\tperm={s.get('permissions')}")


def cmd_who(a):
    d = ocs("GET", f"sharees?search={urllib.parse.quote(a.query)}&itemType=folder&perPage=20&lookup=false")
    found = 0
    for block in (d.get("exact", {}), d):
        for key, label in (("users", "user"), ("groups", "group"), ("emails", "email")):
            for r in block.get(key, []) or []:
                print(f"{label}\t{r.get('value', {}).get('shareWith')}\t{r.get('label')}\t"
                      f"{r.get('shareWithDisplayNameUnique', '')}")
                found += 1
    if not found:
        print("nobody found (try part of the name, or their email)")


def cmd_share(a):
    p = clean(a.path)
    what = f"Share '{p}' ({a.perm}) with {'group' if a.group else 'user'} {a.who}"
    _approved(a, what)
    d = ocs("POST", "shares", {"path": "/" + p, "shareType": 1 if a.group else 0,
                                "shareWith": a.who, "permissions": PERMS[a.perm]})
    log("share", f"{what} -> id {d.get('id')}")
    print(f"{what}: done (share id {d.get('id')})")


def cmd_email_share(a):
    p = clean(a.path)
    if not a.expire:
        die("email shares must have --expire YYYY-MM-DD")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", a.email):
        die(f"'{a.email}' is not an email address")
    what = (f"Share '{p}' ({a.perm}) by email with {a.email}, password by separate "
            f"email, expiring {a.expire}")
    _approved(a, what)
    d = ocs("POST", "shares", {"path": "/" + p, "shareType": 4, "shareWith": a.email,
                                "permissions": PERMS[a.perm],
                                "password": secrets.token_urlsafe(12), "expireDate": a.expire})
    log("email-share", f"{what} -> id {d.get('id')}")
    print(f"{what}: done (share id {d.get('id')}). The server emails the link and, "
          "separately, the password (if the server sends share emails).")


def cmd_link(a):
    p = clean(a.path)
    if not a.expire:
        die("links must have --expire YYYY-MM-DD")
    pw = secrets.token_urlsafe(12)
    what = f"Create a password-protected {a.perm} link to '{p}' expiring {a.expire}"
    _approved(a, what)
    d = ocs("POST", "shares", {"path": "/" + p, "shareType": 3, "permissions": PERMS[a.perm],
                                "password": pw, "expireDate": a.expire})
    log("link", f"{what} -> {d.get('url')}")
    print(f"link: {d.get('url')}\npassword: {pw}\nexpires: {a.expire}")


def cmd_unshare(a):
    ocs("DELETE", f"shares/{int(a.id)}")
    log("unshare", f"id {a.id}")
    print(f"share {a.id} removed")


# -- receiving a share (no account) --------------------------------------------------


def _ext(cred_file):
    """(dav_base, headers) for a share link + password stored in a file."""
    f = Path(cred_file).expanduser()
    if not f.exists():
        die(f"{f} not found (line 1: the share link, line 2: its password)")
    lines = [l.strip() for l in f.read_text().splitlines() if l.strip()]
    m = re.search(r"https?://([^/]+)/(?:index\.php/)?s/([A-Za-z0-9]+)", lines[0])
    if not m:
        die("line 1 is not a Nextcloud share link (…/s/<token>)")
    host, tok = m.groups()
    h = {"X-Requested-With": "XMLHttpRequest"}  # without it Nextcloud answers 401
    if len(lines) > 1:
        h["Authorization"] = "Basic " + base64.b64encode(f"anonymous:{lines[1]}".encode()).decode()
    return f"https://{host}/public.php/dav/files/{tok}/", h


def _ext_err(e):
    die(f"share answered {e.code}" + (" (not allowed by this share)" if e.code == 403
                                      else " (wrong password, expired or revoked?)"))


def cmd_ext_ls(a):
    base, h = _ext(a.cred)
    req = urllib.request.Request(base + urllib.parse.quote(clean(a.path)), method="PROPFIND",
                                 headers={**h, "Depth": "1"})
    try:
        body = urllib.request.urlopen(req, timeout=60).read().decode()
    except urllib.error.HTTPError as e:
        _ext_err(e)
    for href in re.findall(r"<d:href>([^<]+)</d:href>", body)[1:]:
        print(urllib.parse.unquote(href.rstrip("/").rsplit("/", 1)[-1]) + ("/" if href.endswith("/") else ""))


def cmd_ext_get(a):
    base, h = _ext(a.cred)
    p = clean(a.path)
    dest = Path(a.to or CACHE_ROOT / "external") / Path(p).name
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(urllib.request.Request(base + urllib.parse.quote(p), headers=h),
                                    timeout=300) as r, open(dest, "wb") as out:
            while chunk := r.read(1 << 20):
                out.write(chunk)
    except urllib.error.HTTPError as e:
        _ext_err(e)
    print(dest)


def cmd_ext_put(a):
    base, h = _ext(a.cred)
    src = Path(a.local)
    if not src.is_file():
        die(f"{src} does not exist or is not a file")
    target = clean(a.path)
    target = target + src.name if (not target or target.endswith("/")) else target
    url = base + urllib.parse.quote(target)
    exists = True
    try:
        urllib.request.urlopen(urllib.request.Request(url, method="HEAD", headers=h), timeout=60)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            _ext_err(e)
        exists = False
    if exists and not a.overwrite:
        die(f"'{target}' already exists in the share, so nothing was uploaded. "
            "To replace it, rerun with --overwrite.")
    try:
        urllib.request.urlopen(urllib.request.Request(url, data=src.read_bytes(), method="PUT", headers=h),
                               timeout=600)
    except urllib.error.HTTPError as e:
        _ext_err(e)
    print(f"{'replaced' if exists else 'uploaded'} {src.name} in the share as {target}")


# -- CLI ----------------------------------------------------------------------------


def main():
    global PROFILE
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--profile", help="profile to use (default: config default or $NEXTCLOUD_PROFILE)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, *args):
        x = sub.add_parser(name)
        for spec in args:
            spec(x)
        x.set_defaults(fn=fn)
        return x

    x = add("setup", cmd_setup)
    x.add_argument("--profile", dest="profile_opt"); x.add_argument("--url"); x.add_argument("--user")
    x.add_argument("--password-file"); x.add_argument("--make-default", action="store_true")
    add("profiles", cmd_profiles)
    add("check", cmd_check)
    add("ls", cmd_ls).add_argument("path", nargs="?", default="")
    x = add("tree", cmd_tree); x.add_argument("path"); x.add_argument("--depth", type=int, default=3)
    add("index", cmd_index).add_argument("path", nargs="?", default="")
    x = add("find", cmd_find); x.add_argument("pattern"); x.add_argument("--in", dest="within")
    x.add_argument("--limit", type=int, default=200)
    x = add("get", cmd_get); x.add_argument("path"); x.add_argument("--to")
    x.add_argument("--allow-secret", action="store_true")
    x.add_argument("--remote", action="store_true", help="always download, ignore a local copy")
    add("where", cmd_where).add_argument("path")
    x = add("put", cmd_put); x.add_argument("local"); x.add_argument("path")
    x.add_argument("--overwrite", action="store_true")
    add("mkdir", cmd_mkdir).add_argument("path")
    add("shares", cmd_shares).add_argument("--mine", action="store_true")
    add("who", cmd_who).add_argument("query")
    x = add("share", cmd_share); x.add_argument("path"); x.add_argument("--with", dest="who", required=True)
    x.add_argument("--group", action="store_true"); x.add_argument("--perm", choices=PERMS, default="read")
    x.add_argument("--approved", action="store_true")
    x = add("email-share", cmd_email_share); x.add_argument("path"); x.add_argument("--email", required=True)
    x.add_argument("--expire"); x.add_argument("--perm", choices=PERMS, default="read")
    x.add_argument("--approved", action="store_true")
    x = add("link", cmd_link); x.add_argument("path"); x.add_argument("--expire")
    x.add_argument("--perm", choices=PERMS, default="read"); x.add_argument("--approved", action="store_true")
    add("unshare", cmd_unshare).add_argument("id")
    x = add("ext-ls", cmd_ext_ls); x.add_argument("--cred", required=True); x.add_argument("path", nargs="?", default="")
    x = add("ext-get", cmd_ext_get); x.add_argument("--cred", required=True); x.add_argument("path")
    x.add_argument("--to")
    x = add("ext-put", cmd_ext_put); x.add_argument("--cred", required=True); x.add_argument("local")
    x.add_argument("--overwrite", action="store_true")
    x.add_argument("path", nargs="?", default="")

    a = p.parse_args()
    PROFILE = a.profile
    a.fn(a)


if __name__ == "__main__":
    main()
