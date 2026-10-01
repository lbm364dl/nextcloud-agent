---
name: nextcloud
description: Use the user's Nextcloud (any server, e.g. an institutional one) without needing a local sync copy. List, search, download, upload into allowed folders, see shares, share with users, groups or by email, and create protected links, the last three only with the user's explicit OK. Also receive shares someone sent by link. Use whenever a task needs a file "in Nextcloud" or "on the cloud drive", or sending files to a collaborator.
---

# Nextcloud for agents

```
NC="python3 ${CLAUDE_PLUGIN_ROOT}/scripts/nextcloud.py"
```

Works over the network (WebDAV via `rclone`, sharing via Nextcloud's OCS API).
Each **profile** is one server and account. Its app password lives in a
private file (mode 600). **Never print, copy or ask for a password.** Use
`--profile NAME` for a non-default profile.

## First-time setup (the human does the password part)

1. Install `rclone` if `which rclone` finds nothing (https://rclone.org/install/).
2. The user creates an **app password** in Nextcloud: avatar > Personal
   settings > Security > Devices & sessions > "Create new app password".
3. The user saves it **themselves**, so it never enters the chat:
   ```
   ! mkdir -p ~/.config/nextcloud-agent && read -rsp "app password: " P && printf '%s' "$P" > ~/.config/nextcloud-agent/<profile>.app-password && chmod 600 ~/.config/nextcloud-agent/<profile>.app-password && unset P && echo saved
   ```
4. `$NC setup --profile <profile> --url https://<server> --user <login>`. This
   checks the connection.
5. Optional: `$NC index` builds a file index for fast search.

## Everyday use

```bash
$NC check                         # connected? quota, top folders
$NC ls some/folder/
$NC find "*report*2025*" --in projects   # search names (run `index` when stale)
$NC get projects/x/data.csv       # identical local synced copy if any, else download; prints the path
$NC put out.csv agents/run-42/    # upload, only into allowed folders
$NC shares                        # shared with me   (--mine: shared by me)
$NC who "Garcia"                  # find a user's login or a group to share with
```

- **Local copy:** if the Nextcloud desktop client syncs this account, `get`
  uses the local file when it is identical (same size), and never for paused
  or placeholder-only syncs. `where PATH` explains which applies, `get
  --remote` forces a download, and `NEXTCLOUD_NO_LOCAL=1` disables local use.
  Writes always go over the network: immediate, logged, and no sync-conflict
  copies.
- Download only what the task needs; files land in
  `~/.cache/nextcloud-agent/<profile>/files/`.

## Hard rules

1. **Never delete, move or rename anything** on the server. The script has no
   command for it; do not work around that with raw rclone.
2. **Write only inside `write_allowed`** (per profile, in
   `~/.config/nextcloud-agent/config.json`; default `agents/`). Files written
   into a folder that is shared, or covered by a public link, are visible to
   everyone that share reaches. Tell the user if that applies.
3. **Giving anyone new access needs the user's explicit OK for that exact
   share.** That covers `share`, `email-share` and `link`. Ask in plain words
   ("Share `reports/x.pdf` view-only with Ana García?"), and pass `--approved`
   only after a yes. Links and email shares always get a password and an
   expiry date. Removing access (`unshare ID`) needs no approval.
4. **Never download or print credentials.** `get` refuses names that look like
   secrets (`.env`, keys, tokens, passwords, `*key*.json`) unless the user asks
   for that exact file (`--allow-secret`). Never echo their contents.
5. Licensed papers and data stay private or shared with named people, never in
   links.
6. Every write and share is logged in
   `~/.cache/nextcloud-agent/<profile>/actions.log`.

## Sharing levels

`--perm read` (view) · `drop` (upload only; cannot see the folder) ·
`contribute` (read, add and change, never delete) · `edit` (everything). Use
the least that does the job; `contribute` for working together.

- **People with an account on the same server:** `who NAME`, then
  `share PATH --with LOGIN --perm contribute --approved` (or `--group`). It
  appears in their "Shared with me", and their own agents use it with their
  own app password. No link or password changes hands.
- **People without one:** `email-share PATH --email ADDR --expire YYYY-MM-DD
  --approved`. The server emails them a personal link and, separately, its
  password. That only happens if the server has share-by-email enabled; check
  with the admin if no email arrives.

## Receiving a share (no account needed)

For a share link someone sent, save it as a private file: the link on line 1
and the password on line 2, mode 600. The human pastes them with a hidden
`! read -rsp …` command. Then:

```bash
$NC ext-ls  --cred ~/.config/nextcloud-agent/share-<name>
$NC ext-get --cred ~/.config/nextcloud-agent/share-<name> path/file.csv
$NC ext-put --cred ~/.config/nextcloud-agent/share-<name> result.csv   # if the share allows uploads
```

This uses `/public.php/dav/files/<token>/` with the header
`X-Requested-With: XMLHttpRequest`. Without that header Nextcloud answers 401.
