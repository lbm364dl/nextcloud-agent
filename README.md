# nextcloud-agent

A Claude Code plugin that lets AI agents use **any Nextcloud**, such as an institutional one, safely:
- browse, search and download files, without a local sync copy;
- upload, only into folders you allow;
- share with colleagues, by email or through protected links, only after you approve each share.

## Install

```
/plugin marketplace add lbm364dl/nextcloud-agent
/plugin install nextcloud@nextcloud-agent
```

You also need [rclone](https://rclone.org/install/) on your `PATH`, and Python 3, which ships with Linux and macOS.

## Set up an account (once)

1. **Create an app password** in Nextcloud: avatar → *Personal settings* → *Security* → *Devices & sessions* → name it e.g. `claude-agents` → *Create new app password*. You can revoke it at any time from the same page.
2. **Save it yourself**, so it never enters the chat. In Claude Code:
   ```
   ! mkdir -p ~/.config/nextcloud-agent && read -rsp "app password: " P && printf '%s' "$P" > ~/.config/nextcloud-agent/myserver.app-password && chmod 600 ~/.config/nextcloud-agent/myserver.app-password && unset P && echo saved
   ```
3. Ask Claude: *"set up the nextcloud profile `myserver` for https://cloud.example.org with my login `jdoe`"*. It runs `setup` and checks the connection.

Several servers or accounts can be configured as separate profiles.

## What agents may and may not do

| Allowed | Needs your explicit OK | Never |
|---|---|---|
| list, search, download | share with a person or group | delete, move or rename |
| upload into `write_allowed` folders (default `agents/`) | share by email | upload outside allowed folders |
| see what is shared with you or by you | create a link (always with a password and an expiry) | download credential-looking files (`.env`, keys, tokens) unless you ask for that exact file |
| remove a share | | print passwords |

Everything an agent writes or shares is logged in `~/.cache/nextcloud-agent/<profile>/actions.log`.

### Things to know

- A file in your own space is **private** until shared.
- Anything written into a **shared folder** is visible to everyone that share reaches. That includes a public link on a parent folder.
- **Share levels:**
  - `read`;
  - `drop` (upload only);
  - `contribute` (read, add and change, never delete);
  - `edit`.
- **People without an account:** they can still receive files through an email share or a protected link. Their own agents can read from it (`ext-ls` / `ext-get` / `ext-put`) using only the link and the password.
- **Local copy:** if the Nextcloud desktop client syncs your account, reads use the local file when it's identical to the server's. Writes always go over the network.

## Files

- `plugins/nextcloud/skills/nextcloud/SKILL.md`: the instructions Claude follows.
- `plugins/nextcloud/scripts/nextcloud.py`: the command-line helper. Python standard library plus `rclone`.
- `tests/selfcheck.py`: offline checks of the guard rails. Run it with `python3 tests/selfcheck.py`.

## Local state (never in this repo)

- `~/.config/nextcloud-agent/config.json`: profiles (server, login, allowed folders).
- `~/.config/nextcloud-agent/*.app-password`: app passwords, mode 600.
- `~/.cache/nextcloud-agent/`: file index, downloads, action log.
