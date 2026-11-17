# Agent VPS: setup and hardening

A pattern for one Linux VPS (Ubuntu 24.04 LTS) that runs coding agents in rootless containers (`nc-work`) and, optionally, a few static websites. Placeholders:

| Placeholder | Meaning |
|---|---|
| `<server>` | the host name of the VPS in your tailnet and in `~/.ssh/config` |
| `<admin-user>` | the only user with `sudo`; used by a human, never by agents |
| `<work-user>` | the user that runs agents, Docker and `nc-work`; no `sudo` |

The guiding rule: agents run as `<work-user>` and can never become root. Everything that needs root is done by a human as `<admin-user>`, from a separate SSH key.

## 1. Users and access

1. Start from a minimal image and take a provider snapshot after this section.
2. Create the admin user, with its own password for `sudo`:

   ```sh
   adduser --disabled-password --gecos "" <admin-user>
   passwd <admin-user>
   usermod -aG sudo <admin-user>
   ```

   Put its public key into `/home/<admin-user>/.ssh/authorized_keys` (folder 700, file 600, owned by `<admin-user>`). On your laptop, use a separate key with a passphrase for it, and keep that key out of any SSH agent that coding agents on the laptop can use (for OpenSSH on macOS: `UseKeychain no` and `AddKeysToAgent no` in a `Host <server>-admin` block above `Host *`).
3. Test `ssh -t <server>-admin 'sudo -k; sudo whoami'` (prints `root`). Only then create `<work-user>` without `sudo`, or remove it from the group: `sudo deluser <work-user> sudo`, and check that `sudo grep -rn <work-user> /etc/sudoers /etc/sudoers.d/` prints nothing.
4. Keep a root password only for the provider's web console, stored in a password manager. Test it once. Web consoles often type with a US keyboard layout, so choose characters that are the same on your layout.
5. Turn on unattended upgrades.

## 2. Firewall and SSH

- Install Tailscale and reach SSH only through the tailnet. With `ufw`: default deny incoming, allow in on `tailscale0`, plus `80/tcp` and `443/tcp` only if the server hosts websites, and `41641/udp` for direct Tailscale connections.
- sshd may still listen on all addresses; the firewall is what closes it. Check from outside the tailnet that port 22 does not answer.
- Put the SSH settings into a drop-in that sorts first, e.g. `/etc/ssh/sshd_config.d/00-hardening.conf`:

  ```
  PermitRootLogin no
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  ```

  sshd takes the first value it reads, so this file wins over later lines in `sshd_config`. Check: `sudo sshd -T | grep -Ei '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication) '` shows `no` three times.
- Service users that must never log in (such as a hosting user, below) get `DenyUsers <name>` in another drop-in.

## 3. Rootless Docker for the work user

- Packages: `uidmap` (rootless Docker), `libatomic1` (Node builds from version managers on minimal images).
- Install rootless Docker as `<work-user>` (`dockerd-rootless-setuptool.sh install`) and let its user services run without a login: `sudo loginctl enable-linger <work-user>`.
- `DOCKER_HOST=unix:///run/user/<uid>/docker.sock` for `<work-user>`.
- Publish container ports only on `127.0.0.1`, never on `0.0.0.0`; reach them through an SSH tunnel (`ssh -N -L 8080:127.0.0.1:<port> <server>`). Long-running development databases get `restart: unless-stopped`, or they stay down after a reboot.
- `nc-work` then adds its own isolation per task (internal networks, egress proxy, read-only root, no capabilities); see `docs/design.md`.

## 4. Optional: static websites with Caddy

Run Caddy from the official Caddy apt repository (distribution packages are often too old for current site files) as the system service.

- Two service users with lingering and mode-700 homes: `host` (live sites, e.g. `/srv/hosting`) and `staging` (`/srv/staging`). Neither can log in over SSH.
- Admin API on a unix socket instead of a TCP port:

  ```
  {
  	admin unix//run/caddy/admin.sock
  }

  # No project is public until its route is explicitly added.
  :80 {
  	respond "No project configured for this hostname." 404
  }

  import /etc/caddy/staging.d/*.caddy
  import /etc/caddy/hosting.d/*.caddy
  ```

  A systemd drop-in for `caddy.service` creates `/run/caddy` (mode 750) and replaces `ExecReload` (an empty `ExecReload=` line first, then) with `caddy reload --config /etc/caddy/Caddyfile --address unix//run/caddy/admin.sock --force`.
- One site is one root-owned file in `hosting.d` or `staging.d`. Validate before every reload: `sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile && sudo systemctl reload caddy`. A site with its own server process listens on `127.0.0.1` behind `reverse_proxy`.

**Pull deploy (optional).** Agents never get a key to the server. A site goes live when its default branch on GitHub changes:

- A root-owned script and a systemd timer/service pair (`User=host`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=full`) fetch `origin/main` every minute into a deploy clone, build a new commit and `rsync --delete` the output into the web root.
- `host` has a read-only deploy key for that one repository and a pinned `known_hosts` for GitHub.
- A failed build keeps the old site online and is not retried for the same commit. If the repository's copy of the site file, script or units differs from the installed one, the script holds or warns in the journal and a human installs the new version with `sudo`; a commit can never change root-owned files.
- Roll back with `git revert` and a merge. Merging into the default branch is publishing, so treat merge rights as deploy rights; on plans without branch protection this is a rule, not a lock.

## 5. Resource limits

Anything that faces the internet should not be able to starve the agents. For Caddy, `/etc/systemd/system/caddy.service.d/limits.conf`:

```
[Service]
CPUQuota=200%
MemoryHigh=768M
MemoryMax=1G
Restart=on-failure
RestartSec=2s
```

Size the numbers to your machine. This protects the rest of the server, not the site. `nc-work` sets CPU, memory and process limits per task itself and runs at most three agent containers at once.

## 6. Logs and privacy

- `/etc/systemd/journald.conf.d/retention.conf` with `MaxRetentionSec=7day` and `MaxFileSec=1day` (or whatever your privacy policy promises for IP addresses).
- Keep web server messages out of `/var/log/syslog` if they can contain IP addresses, e.g. `/etc/rsyslog.d/10-no-caddy.conf` with `:programname, isequal, "caddy" stop`.
- Sites that need no access log should not write one.

## 7. Backups

- Provider snapshots after each milestone (base system, users, web server). Note whether your provider can only take them with the machine offline.
- Everything important is in Git: projects, this repository, the nc-harness checkout and its memory repository. What is not in Git and must be backed up separately: `~/.config/nc-harness/secrets.env`, the Claude tokens under `~/.local/share/nc-work/auth/`, deploy keys, and database volumes of long-running services.
- Never put keys into a repository, including private ones.

## 8. Monitoring (optional)

`monitoring/beszel/` has a Beszel hub and agent that run entirely as `<work-user>`, reachable only on `127.0.0.1`; see its README.

## 9. What not to co-host

- No production database or production keys of a client on the same machine as the agents. A client that needs that gets its own server.
- No service that listens on a public address without the firewall in front of it; containers publish to `127.0.0.1` only.
- No Docker socket, SSH agent or host home mounted into an agent container.
- No `sudo` for `<work-user>`, and no admin key on a machine where agents run unattended.

## Checks

```sh
sudo ufw status verbose
sudo sshd -T | grep -Ei '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication) '
systemctl show caddy -p CPUQuotaPerSecUSec -p MemoryHigh -p MemoryMax -p Restart
loginctl show-user <work-user> -p Linger
```
