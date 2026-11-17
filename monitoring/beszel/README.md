# Beszel monitoring

[Beszel](https://github.com/henrygd/beszel) 0.21.2 shows CPU, memory, disk, network and Docker containers of one server. Here everything runs as one unprivileged user with rootless Docker, without `sudo`, and is reachable only on `127.0.0.1`.

| What | Where |
|---|---|
| Hub | container `beszel` (compose project `beszel`, `compose.yml`), `127.0.0.1:8090` |
| Hub data (database, SSH key `id_ed25519`) | `~/.local/share/beszel/hub` |
| Agent | `~/.local/bin/beszel-agent`, user unit `beszel-agent.service` |
| Agent socket | `~/.local/share/beszel/socket/beszel.sock`, mounted into the hub as `/beszel_socket/beszel.sock` |
| Agent data | `~/.local/share/beszel/agent` |
| Agent key | `~/.config/beszel/agent.env` (mode 600, not in Git; see `agent.env.example`) |

The agent is a binary, not a container: the network namespace of rootless Docker hides the real network traffic. The hub reaches it over SSH on the unix socket; there is no TCP port, no `HUB_URL` and no `TOKEN`.

## Set up

As the service user, with `DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock`, from the root of this repository:

1. `mkdir -p ~/.local/share/beszel/{hub,socket,agent} ~/.config/beszel` (the agent falls back to `~/.config/beszel` if its data folder is missing).
2. `docker compose -f monitoring/beszel/compose.yml up -d`; the hub writes `id_ed25519` on its first start.
3. `echo "KEY=$(ssh-keygen -y -f ~/.local/share/beszel/hub/id_ed25519)" > ~/.config/beszel/agent.env && chmod 600 ~/.config/beszel/agent.env` (only the public key).
4. Download `beszel-agent_linux_amd64.tar.gz` and `beszel_0.21.2_checksums.txt` from the GitHub release, then `grep ' beszel-agent_linux_amd64.tar.gz$' beszel_0.21.2_checksums.txt | sha256sum -c`, `tar xzf beszel-agent_linux_amd64.tar.gz beszel-agent` and `install -m 755 beszel-agent ~/.local/bin/`.
5. `cp monitoring/beszel/beszel-agent.service ~/.config/systemd/user/ && systemctl --user daemon-reload && systemctl --user enable --now beszel-agent`.

Then, as the operator:

1. Tunnel from your laptop: `ssh -N -L 8090:127.0.0.1:8090 <server>` and open `http://localhost:8090`.
2. Create the account on the first-run page.
3. "Add system": any name, host `/beszel_socket/beszel.sock` (the port field disappears). Type the host rather than pasting it; a pasted leading tab is stored with it and the system stays down. The key the dialog shows is the one already in `agent.env`; the token is not needed.

## Operate

- Update: bump the image tag in `compose.yml` and run `docker compose -f monitoring/beszel/compose.yml up -d`; repeat step 4 with the new version, then `systemctl --user restart beszel-agent`. Keep hub and agent on the same version.
- Check: `systemctl --user status beszel-agent`, `journalctl --user -u beszel-agent -n 20`, `curl -fsS http://127.0.0.1:8090/api/health`.
- Remove: `systemctl --user disable --now beszel-agent`, delete the unit and `~/.local/bin/beszel-agent`, `docker compose -p beszel down`, then `rm -rf ~/.local/share/beszel ~/.config/beszel`.

## Limits

- The hub runs on the server it watches, so it cannot alert when that server is down.
- No S.M.A.R.T. data (no `smartctl` and no capabilities in a user unit) and, on most VPS, no temperatures.
- Per-container block I/O stays 0 unless the `io` cgroup controller is delegated to the user's systemd instance (a root drop-in for `user@<uid>.service` with `Delegate=cpu cpuset io memory pids`).
