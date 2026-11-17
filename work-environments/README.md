# nc-work: isolated work environments for coding agents

`bin/nc-work` runs Claude Code and OpenCode in one rootless Docker container per task, on a Linux server. Each task gets its own internal network behind an egress proxy with an allow list, its own workspace and home volumes, a read-only snapshot of [nc-harness](https://github.com/iAmSerathion/nc-harness), and no credentials: GitHub pushes happen on the host, the Claude token is passed per session, and the OpenRouter key stays in a key proxy outside the agent container. The full reference is [`docs/design.md`](../docs/design.md).

## Requirements

- A Linux host (tested on Ubuntu 24.04) with rootless Docker for an unprivileged user, `uidmap`, lingering on, and Python 3. [`docs/vps-setup.md`](../docs/vps-setup.md) describes such a server.
- nc-harness checked out at `~/projects/personal/nc-harness` and installed (`./install.sh`). `nc-work` calls its `bin/nc` on the host for model policy, agent files, memory and delegation.
- Projects as Git checkouts below `~/projects`, one profile per project.
- For OpenCode: OpenRouter keys in `~/.config/nc-harness/secrets.env` (see nc-harness). For Claude: a Claude subscription (`nc-work auth-login`).

## Install

```sh
git clone https://github.com/iAmSerathion/nc-infra.git ~/projects/personal/nc-infra
ln -s ~/projects/personal/nc-infra/work-environments/bin/nc-work ~/.local/bin/nc-work
```

Build the image once (the binaries are not in Git; their checksums are):

1. Put the Node versions from `VERSIONS` in `bin/nc-work` under `images/toolchains/node/<version>/` and Bun 1.4.4 under `images/toolchains/bun/1.4.4/` (official release archives, checksums verified).
2. Put the Linux x64 binaries of Claude Code and OpenCode at `images/claude` and `images/opencode`; the versions must match `pins.txt` in nc-harness and the files `images/*.sha256`.
3. `cd work-environments && sha256sum -c images/claude.sha256 images/opencode.sha256 && docker build -t nc-work:<date> images`, then set `IMAGE` in `bin/nc-work` to that tag.

Then `nc-work snapshot` publishes the harness snapshot for new tasks.

## Profiles and the overlay

A profile (`profiles/<id>.json`) names the project folder below `~/projects`, its GitHub repository, Node version, preview ports, allowed internet targets and limits. The shipped profiles are examples; copy one and adapt it.

Your own files go into one fixed folder, `~/.nc/overlay` (usually a link to a private Git checkout):

| In `~/.nc/overlay` | Effect |
|---|---|
| `profiles/<id>.json` | added to the shipped profiles; wins on the same id |
| `AGENTS.md`, `models.yaml` | baked into the harness snapshot instead of nc-harness' public defaults (regular files only, at most 256 KiB, committed) |

Nothing else in the overlay reaches a container. No environment variable moves the overlay. `NC_HOME` moves nc-harness' own folder, and with it the memory checkout `nc-work` reads (default `~/.nc/memory`).

## First task

```sh
nc-work profiles
nc-work auth-login                       # once: Claude token for all projects
nc-work create example-site layout       # from the last commit of ~/projects/sites/example-site
nc-work claude layout                    # or: nc-work opencode layout
nc-work publish layout                   # dry run; --push pushes the task branch from the host
nc-work remove layout
```

`nc-work here` picks or creates a task for the project of the current folder and starts Claude (`--runtime opencode` for OpenCode); the herdr card [herdr-nc](https://github.com/iAmSerathion/herdr-nc) calls it from its menu. `nc-work broker` runs in the foreground and serves `nc delegate` and `nc memory add` from inside tasks.

## Tests

```sh
cd work-environments && python3 -m unittest tests/test_policy.py
```

Some tests read `/proc` and pass only on Linux.
