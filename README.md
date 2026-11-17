# nc-infra

Infrastructure for running coding agents on your own Linux server:

- [`work-environments/`](work-environments/README.md): `nc-work`, one rootless Docker container per agent task with an egress allow list, no credentials inside, and host-side publishing. Works with [nc-harness](https://github.com/iAmSerathion/nc-harness) (rules, model policy, memory, delegation) and optionally the [herdr-nc](https://github.com/iAmSerathion/herdr-nc) card.
- [`docs/vps-setup.md`](docs/vps-setup.md): setting up and hardening the server underneath (admin user, firewall, Tailscale-only SSH, rootless Docker, optional Caddy with pull deploy).
- [`docs/design.md`](docs/design.md): how `nc-work` behaves in detail and why.
- [`monitoring/beszel/`](monitoring/beszel/README.md): optional Beszel monitoring that runs without root.

Getting started: follow `docs/vps-setup.md` for the server, then `work-environments/README.md`.

Private profiles and rules never go into this repository: put them into `~/.nc/overlay` (see `work-environments/README.md`).

## Licence

MIT, see [LICENSE](LICENSE).
