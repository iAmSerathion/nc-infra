# nc-work: design and behaviour

The detailed reference for `work-environments/bin/nc-work`. For installation and first steps see
[`work-environments/README.md`](../work-environments/README.md); for the server underneath see [`vps-setup.md`](vps-setup.md).
Paths are those of the host user that runs `nc-work` (`~` is that user's home).

## Basic use

```sh
~/.local/bin/nc-work profiles
~/.local/bin/nc-work create example-site website-layout
~/.local/bin/nc-work enter website-layout
~/.local/bin/nc-work status website-layout
~/.local/bin/nc-work stop website-layout
~/.local/bin/nc-work start website-layout
```

A task gets its own container, its own internal network and its own persistent workspace and home volumes. Several tasks of the same project are possible. At most three agent containers run at the same time, each with at most 2 CPUs and 4 GiB RAM. Stopped containers keep their data. `create` and `start` are serialized on the server.

On creation, only Git-committed data of the clean canonical checkout is taken over. Unversioned `.env` files, local dependencies and personal configuration are not copied. Data already stored in Git and its history remain part of the project; the import is not a secret scanner. Every task gets `nc-work/<task-name>` as its branch, at first without a Git remote.

## Starting from herdr: `nc-work here`

In herdr, choose "Claude (isolated)" in the menu (entry in `programs.json` in the herdr-nc repo). This calls `nc-work here` in the folder of the space. "OpenCode (isolated)" calls `nc-work here --runtime opencode`, the same with OpenCode instead of Claude (see "OpenCode with OpenRouter key").

1. The folder determines the profile (subfolders too, e.g. `apps/example-monorepo/packages/shared`). Folders without a profile (`nc-harness`, `nc-infra`, …) are refused; use the normal "Claude Code" there.
2. A selection shows the tasks of this project with their state. A number continues a task (a stopped container is started), `n` creates a new one. Pressing Enter twice creates a task named `<profile>-<MMDD-hhmm>`.
3. If three tasks are already running, the selection asks which one to stop.
4. Then Claude starts in the container. After it exits, the screen shows how many commits the task has and how to upload them with `nc-work publish TASK --push`.

A new task starts from the last commit of the checkout in `~/projects`; if the checkout has local changes, it is refused. The herdr cards "Folders" and "Git" show the checkout on the server, not the work in the container.

## Usage cards in herdr: `nc-work feed`

The cards "Usage by model" and "Used in this session" (mod `nc-session` in herdr-nc) call `nc-work feed --pid <pid> --script <usage.py> [--since <sig>]` on the server for an isolated session. `pid` is the foreground process of the herdr terminal. The orchestrator card (mod `nc-orchestrator`) adds `--orch`, which is passed to the script before `--since`.

- `nc-work claude` creates `~/.local/share/nc-work/sessions/<own pid>.json` with the task at start and gives Claude the marker `NC_HOST_PID=<own pid>`. At the end the file is deleted.
- `feed` finds the task through the process chain of the terminal, starts a short Python in the container that finds the Claude process with this marker, and runs the given script against it. It only reads `/proc` and `~/.claude` there, writes nothing and has no network except that of the task.
- Without an isolated session, `feed` answers with `{"error": "not-isolated"}`.

## Removing tasks: `nc-work remove`

```sh
nc-work remove TASK [TASK …]
```

Deletes the container, proxy, network, volumes, state and the agents folder of the task, plus leftover key proxies (through the label `task=`) and their lock files. Refused if the workspace has uncommitted changes or the task branch contains commits that are not on GitHub exactly as they are (checked offline and read-only in a throwaway container, compared with `git ls-remote` from the host). Also refused if memory requests are in the outbox (waiting or refused); the message lists all reasons at once. `--discard-memory` deletes the whole task and drops the requests; the check for unpublished work stays. A refused request in a task that should stay is dropped by hand: delete the file and its `.reason` in `~/.local/share/nc-work/memory/<task>/outbox/`. If Docker does not answer, `remove` refuses without `--force` ("work check not possible"). `--force` deletes anyway and drops everything. The memory folder is deleted before the task file so that an interrupted cleanup can be repeated; `create` refuses as long as an old memory folder of the same name exists.

Tasks with a mailbox for `nc delegate` (see "Broker") also have `~/.local/share/nc-work/broker/<task>/{requests,inbox}`. `remove` deletes that folder too; for files or folders the container created in the mailbox as a sub-UID, it uses a throwaway container as root (as for memory), and it also deletes the staging copies of the broker for this task. If requests are still in the mailbox (files without a leading dot), `remove` refuses and names it together with the other reasons; `--discard-requests` deletes the task and drops them, the check for unpublished work stays (as with `--discard-memory`). `--force` still deletes everything. `--delivered` does not apply together with `--discard-requests`. Running workers of the task are left alone; their results then stay in `~/.nc/delegate/<id>`, and the broker writes nothing more into an inbox that no longer exists. `create` refuses as long as an old mailbox folder of the same name exists.

## Profiles

A profile is one JSON file per project: `id`, folder below `~/projects` (`path`), GitHub repository, Node version, package manager, preview ports, allowed internet targets and protected branches. A `limits` entry is descriptive only: every task gets 2 CPUs, 4 GiB RAM and 512 processes, fixed in `bin/nc-work`. `nc-work` reads `~/.nc/overlay/profiles/` first and then `work-environments/profiles/`; a profile in the overlay wins on the same id, and `nc-work profiles` lists both. The shipped profiles are examples:

| Profile | Node | Tools / preview ports in the container |
| --- | --- | --- |
| example-site | 24.22.3 | static website; 8080 |
| example-bun-app | 24.22.3 | Bun; 3000, 5173 |
| example-monorepo | 20.20.2 | pnpm 9.15.9, task-local Postgres and Redis; 3000, 3001, 3002, 8081 |
| herdr-nc | 24.22.3 | configuration work; UI checks stay on the desktop |

Bun 1.4.4, Claude Code 2.1.322, OpenCode 2.2.7, Git, Python, compilers and browser runtime libraries are in the shared image. Project-specific packages and browser downloads are installed inside the task. Xcode and iOS simulators are not server tools.

The profiles contain exact allowed internet targets for package registries, source code downloads, Claude, OpenRouter (`openrouter.ai`, for OpenCode) and necessary project-specific downloads. Unknown targets, private networks, Tailscale, localhost and the public address of this server are blocked at the egress proxy. The server's own addresses are not fixed in the code: `nc-work` reads them with `ip -j addr show scope global` when it creates a task (only publicly routable ones; IPv4 as /32, IPv6 as its prefix but never narrower than /64) and refuses to create an online task without one. A task keeps the addresses from its creation; after a server rebuild with new addresses, create online tasks again. Direct internet connections from the agent container are not possible. These allowances are no guarantee against data transfer to the explicitly allowed services.

External databases are not assigned. Local Postgres/Redis services (`local_services`) are described but not started automatically, and shared development databases on the host are never connected. `commands` and `local_services` are profile entries; the launcher does not run them automatically.

## Private preview

`nc-work status TASK` shows the ports actually assigned. Example: the output `3000/tcp -> 127.0.0.1:32771` means, on your laptop (`<server>` is the server's SSH host name, see `vps-setup.md`):

```sh
ssh -N -L 8080:127.0.0.1:32771 <server>
```

Then open `http://localhost:8080`. Take the port number from the actual output. The development server in the container must listen on `0.0.0.0`; on the server the forwarding is bound to `127.0.0.1` only. The fixed preview relay leads only to the matching agent container. No public domain is set up.

## Shared harness

New tasks use the snapshot named in `~/.local/share/nc-work/harness-current.json`: a read-only copy of a committed nc-harness checkout under `~/.local/share/nc-work/harness/<tag>`, mounted at `/opt/nc-harness`.

`nc-work snapshot` takes `git archive` of the harness HEAD (refused while the checkout has uncommitted changes) and adds the overlay's `AGENTS.md` (optional) and `models.yaml` from `~/.nc/overlay` over the public defaults. If `~/.nc/overlay` exists, `models.yaml` is required: an overlay without it is refused. Only those two files of the overlay reach a container; profiles, docs and anything else stay on the host. Each must be a regular file, not a link, at most 256 KiB, and committed if the overlay is a Git checkout; otherwise the snapshot is refused. The tag is the harness commit, plus `-<12 hex>` of a SHA-256 over the overlay files when there are any, so a changed overlay gives a new snapshot. The copy is built in `<tag>.tmp` and then renamed. Policy decisions on the host (the key, the agent files) always read the live host checkout and overlay, never the snapshot.

The start script links the rules for Claude and OpenCode (`~/.claude/CLAUDE.md`, `~/.config/opencode/AGENTS.md`), `~/.claude/skills` as a whole to `/opt/nc-harness/skills` (OpenCode reads skills there too), the OpenCode configuration `adapters/opencode/opencode.json`, and `service.json` and `nc`. The subagents do not come from the snapshot but from their own mounts (see "Subagents and orchestrator"). The harness therefore never gets a top-level folder `agents`: an image built from an older `images/entrypoint` would link it to `~/.claude/agents`, where the read-only mount sits, and every new container would fail at start. In `images/entrypoint`, `agents` is taken out of the loop. Personal skills from the host home are not taken over. `nc doctor` recognizes the container by `NC_HARNESS_VERSION` and checks there only what must hold in the container.

`nc-work snapshot` deliberately publishes a new snapshot from a clean harness checkout for future tasks. Running or existing tasks keep their previous state; updating all tasks has to be done on purpose.

## Shared memory

New tasks get two additional mounts for the memory of nc-harness (`nc memory`, on the host in `$NC_HOME/memory`, default `~/.nc/memory`, the same rule as nc-harness):

| In the container | On the host | Content |
| --- | --- | --- |
| `/opt/nc-memory`, read-only, `NC_MEMORY_DIR` | `~/.local/share/nc-work/memory/<task>/view` | only `MEMORY.md`, `global/` and `projects/<profile>.md`; no other projects, no journal, no links |
| `/opt/nc-memory-outbox`, writable, `NC_MEMORY_OUTBOX` | `~/.local/share/nc-work/memory/<task>/outbox` | fallback for `nc memory add` without the broker, one JSON file per note |

`nc memory add` sends a note through the mailbox to the broker, which applies it immediately (see "Broker", memory requests). The outbox is only a fallback now: for tasks without a mailbox and when the broker is not running.

The state is rewritten on creation, on every start of `nc-work claude`/`opencode`, after `memory-apply` and after every stored note of the broker (`stored`), into the same folder so that a running container sees it. Each file is replaced atomically on its own (`.<name>.tmp`, then renamed), and only afterwards does what no longer belongs disappear; so an `nc memory search` never finds an empty state. While doing so, `nc-work` holds a shared `flock` on the folder `~/.nc/memory`, the same one `nc memory` takes exclusively when writing, so that no half `pull` is copied. If it does not get the lock within 30 seconds (or the folder is missing), it continues with a warning without the lock; creating or starting a task never fails because of it. In addition, every run holds an exclusive `flock` on the folder of the task (`~/.local/share/nc-work/memory/<task>`) for its whole duration: two runs for the same task (the broker after `stored` and a session start) use the same temp names; the second waits until the first is done. The outbox has mode 777: the container user is a sub-UID on the host, the folder belongs to the host user, who can delete everything in it.

```sh
nc-work memory-apply TASK [TASK …]   # without names: all tasks with memory
```

Calls `nc memory apply --outbox <outbox> --project <profile>` from the harness checkout for each task. The profile comes from the records of `nc-work`, never from the request; the harness refuses requests with a project field. Applied requests are deleted, refused ones stay with `<file>.reason`. After a session, `nc-work` reports when requests are waiting. Transfer from the outbox happens only on this command. `nc memory apply` shows each request with its outcome and text (for `replaces` old → new); the same lines are in the commit. `nc-work remove` refuses as long as requests are in the outbox or in the mailbox (nc delegate, nc memory) (`--discard-memory` drops them, `--force` deletes everything, including folders the container created there).

Older tasks have neither the mounts nor the command `nc memory`: their harness state is the snapshot from their creation, and `nc memory` ends there with `nc: unknown command: memory`. For memory, create a new task after `nc-work snapshot`. The message "NC_MEMORY_DIR is not set" appears only when a new harness snapshot meets an `nc-work` without these mounts.

## Subagents and orchestrator

New tasks get the same subagents as the host, with model and effort from `models.yaml` and according to the policy of the project: in a project whose policy denies free models the OpenCode researcher with the free model is missing.

| In the container | On the host | Content |
| --- | --- | --- |
| `/home/agent/.claude/agents`, read-only | `~/.local/share/nc-work/agents/<task>/claude` | Claude subagents (user level of Claude Code) |
| `/etc/opencode/agents`, read-only | `~/.local/share/nc-work/agents/<task>/opencode` | OpenCode subagents (system folder of OpenCode, applies last) |

- `create` creates the two folders (0755), mounts them and sets `NC_AGENTS=/home/agent/.claude/agents:/etc/opencode/agents` (for `nc doctor`) and `NC_PROJECT_PATH=<profile path>` (for `nc models`). The helper run as root first creates `~/.claude/agents` in the home volume and hands it to uid 1000; otherwise Docker creates `.claude` as root for the mount, and the start script fails. The task entry has `"agents": true` and `"project_path"`. `create` generates nothing; the first session start does that. A leftover agents folder of the same name is refused (run `nc-work remove` first).
- Before every session start (`nc-work claude`, `nc-work opencode`, also through `here`), `nc-work` calls the harness checkout on the host, never the snapshot: `~/projects/personal/nc-harness/bin/nc generate --out ~/.local/share/nc-work/agents/<task> --path ~/projects/<profile path>` (from `/`, at most 60 seconds, under a per-task lock in `.lock`). The files are replaced in the existing folder, never the folder itself; a running container sees the new version, and a running Claude session picks it up after a few seconds. Changes to `models.yaml` thus take effect at the next session start, without a new snapshot.
- `nc-work claude` starts Claude with `--model` and `--effort` from `nc models orchestrator` (harness checkout). If the orchestrator is not set there, without both and without a message.
- If something fails, the session starts anyway, with one warning line per call (at most two before Claude, at most one before OpenCode): `agents not generated (…) – the roles of the last start stay` before Claude, `… – OpenCode starts without roles` before OpenCode, and then the files in `opencode/` are deleted (the folder stays; never through a link) so that no agent runs with a model from an older state. `orchestrator setting not read (…) – Claude starts without --model and --effort`. If there was a warning line and stdin and stderr are a terminal, `nc-work` waits 3 seconds before the start, because Claude clears the screen at start (same for OpenCode). The reason for a warning is shown by `~/projects/personal/nc-harness/bin/nc generate --check --out ~/.local/share/nc-work/agents/<task> --path ~/projects/<profile path>`.
- `start` and `here` create missing folders before `docker start` (a container with a bind mount does not start without the source). A folder that is a link is not touched (warning line).
- If a folder is blocked (`nc generate` reports `… is not a generated file – the folder belongs to nc-work; remove it by hand`): delete the named file or subfolder in `~/.local/share/nc-work/agents/<task>/`; the next start generates again.
- `remove` deletes `~/.local/share/nc-work/agents/<task>` (even without a task entry), with no new refusal reason: the content is generated and can be restored.
- `nc-work` sets `umask 022`; the folders of the memory view and of the agents no longer depend on the umask of the caller.

Limits:

- Existing tasks do not get the roles. Mounts can only be set at creation; create a new task for that. They start as before, without a message.
- In Claude Code, a subagent of the same name in `.claude/agents` of the repo overrides the mounted file. User-level subagents cannot be created in the task (the folder is read-only; `/agents` no longer exists in Claude Code 2.1.322). Claude subagents always run through the Claude subscription.
- In OpenCode, the fields that the generated file sets stay (description, mode, `hidden: false`, model with variant, locks of the read-only roles). A project can, however, add fields that it does not set (e.g. `steps`, `request`), and bring its own agents with their own model, including a researcher with a free model in a restricted project. Checked with OpenCode 2.2.7 (file in `/workspace/.opencode/agents`): a different `model` has no effect; `request.body.model` is taken over (whether OpenRouter then gets a different model is not checked); `hidden: true` and `steps` are taken over when the generated file does not set them; permissions of the project come before the locks from `/etc`, and because the last matching rule applies, the locks hold; a custom researcher appears with its model when `/etc` has none. In addition, the orchestrator can choose any model per call through the parameter `model`. A free or not allowed model fails in restricted projects at the key (see "Which key").
- The model catalog in the container is the one built into OpenCode 2.2.7 . A newer model in `models.yaml` ends there with an error at the call; no other model steps in. Until a new image, take a model from the catalog.
- If generation fails before an OpenCode start, running OpenCode sessions of the same task also lose their roles.
- Generation uses the checkout on the host, `AGENTS.md` in the container comes from the snapshot. So the two can be of different age.
- The harness never gets a top-level folder `agents` (see "Shared harness").

## GitHub without credentials in the container

```sh
nc-work github-check TASK
nc-work publish TASK
nc-work publish TASK --push
```

`publish` is only a dry run by default. Only `--push` writes to GitHub. The trusted host exports Git objects from the task, checks them in a fresh bare repository and uses its own SSH login. The Git configuration and hooks of the container are not run on the host. Target repository and task branch are set by the host. Other branches, force push and merge are not available through this command. In particular, an automatically deploying branch such as `staging` is not written to.

The container gets neither an SSH agent socket nor keys or a GitHub token. Direct authenticated GitHub calls from the container are therefore not available. Automatic PR creation and the integration of this host command into an agent control are not implemented yet. Project-specific rules for commit/push still apply.

## Workers for `nc delegate`

`nc delegate` (harness) lets an OpenCode worker do a job in its own task and collects branch and `RESULT.md` on the host. For this, `nc-work` has five additions; nothing changes for image and mounts, and normal tasks get a mailbox (see "Broker").

```sh
nc-work profiles --json
nc-work create PROFILE TASK --worker
nc-work create PROFILE TASK --worker --from-task REQUESTER
nc-work export TASK --out DIR
nc-work remove TASK --delivered SHA
```

- `profiles --json` prints exactly one line: a JSON array `[{"id", "path", "github"}, …]`, sorted by `id`. Without `--json` the text output stays as it is.
- `create … --worker` creates a task like `create`, but without memory: no view, no outbox, no memory mounts, no `NC_MEMORY_DIR`/`NC_MEMORY_OUTBOX`. A worker thus never writes to the shared memory. The task entry has `"worker": true` and `"memory": false`. Agents folders, mounts and `NC_PROJECT_PATH` as for every new task (`opencode run --agent <role>` needs them).
- If three agent containers are already running, `create` ends with exit 3 and `nc-work: 3 tasks are already running; stop one first (nc-work stop <task>)`, before anything is stored. This also applies to `create` without `--worker`. Every other error stays exit 1 (the entry may then stay with `status: failed`).
- `create … --worker --from-task REQUESTER` lets the worker start from the last commit of a task instead of from the checkout in `~/projects`; the checkout is neither checked nor read. Only together with `--worker` (otherwise `wrong call`, exit 1, before anything else). All checks run before the entry is stored; a refusal leaves nothing behind and ends with **exit 4** (class `Refused`, one line `nc-work: <reason>` on stderr). Checked: the requester has an entry with `status: ready` and `"broker": true`, belongs to the same project as `PROFILE`, its container is running (`create` starts nothing), `git status --porcelain` is empty there as uid 1000 (`the requesting task has uncommitted changes – commit first`). Its `HEAD` comes out as a bundle (uid 1000, hooks and fsmonitor off, at most 200 MiB, size checked beforehand with `stat`, the bundle in the container is always deleted), is checked and fetched on the host in a throwaway folder (`bundle verify`, `fetch` of `HEAD:refs/heads/nc-from-task` with `transfer.fsckObjects=true`, then `git fsck`; the same steps as for `export`, in a shared function), and `base` is `rev-parse refs/heads/nc-from-task` in this repo, never something the container prints. The steps in the container (`git status`, `bundle create`, `stat`, copying) take at most 120 seconds each (for `export` 300 and 60). The Git steps on the host (`bundle verify`, `fetch`, `fsck`) can take up to 300 seconds each; for that long `create` holds the lock `launcher.lock`, and other `create`, `start` and `snapshot` calls wait. A timeout of Git on the host is an error (exit 1, "timeout in git …"), not a refusal. From this a bundle with `HEAD` and `nc-from-task` is made for the worker; after `git clone` and `switch -c nc-work/<task>`, `HEAD` in the worker must be exactly `base`, otherwise `create` fails (exit 1, entry `failed`). The entry additionally has `"from_task"` and `"from_token"` (the `broker_token` of the requester); `create` prints the whole entry as JSON on stdout, nothing else. **Project path:** the worker takes `project_path` from the entry of the requester, not the current path of the profile, for its own entry and for `NC_PROJECT_PATH` in the container; this way the same policy (and the same key) applies to it as to the requester, even if the profile looks different by now. The path is checked like `PROJECT_PATH` in the harness (parts of letters, digits, `.`, `_`, `-`, no `.` or `..`); if it is missing or invalid, `create` refuses (exit 4, `requesting task … has no valid project path in its record`), without falling back to the profile. Without `--from-task` it stays with the profile path.
- **Lock for the OpenCode project configuration:** between the `base` from the entry of the requester and the new `base`, nothing may have changed in `opencode.json`, `opencode.jsonc` and `.opencode/` (`git diff --quiet`), otherwise `the requesting task changed the OpenCode project configuration`; if the old `base` is not an ancestor of the new one (`merge-base --is-ancestor`, also if it is missing): `history rewritten – the base of the requesting task is not an ancestor of its last commit` (both exit 4). Reason (OpenCode 2.2.7): an `opencode.json` in the repo is loaded after the global configuration (with its `policies`) and before `/etc/opencode`. The model of a role from the generated agent file in `/etc/opencode/agents` does stay, but `policies`, `plugin` and `provider` of the project are read in. A requester that changes them could bring them into the worker this way. Limit of the lock: only these paths are locked. Files that an `opencode.json` points to (such as `instructions`, `{file:…}` values, prompt or plugin files elsewhere in the repo) are not; they are part of the working state of the worker. Since the `opencode.json` itself may not change, a requester can only change files it already pointed to at creation. Further reasons for exit 4: requester missing, not running, not a mailbox task, different project, bundle too large.

`export` (only for tasks with `"worker": true`, otherwise `not a worker task`) collects the result of a worker onto the host, similar to `publish`. Everything from the container counts as data: sizes are limited, links are not followed, every `docker exec` has a time limit (bundle and copying 300 seconds, otherwise 60), and nothing from the task is run on the host.

1. The container must be running; `export` does not start it but aborts with a reason. The task must be `ready`.
2. `DIR` must not exist yet (not even as a link); it is created with mode 700, and the parent folder must exist.
3. In the container as uid 1000: `git bundle create` only with `refs/heads/nc-work/<task>`, hooks and fsmonitor off. The size is checked beforehand with `stat` and limited once more while copying (`docker exec … cat`): at most 200 MiB, otherwise abort. The bundle file in the container is always deleted afterwards.
4. On the host: fresh `DIR/repo.git` (`git init --bare --template=`), `bundle verify`, then `fetch --no-tags` of only this one ref with `transfer.fsckObjects=true` and `gc.auto=0`, then additionally `git fsck` (Git before 2.46 skips `transfer.fsckObjects` when fetching from a bundle). The bundle is deleted, `repo.git` stays.
5. `/home/agent/.nc/RESULT.md` is read by a short `python3 -I -B` in the container as uid 1000: only a real file whose resolved path is exactly this one, opened without following links (`O_NOFOLLOW`, `O_NONBLOCK`), at most 64 KiB. The bytes land unchanged in `DIR/RESULT.raw`, only if the file exists. If it is missing or not readable, the export does not abort.
6. `DIR/export.json` and the same line on stdout, exit 0:

| Field | Content |
| --- | --- |
| `task`, `branch` | task and `nc-work/<task>` |
| `base` | base commit from the task entry |
| `head` | state of the branch in `repo.git` |
| `base_is_ancestor` | whether `base` is an ancestor of `head` (`false` if `base` is missing in the bundle) |
| `commits` | `rev-list --count base..head`, `null` if `base_is_ancestor` is false |
| `dirty` | whether `git status --porcelain` reports anything in the container (only yes/no) |
| `result_file` | `present`, `truncated` (more than 64 KiB, the first 64 KiB are in `RESULT.raw`), `missing` (missing, is a link, not a real file or lies elsewhere) or `error` (read error, timeout) |

If `export` aborts (exit 1 with a reason), the created `DIR` stays; delete it before a new try (`nc delegate` does that itself).

`remove TASK --delivered SHA` deletes a collected worker task without a GitHub check, but only if everything holds:

- `SHA` is a full commit (40 hex characters, lowercase), exactly one task is named, neither `--force` nor `--discard-memory` (otherwise `wrong call`);
- the task entry has `"worker": true`;
- Docker answers and the workspace volume is readable (the same read-only check without network as for `remove`);
- the workspace has no uncommitted changes;
- `refs/heads/nc-work/<task>` in the volume is exactly at `SHA`.

Otherwise `nc-work: <task>: not deleted – <reason>`, exit 1, nothing is deleted. `--force` stays as it is.

`memory-apply` without names explicitly skips tasks with `"worker": true`, even if an entry sets `memory`. With the name of a worker, it refuses (`worker task without memory (nc delegate)`). `stop` on an already stopped task still ends without an error.

Limits:

- Only the one branch is collected. Uncommitted work in the container does not come along; `dirty` only says that there is some.
- `export` needs a running container. A stopped worker must first be started with `nc-work start`.
- At most 200 MiB bundle and 64 KiB `RESULT.md`; more is refused or truncated respectively.
- A worker counts towards the at most three running tasks. `nc-work here` also offers workers to stop when the slots are full; after that `export` fails until the task runs again.
- The generated OpenCode researcher may neither write nor use the shell. As a worker it cannot create `RESULT.md` and cannot commit anything; therefore the role is locked as a worker: `nc delegate` refuses it.
- Workers get no memory, not even read-only, and neither mailbox nor inbox: they do not delegate further.
- No worker has the key; OpenCode only gets the placeholder (see "Key proxy"). A worker can therefore write it neither into `RESULT.md` nor into a commit. As long as its run is active, every process in the worker can use the proxy of the run (daily limit, and with the clients key the allow list).

## Broker (`nc-work broker`)

An isolated session can call `nc delegate --role tester --task "…"` and `nc memory add "…"` in the container. The client (harness) puts a request into the mailbox of the task; the broker collects it on the host, hands it to the host path of the harness (`nc delegate --broker …`, checks role, model and policy and creates a worker through `nc-work create … --worker --from-task`), and at the end puts result, `RESULT.md` and the branch as a bundle into the read-only inbox of the task. Nothing is merged, checked out or run.

```sh
nc-work broker        # runs in the foreground, Ctrl-C ends it; no service, no systemd
```

It is started visibly in a herdr pane (entry "Broker" in herdr-nc, `["nc-work", "broker"]`). Only one instance runs: `flock` without waiting on `~/.local/share/nc-work/broker.lock`, otherwise exit 1 and `broker is already running`.

**Folders per task** (only tasks without `--worker`, created by `create`, created again at `start` and `here` if they are missing; the broker never creates folders of a task):

| In the container | On the host under `~/.local/share/nc-work/broker/<task>/` | Mode |
| --- | --- | --- |
| `/opt/nc-requests`, writable, `NC_REQUESTS` | `requests` | 777 (the container user is a sub-UID, as for the memory outbox) |
| `/opt/nc-inbox`, read-only, `NC_INBOX` | `inbox` | 755 |
| – | the folder itself | 700 |

The task entry has `"broker": true` and `"broker_token"` (32 hex characters, `secrets.token_hex(16)`). Older tasks have neither and get nothing added later; a new task with the name of a deleted one has a different token and therefore gets no old results. Workers get neither mailbox nor inbox.

**Reading requests.** Everything from a container is data. The requester is always the task the folder belongs to; project, path and token come from its entry, never from the request.

- Only names matching `^[a-z0-9][a-z0-9-]{0,63}\.json$`, sorted. Entries with a leading dot belong to the client (`.<name>.tmp`, still being written) and are ignored. Folders are never touched.
- At most 8 files stay in the mailbox; what lies above that after sorting is deleted without an answer (one line per round). The deleted requests with a valid name get an entry in `.dropped` (reason "mailbox full (more than 8 requests)", one write per round). At most 4 requests per task and round (every 2 seconds), and for `delegate` at most one hand-over per task every 10 seconds; because the type is only known after reading, nothing is read from a task during that time, the files stay until the next round.
- Every answered request counts against the requester, also `refused` without a call to the harness: at most 4 answers per requester and minute, the rest stays. If the inbox has 200 answer folders, new delegate requests are deleted without an answer (one line per request and an entry in `.dropped`). The broker keeps answering cleanup requests if they are valid and name a delegation of this task (`broker_owns`); whether it is one is decided by the content, not the name. A broken cleanup request or one with a foreign ID is then also deleted without an answer, so that no `refused` folder is added. Every cleanup takes the answer folder of its delegation with it. `cleaned` answers do not count towards the 200, so there is room again afterwards for a delegate request. This stays bounded: every `cleaned` has first removed an answer of its delegation (or follows a run of this task), and the sweep deletes it after 24 hours. Folders in the mailbox are never touched and reported once per run.
- Opened with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`, only real files (`fstat`), at most 64 KiB (more: answer `refused`, file deleted). Links, FIFOs and devices are not opened but deleted without following, wrong names deleted; every such finding is reported once per run and name.
- If `inbox/<name>` already exists or the request is already in staging: delete the file without answering, one line. An existing answer folder is never overwritten.
- Staging `~/.local/share/nc-work/broker-runs/staging/<task>/<name>` (folder 700, file 600, host-owned): the bytes get there only immediately before the hand-over, after that the request in the mailbox is deleted (if it is already gone, that is no error). The requests are processed one after the other. The copy in staging is deleted only after an answer is written; if the broker ends before that, it stays for the next start. At start, every file in staging gets an answer (only if the inbox exists and the answer folder is missing) and is deleted; nothing is run again:
  - if `broker-runs` has an entry for the requester (with its token) and request: `started` from that entry;
  - otherwise, if `~/.nc/delegate/*/request.json` has a run with `origin: broker`, the same requester, token and `request_name` and without `result.json` (the broker was ended between `create` and its own entry): the run is taken over (entry in `broker-runs`, line "run taken over") and gets `started`;
  - otherwise `error`: "broker stopped during hand-over – submit the request again. A half-created worker may be left over: nc-work list, then nc-work remove <task> --force";
  - a memory request (by the content of the staging copy) is never taken over as a run: `error` "broker stopped during hand-over – submit the note again", without the hint about a half worker, the daily counter stays unchanged. Submitting again is harmless: a note that is already stored then gives `refreshed` or `unchanged`.
- **Switch** (`broker_type`): only by the content, never by a letter in the name. An object with `"type": "cleanup"` goes to the cleanup check, UTF-8 JSON with one object and `"type": "memory"` to `broker_memory`, everything else (also invalid JSON) to `nc delegate --broker`. A delegate request with the name `m….json` stays a delegate request.
- The broker checks `cleanup` requests strictly itself (UTF-8, exactly one object with `v` as the number 1, `type`, `task_id`; ID matching `^d[0-9]{4}-[0-9]{4}-[0-9a-f]{4}$`), otherwise `refused`. The ID must belong to this requester: a `response.json` with this `task_id` in its own inbox, or an entry in `broker-runs` with its token; the request alone is never enough. If neither `~/.nc/delegate/<id>` nor the worker task (`tasks/<id>.json`) exists, the broker itself answers with `cleaned` and `"gone": true` and deletes the answer folder of the delegation; the harness would only have refused. Otherwise `nc delegate --cleanup <id>`; on success the answer folder of the delegation is deleted and the request answered with `cleaned`, exit 1 → `refused`, exit 2 → `error`, each with the reason of the harness. Everything that is not an object with `"type": "cleanup"` (also invalid JSON) goes to `nc delegate --broker`, which then refuses with a reason.

**Hand-over to the harness.** `~/projects/personal/nc-harness/bin/nc delegate --broker --requester <task> --token <broker_token> --profile <project> --project-path <path> --request <staging-file> --request-name <name>` (`subprocess.Popen`, `cwd=/`, own process group). The harness writes exactly one line of JSON: `started` (exit 0, with `task_id`, `timeout_min` 1 to 20, `started`), `refused` (exit 1) or `error` (exit 2). Fields, types and ID are checked; unusable output or the time limit of 20 minutes gives `error` (the message names the expired limit). A call can take up to 15 minutes (`create` fetches the bundle); the broker does nothing else in that time, but keeps the heartbeat.

**Memory requests**. Content exactly `{"v":1,"type":"memory","text":"…"}`, optionally `"replaces"`; the harness checks the content. Flow:

- A worker or a task without memory gets `refused` without a call to the harness (the same texts as `memory-apply`), and so does a task that already had 20 new or replaced notes today: "at most 20 new or replaced notes per task and day".
- Only a request that the broker itself deleted in the mailbox goes to the harness. If the client took it back between reading and deleting (it then writes the note into the outbox), the staging copy is discarded, one line "taken back by the task", no answer. This way no note is applied twice. delegate and cleanup are answered in every case as before.
- Call: `bin/nc memory apply --broker --project <profile> --request <staging-file> --requester <task>`, profile and requester from the task entry (a `project` in the request is refused by the harness), `cwd=/`, own process group, time limit 5 minutes. The harness takes the lock on `~/.nc/memory`, writes only `projects/<profile>.md`, never deletes a note, commits with `nc memory apply: <profile> (task <task>, <outcome>)` and pushes.
- Output strictly checked: exactly one line, `stored` with exit 0, `outcome` from `new|refreshed|replaced|unchanged`, `pushed` bool, `note` text; `refused` with exit 1 or `error` with exit 2 and `reason`. Everything else is `error` "the harness gave no usable answer". Timeout or signal: `error` with its own text (without the hint about a half worker), on a signal the broker ends afterwards.
- On `stored`, in this order: store the daily counter (only for `new` and `replaced`), renew the view of the task, then `response.json` with `stored` and `result: {"outcome", "pushed"}`, last the line in the pane `stored (<outcome>[, not pushed]): <note>`. This way `nc memory search` finds the note as soon as the client sees `stored`. An error of the host after `stored` never ends without an answer: if the counter cannot be stored, "counter not saved: …" appears in the pane and the answer comes anyway; if `response.json` cannot be written, there is an entry in `.dropped` ("stored, answer not written – the note is in the memory"). In both cases the staging copy goes, so a restart does not wrongly report "submit the note again".
- **Exception "note text in the pane":** otherwise the broker shows no text from a request. On `stored` it shows the note, and only `note` from the output of the harness (after its check, control and invisible characters removed, at most 120 characters); it does not parse the JSON content from the container for this. This is the protection instead of review: every note is in the pane and in the log, the commit names the task.
- No gap of 10 seconds (that applies only to delegate); the 4 answers per minute apply.
- **Daily counter** in `~/.local/share/nc-work/broker-runs/memory/<task>.json` (folder 700, file 600): `{"token", "day", "count"}`. Only the broker keeps it. A different token (new task with an old name), a different day, a missing or broken file count as 0. `nc-work remove` deletes the file. The day follows UTC (clock of the broker), the date in the note line follows the local time of the host; so at midnight local time a new counting day does not necessarily begin.

**Full inbox and `.dropped`**. At 200 answer folders, a valid own cleanup and memory requests continue. `stored` creates a folder that does not count; `refused` and `error` of a memory request and every cleanup that does not result in `cleaned` (exit 1, exit 2, timeout) create no folder. Every request that ends without an answer gets an entry in `inbox/.dropped` instead:

    {"v":1,"entries":[{"request":"<name without .json>","reason":"<at most 200 characters>","ts":"<UTC>"}]}

At most 8 entries, newest first, 644, written atomically, as UTF-8 without escapes, never above 8 KiB (otherwise the oldest drop out). At most 32 KiB are read; a broken, linked or too large file gives an empty list (a link is replaced, never followed). When there is an entry for its request, the client ends immediately with exit 1 and the reason, instead of waiting until its deadline. The container cannot write `.dropped`; the file never counts as an answer and is never cleaned up. If an entry is missing (write error, or it has already dropped out again with more than 16 requests in one round), the client waits until its deadline as before.

**Running delegations** are in `~/.local/share/nc-work/broker-runs/<id>.json` (mode 600; requester, token, request name, deadline = `started` + `timeout_min`), not in the folder of the requester, and are followed after a restart. Every 10 seconds the broker asks `nc delegate --result <id>` (without `--wait`), with the same time limit as `--broker` (20 minutes): collecting can take a while (lock up to 15 minutes, export, stop, bundle). If the harness needs longer in the worst case, the broker aborts the call; such a run ends only with `error` (deadline plus 5 minutes). If the result is there (exit 0, status not `running`), it checks only now whether the requester still fits (entry there, same `broker_token`); until then it keeps asking, so that the worker is stopped at the deadline. If it does not fit any more, only a line "requesting task gone or replaced – the result is in ~/.nc/delegate/<id>" is in the pane and nothing in the inbox. Otherwise it copies from `~/.nc/delegate/<id>/delivery/` only real files (`O_NOFOLLOW`, `fstat`) into the answer folder, with mode 644: `result.bundle` (at most 200 MiB, more: `error`), `RESULT.md` (at most 64 KiB, more is truncated), and finally writes `response.json` with `done` (`result` = content of `result.json`). Exit 2 of `--result` is reported once; when the deadline plus 5 minutes has passed, the broker writes `error` with the reason of the harness (names `nc-work start <id>`, otherwise `nc-work remove <id> --force`), keeps the entry so that a later success can write `done`, and then asks only every 5 minutes. It does not check the requester in that case (only at delivery): if it is gone or replaced, no `error` is in an inbox, but asking continues. If the worker task no longer exists (no `tasks/<id>.json`, e.g. after `nc-work remove <id> --force`), the entry is deleted (line "worker task is gone – no longer followed").

**Answer in the inbox.** One folder per request `inbox/<name without .json>/` (755) with `response.json` (644), later `RESULT.md` and `result.bundle`. First the files, then `response.json` atomically (tmp + rename):

    {"v": 1, "request": "<name>", "state": "refused|started|done|cleaned|stored|error",
     "reason": null, "task_id": null, "timeout_min": null, "started": null, "result": null}

`refused` and `error` carry `reason` (control and invisible characters removed, at most 400 characters); `started` has `task_id`, `timeout_min`, `started`; `done` additionally `result`; an `error` for a started run keeps `task_id`, `timeout_min` and `started`, and a later `done` may replace it. Times are always ISO with `Z` (UTC): the clock in the container is UTC, that of the host is not. `stored` (memory) has `result: {"outcome", "pushed"}`, does not count against the 200 and is cleaned up after one hour ("cleaned up (1 hour)"). Answer folders with `refused`, `error` (without a running delegation) or `cleaned` are deleted by the broker after 24 hours; an `error` with `task_id` stays as long as `~/.nc/delegate/<id>` exists (the run can still be collected or cleaned up). `cleaned` can carry `"gone": true` (see `cleanup`).

**Heartbeat.** `inbox/.broker` with `{"v":1,"ts":"<ISO>"}`, atomic, in every inbox at least every 10 seconds (every 5), also while waiting for a harness call. The client evaluates it: older than 60 seconds or missing means "broker not running".

**Ctrl-C and signals.** The first Ctrl-C in the pane announces that the running call is awaited; after that the broker accepts nothing new and ends. Only at the time limit, at the second Ctrl-C or at SIGTERM/SIGHUP (pane closed) does the whole process group of the harness get the signal (`os.killpg`, first SIGTERM, then SIGKILL), and the broker ends. Only for a `--broker` call does the request get `error` and name `nc-work list` and `nc-work remove <task> --force` for a half-created worker; for `--result` nothing is answered, the run stays in `broker-runs` and is followed after the restart. During a call, the signal handlers only set flags, so that no KeyboardInterrupt can escape from the wait loop or the kill loop; without a running call, Ctrl-C, SIGTERM and SIGHUP end the broker immediately. If the process of a call ends normally in the same second in which the signal arrives, that call is still answered. After that, main loop, hand-over and polling evaluate the flags before anything new begins, and the broker ends; so it does not stay behind without a terminal holding `broker.lock`. Write errors to the terminal (EIO after the pane is closed) are ignored; the log still gets the line.

**Pane and log.** One line per event with time, requester, kind, result and ID, without task text (exception: the text of a stored note, see above); file names from a container appear with visible escapes (control and invisible characters as `\u{…}`). The same line as JSON in `~/.nc/log/broker.jsonl` (folder 700, file 600). An error with one task does not stop the round (line `error`, the round goes on). Besides `delegate`, `memory` and `cleanup`, the kinds are `mailbox`, `request`, `inbox` and `error`.

**Not handled by the broker:** `publish --push` (the broker does not know it). Budgets are only a display in the result (`cost_usd`, `over_budget`, in the harness).

**Two deliberate choices:**

- Refused requests get an answer in the inbox (`response.json` with `refused` and a reason) instead of a `.reason` file in the mailbox: there is an answer channel now, and the client sees the reason without searching in the writable mailbox.
- Links and special files in the mailbox are deleted instead of left behind: a FIFO or link that stayed would occupy the 8 slots of the mailbox and be noticed again every round, and the broker should never open anything of it.

Limits: the broker processes the requests one after the other; during an `nc delegate --broker` (up to about 15 minutes) everything else waits, only the heartbeat keeps running. It never reads dot files in the mailbox, but does not delete them either (as with the memory outbox, the container can take up space there). If `nc delegate --result` ends in exit 2 after a restart, the entry stays in `broker-runs` until a result comes, the requester was replaced or the deadline plus 5 minutes has written an `error` and someone runs `nc-work remove <id> --force`.

## Claude with a separate model token

In your own interactive server terminal:

```sh
~/.local/bin/nc-work auth-login
~/.local/bin/nc-work start example-site-check
~/.local/bin/nc-work claude example-site-check
```

The browser step requires the account owner. The token is taken over automatically; no manual copying is needed. `auth-set` stays available as a manual alternative. Do not enter tokens in the chat or as a command argument. `auth-set` expects a token from `setup-token`; the format check does not replace a check of its permissions at the provider.

The shared default is stored once in the host state under `auth/.default.token` with file mode 600 and folder mode 700. All project profiles, and any added in the future, use it automatically. An explicitly set up project token takes precedence. A renewal with `nc-work auth-login` applies to all Claude sessions started in the future without their own project token; running sessions keep their previous token until restart. On interactive start, only the selected model token is passed to the Claude process, not as a command argument and not in the persistent container configuration. An agent in the same container can still read this token and use it for model requests. It is not a project-bound provider account or its own usage limit. No `.credentials.json`, no refresh token and no complete personal login are copied.

According to the [Anthropic documentation](https://code.claude.com/docs/en/authentication#generate-a-long-lived-token), `setup-token` allows model requests through the subscription, but no remote-control sessions or Claude web connectors. There is no automatic switch to API billing. A different account can be assigned with `nc-work auth-login PROJECT`. `nc-work auth-status PROJECT` shows only whether the shared default or a separate login is selected. New projects still need a project profile and their tool/network configuration, but no further Claude login. Start through `nc-work claude TASK`; a plain `claude` in a container shell does not get the token automatically.

No API key is needed. If a token is stored, the starter only skips the initial account setup dialog; project trust and tool approvals stay active. The starter refuses to start without a token. Passing without the token in the argument was additionally checked with a synthetic test value.

## OpenCode with OpenRouter key

```sh
nc-work opencode TASK                                   # TUI in the terminal
nc-work opencode TASK -- run --model openrouter/<provider>/<model> "…"   # one job without TUI
nc-work here --runtime opencode                            # selection as for "Claude (isolated)"
git diff | nc-work opencode --stdin TASK -- run --model … "review this"   # pass input through
```

On each start, the starter reads exactly one key from `~/.config/nc-harness/secrets.env` (created by the harness, mode 600, parsed, not executed; which one is described under "Which key") and hands it only to the key proxy of the run (see "Key proxy"). OpenCode gets the placeholder `OPENROUTER_API_KEY=nc-keyproxy`, the address of the proxy in `OPENCODE_CONFIG_CONTENT` and its alias in `NO_PROXY`/`no_proxy`, all through the environment of `docker exec`. `secrets.env` itself never enters a container. So that no process keeps working after the run:

- The shared background service of OpenCode 2 is switched off (`service.json` from the harness); every run has its own server, also for `opencode` calls that an agent makes itself.
- Every run gets a marker `NC_OPENCODE_RUN=<random>`. After the end, also if the host client aborts (SSH gone, window closed, `timeout`, SIGTERM/SIGHUP), `nc-work` ends in the container all processes with this marker: OpenCode, its server and what its tools started in the background. `docker exec` alone does not end them. Search and cleanup run as `/usr/bin/python3 -I -B`. In the PATH of the container, `~/.local/bin` comes before `/usr/bin`, and the agent writes there; therefore every `docker exec` of nc-work starts its program through the absolute path (except `nc-work exec`, where the caller gives the command). The fixed path alone is not enough for Python: without `-I`, the working directory `/workspace` and the user site under `~/.local` would be on `sys.path`, and the agent can write to both (a `json.py` or `.pth` file would run). That is why every Python call in the container carries `-I -B`, also onboarding and `auth-check`.

An agent in the same container sees only the placeholder and the address of the proxy; through it, it can make model calls during the run. That is why both keys still have a fixed daily limit at OpenRouter. Without a key or with permissions that are too open, the starter refuses, for `here` before a task is created. Tasks without OpenCode (older image or harness snapshot without `adapters/opencode`) are not offered by `here --runtime opencode`, and `nc-work opencode` refuses them before the key is passed; `create` records this in the task (`"opencode": true`). A terminal (`-t`) exists only if stdin and stdout are a terminal. Redirected input is passed through by `nc-work` only with `--stdin`, because `opencode run` reads a pipe to the end and would hang on an inherited, open pipe (ssh, agent tools). A stopped task is refused (`nc-work start …`), and so is `here --runtime opencode` → `n` if the current harness snapshot has no OpenCode configuration. Runs started with `nohup` survive logout; SIGTERM ends the run and cleans up. If the cleanup fails, `nc-work` reports it (`nc-work stop TASK` then ends everything).

### Which key, default and title model

Before every OpenCode start (`nc-work opencode`, `here --runtime opencode`), `nc-work` asks the harness checkout on the host, never the snapshot: `~/projects/personal/nc-harness/bin/nc models --json --path ~/projects/<profile path>` (from `/`, at most 60 seconds; profile path from the task, for older tasks from the profile).

| Policy of the project in `models.yaml` | Key from `secrets.env` | In the container as |
| --- | --- | --- |
| blocks `free` **or** requires `require: no-training` (in nc-harness' default `models.yaml`: everything under `~/projects/clients/`) | `OPENROUTER_API_KEY_CLIENTS` (OpenRouter workspace `clients`, guardrail with the allowed models, training and publication off) | only in the key proxy of the run |
| otherwise | `OPENROUTER_API_KEY` | only in the key proxy of the run |

`require` is in the output under `policy.require`. If it is missing (an older harness), it counts as an empty list, so that an older harness breaks nothing; if it is there but not a list of strings, OpenCode does not start ("policy … not read (policy.require is not a list of strings)").

In both cases OpenCode sees only `OPENROUTER_API_KEY=nc-keyproxy`; which key is in the proxy depends on the project. With the clients key, no path in the container reaches a free or otherwise not allowed model (selection in the UI, parameter `model` when delegating, agent files of the project, `curl`): OpenRouter refuses. This applies to existing tasks from the next OpenCode start, without a new snapshot.

From the same output, `nc-work` sets `OPENCODE_CONFIG_CONTENT` on every OpenCode start (in every project) with `model` (class `standard`) and `small_model` (class `cheap`, the model of the agent `title`), each only if the class is allowed there and has a model; if both are missing, the variable is left out. It is passed like the key, only through the environment of `docker exec`. OpenCode 2.2.7 loads it after the files of the project and before `/etc/opencode`; without it OpenCode would take its own models, which the clients key blocks. A change in `models.yaml` takes effect at the next start.

OpenCode then does not start, with one line:

- `OPENROUTER_API_KEY_CLIENTS missing in ~/.config/nc-harness/secrets.env – in this project OpenCode starts only with the key from the OpenRouter workspace "clients"`, if it has no value (after the parse rules: last line wins, optional `export`, quotes stripped); a malformed value gives `OPENROUTER_API_KEY_CLIENTS in secrets.env is malformed; value not printed – …`. Never a fallback to `OPENROUTER_API_KEY`. For `here`, this comes before any question, nothing is created.
- `policy for ~/projects/<path> not read (<reason>) – OpenCode does not start`, if `nc models` fails (exit, timeout, no valid JSON, no `policy.deny_classes`); also not with the other key. The reason is shown by `cd / && ~/projects/personal/nc-harness/bin/nc models --path ~/projects/<path>`.

Limits:

- No agent in the container can read the clients key. As long as a run is active, it can still make calls through the proxy: only with the models the guardrail allows, without server tools and up to the daily limit set on the key.
- Guardrail, budget and the page "Tools" are manual settings at OpenRouter. Nothing here checks them; whoever loosens something there loosens the limit.
- If the model of `standard` or `cheap` changes, the guardrail has to be updated. Until then these calls fail in restricted projects; nothing goes to another model.
- Which key applies is decided by the profile path through `models.yaml`. A client project outside the paths that `models.yaml` restricts gets the default key until it gets its own rule.
- Not tested: presets and routing variants like `:nitro`. A preset in the workspace `clients` can only be created by whoever is on the account.
- OpenCode directly on the host still refuses in restricted folders; a session on the host can, however, read any folder (unchanged).
- Claude sessions run through Anthropic. Whether inputs are used for training there is governed by the privacy setting of the Claude account.

`nc-work opencode` sets `TMPDIR=/home/agent/.cache/nc-tmp` on every start (through the environment of `docker exec`) and creates the folder beforehand as uid 1000 with mode 700 if it is missing: `/tmp` is a tmpfs with `noexec` in the task, and the UI of OpenCode loads a native library (OpenTUI) from `TMPDIR`; without this it would not start in any task, only `opencode run` worked.

In the image: OpenCode 2.2.7, the same file that `nc-harness` installs on the host (standalone binary from the GitHub release, `images/opencode.sha256`). `OPENCODE_DISABLE_AUTOUPDATE=1` and `OPENCODE_DISABLE_MODELS_FETCH=1`: no self-update, model catalog from the built-in state, because `models.opencode.ai` is not allowed. Only the provider `openrouter` is allowed (configuration from the harness).

Checked in a fresh task: skill `nc-harness-check` loaded in Claude and OpenCode, key neither in `docker inspect` nor in PID 1. After a normal run and after a hard abort (`timeout -s TERM 8 nc-work opencode example-check -- serve`), no process in the container held the key; as a counter-check, the same server without cleanup kept running after the abort.

## Key proxy

Every `nc-work opencode` (also workers of `nc delegate` and `here --runtime opencode`) starts its own key proxy, `keyproxy/keyproxy.py` from this repo (Python standard library only, not in the image). OpenCode in the container then has only the placeholder `nc-keyproxy`; no agent container has the key in environment, files or memory.

Flow per run:

1. Install signal handlers for SIGTERM/SIGHUP, then in the `try`: hold the lock file of the run (`~/.local/share/nc-work/keyproxy-runs/<task>.<run>.lock`) and remove orphaned proxies of the task (below).
2. Copy the script to `~/.local/share/nc-work/keyproxy/keyproxy.py` (folder 0755, file 0644, like the memory view, independent of the umask of the checkout).
3. `docker run -i` as its own container: name `ncw-<task>-key-<run>`, network of the task, alias `key-<run>`, labels `kind=keyproxy`, `project`, `task`, `run` (so it does not count towards the three agents, `list` does not show it), image of the task, `--user 1000:1000 --cap-drop ALL --security-opt no-new-privileges --read-only --init --memory 256m --pids-limit 64 --ulimit core=0` (no core dump with the key), small `/tmp`, no ports to the outside, the script read-only under `/opt/nc-keyproxy/`, entrypoint `/usr/bin/python3 -I -B /opt/nc-keyproxy/keyproxy.py`. The key goes in as one line on stdin, after that stdin is closed. It is never in argv and never in an environment of Docker, so also not in `docker inspect` or the environment of a `docker exec`.
4. At most 15 seconds for `GET /__ready`, asked through `docker exec` in the proxy. If it does not answer or `docker run` ends: abort ("key proxy for <task> not ready – OpenCode does not start"), no fallback to the key in the task.
5. OpenCode gets `OPENROUTER_API_KEY=nc-keyproxy`, in `OPENCODE_CONFIG_CONTENT` next to default and title model `provider.openrouter.options.baseURL = "http://key-<run>:8080/api/v1"` and `key-<run>` in `NO_PROXY`/`no_proxy` (otherwise OpenCode would send the `http://` address to the egress proxy, which refuses it). `OPENCODE_CONFIG_CONTENT` applies before an `opencode.json` in the repo.
6. In the `finally`: first remove its own proxy through its fixed name, end `docker run` (the caller knows the process right after the start, even if a signal arrives while writing the key) and remove once more (without a process after a pause, in case the daemon is still creating it), then end the processes of the run (`OPENCODE_REAP`), then delete the lock file. If the proxy is still there afterwards or Docker does not answer, "key proxy … maybe not removed; nc-work stop <task>" is shown. A second signal does not interrupt the cleanup.

The proxy:

- `ThreadingHTTPServer` on `0.0.0.0:8080` in the network of the task, at most 8 simultaneous requests (the slot is taken before reading the body, above that 503) and 32 connections. Request line and headers together have a deadline of 60 seconds from the connection (a watchdog thread closes what is above), the body has its own of 60 seconds; a slowly dripping client holds neither slot nor connection longer. At most 64 headers of 16 KiB each (otherwise 431), so that 32 connections do not fill the 256 MiB. `Connection: close` after every request.
- Only `POST /api/v1/chat/completions` passes (OpenCode 2.2.7 calls nothing else). The raw request target is compared byte for byte: no absolute form, no query string, no decoding, no prefix, no normalization; upstream always goes the path from the list. Other methods (CONNECT, OPTIONS, …) 405, other paths 404, without forwarding. `GET /__ready` answers locally.
- Body at most 8 MiB (otherwise 413), exactly one `Content-Length` of digits (otherwise 400, if missing: 411), any `Transfer-Encoding` in any spelling and any header the parser cannot read, 400.
- From the client only `Content-Type`, `Accept`, `HTTP-Referer` and `X-Title` pass on; `Authorization`, `Cookie`, `Proxy-*`, `Host` and everything else are dropped. The proxy sets `Authorization: Bearer <key>` and `Host: openrouter.ai`.
- To the outside only `http.client.HTTPSConnection('egress', 3128)` with `set_tunnel('openrouter.ai', 443)` and a verified certificate (`/etc/ssl/certs/ca-certificates.crt` of the image); no `urllib` (follows redirects including `Authorization`, reads proxy variables). The target is fixed in the code; only tests change it through parameters of the server function. Redirects are not followed but returned without `Location`.
- Back go status, `Content-Type`, `Cache-Control` and `Retry-After`; the body in chunks, immediately (streaming), at most 600 seconds without data.
- Log on stdout (`docker logs`, as long as the proxy lives): per request time, method and path from the list (when refused only "refused"), status, bytes. No bodies, no headers, no text of the client, never the key.

Cleanup (`keyproxy_sweep`, through `docker ps -a` and the label `task=`):

- at the start of every `nc-work opencode`: proxies of the task whose run has neither its `nc-work` (lock file held) nor a living process with `NC_OPENCODE_RUN=<run>` in the container (the same search as `OPENCODE_REAP`). This way a proxy left over after SIGKILL does not stay usable for days, and two runs at the same time (two panes) do not disturb each other. If the search in the container cannot be run, everything stays, with a warning line. A process in the task that carries the marker of its run (such as a background process of a tool) keeps the proxy alive after a SIGKILL on `nc-work` until it ends or `stop` comes.
- at `stop` and `make_room` (selection when slots are full): all proxies of the task; `remove` catches them through the label and deletes the lock files of the task.

`check-leak` (`keyproxy/check-leak`, Python, only on the host, never copy into a container): takes files or `-` (stdin), reads the real keys itself through `openrouter_key` of `nc-work` and prints only counts, two lines, one per name, in the order `OPENROUTER_API_KEY` and `OPENROUTER_API_KEY_CLIENTS`, e.g. `OPENROUTER_API_KEY: 0` (counted raw and JSON-masked), and `<name>: not set (not checked)` for a missing one; never a value. Exit 0 without hits, 1 with hits, 2 if nothing could be checked. Data from a container comes through a pipe: `nc-work exec TASK … | check-leak -`.

Limits:

- As long as an OpenCode run is active, every process in the container of this task can use the proxy, so make model calls at the key owner's expense, also a Claude session in the same task: the address of the proxy is in the environment of OpenCode. This is limited by the daily limit of the key, and with the clients key additionally by the allow list. The key cannot be taken away or passed on.
- The proxy checks no models; the hard model limit stays with OpenRouter. There is deliberately no allow list in the proxy; `nc models check` in the harness only refuses models that are not allowed early, for a better message.
- Offline tasks (`--offline`) get no OpenCode (`offline: no OpenCode`); `here --runtime opencode` does not offer them.
- The egress proxy still allows agents `openrouter.ai` directly; without a key that is useless and stays so that nothing else breaks.
- `nc opencode` directly on the host is unchanged (the host is trusted); the Claude subscription token stays in the environment of Claude in the container.
- After a SIGKILL on `nc-work opencode`, the empty lock file of the run stays until a start finds its proxy or `remove` deletes the task.


## Limits and operation

- Rootless Docker, not privileged, read-only root file system, no additional Linux capabilities, no Docker socket and no host home in the container. Containers still share the host kernel; they are not VMs.
- The trusted host user controls the launcher and its Docker environment. The isolation protects against the agent container, not against the host user or root.
- Existing host terminals and Claude sessions keep running outside this new isolation. The new isolation applies when started through `nc-work`.
- Hosting and staging on the same host are not changed by `nc-work`.
- Failed creations are marked `failed` and stopped; data stays for a targeted recovery. There is deliberately no blanket delete/prune command.
- Image: the tag in `IMAGE` in `bin/nc-work` (new tasks; existing ones keep their image). A rebuild needs the version-bound Node/Bun runtimes in `images/toolchains` and the checked binaries `images/claude` and `images/opencode`. These binaries are not in Git; `images/claude.sha256` and `images/opencode.sha256` contain the checksums. Rebuild from `work-environments/`: `sha256sum -c images/claude.sha256 images/opencode.sha256 && docker build -t nc-work:<date> images`, then adjust `IMAGE` in `bin/nc-work`. `images/opencode` is the unpacked binary from `opencode-linux-x64.tar.gz` of the GitHub release; the version must match `pins.txt` in the harness. There is no automated download yet.

## Tests

```sh
cd work-environments && python3 -m unittest tests/test_policy.py
```

The unit tests check, among other things: name and target validation, network rules, the profiles (shipped examples and `tests/fixtures/profiles`) and the overlay (profile precedence, snapshot contents and refusals), safe token hand-over, the choice of the key by the policy (no fallback to the default key), default and title model, agents folders, mounts and generation before the start, the memory view (only the own project) and `nc memory apply`, the key proxy (start, cleanup, rules against a fake target, `check-leak`), mailbox, inbox and the broker (one round, fake harness, fake clock), `create --from-task` with its refusals (exit 4), and that no tracked file in `work-environments/` contains non-English words from a small deny list. Contract tests with the real `bin/nc delegate` and `bin/nc memory apply --broker` are skipped without a harness checkout or `bun`. Some tests read `/proc` and need Linux. The tests never read the real `~/.nc/overlay`.

These are infrastructure checks, not builds or functional tests of the projects. Runtime data lives in `~/.local/share/nc-work/`.

### Login without manual copying

`~/.local/bin/nc-work auth-login` starts the official browser flow in a separate temporary configuration folder and stores the printed model token automatically. Run this command in your own server terminal. The existing host login stays separate. The automatic takeover is tested with synthetic outputs.
