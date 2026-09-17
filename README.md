# chimera 🐉


Protocol-compatible GitHub Actions runner replacement, written from scratch in Rust.

Chimera is a single, fast binary that manages multiple runners concurrently. Run it as a systemd service, in a Docker container, or just in a terminal. It speaks the same registration and job execution protocol as the official runner, so it **works with any existing workflow without modification**.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/quinck-io/chimera/main/install.sh | sh
```

Or install a specific version:

```bash
curl -fsSL https://raw.githubusercontent.com/quinck-io/chimera/main/install.sh | sh -s -- v0.1.3
```

Prebuilt binaries are available for Linux and macOS (x86_64 and aarch64) on the [releases page](https://github.com/quinck-io/chimera/releases).

### Build from source

```bash
git clone https://github.com/quinck-io/chimera.git
cd chimera
cargo build --release
# binary is at target/release/chimera
```

## Why?

Official GitHub Actions runners are slow, resource-heavy, leak memory and difficult to manage. 

Chimera is designed to be a better experience for self-hosted runners, with a focus on performance, reliability and multirunner management, which are especially important for larger organizations. It also serves as a reference implementation of the GitHub Actions runner protocol, which is currently only documented through reverse engineering.

See [docs/gh-protocol.md](docs/gh-protocol.md) for the full spec, API and auth flows of the GitHub Actions runner protocol.

## Usage

Register runners the same way you would with the official runner, then start the daemon. Runners poll for jobs concurrently — each job gets a clean workspace and can use Docker containers as needed.

```
chimera register --url https://github.com/org/repo --token AABBC... --name runner-0
chimera register --url https://github.com/org/repo --token DDEEF... --name runner-1
chimera start
```

Jobs with `container:` run inside Docker. Jobs without it run on the host. Services always run as containers on a shared bridge network. Logs stream live to the GitHub UI.

### Runner context compatibility

Chimera exposes the standard `runner.environment == 'self-hosted'` expression
property. For compatibility with existing workflows it also exposes
`runner.labels` as the typed array `["self-hosted"]`. This compatibility array
is intentionally not the complete set of labels registered on GitHub and does
not affect job assignment. See [Runner context compatibility](docs/runner-context.md)
for the exact contract and environment-override behavior.

All state and data is stored in `~/.chimera` by default.

## CLI

```
chimera register --url <url> --token <token> --name <name> [--labels a,b] [--root ~/.chimera]
chimera unregister --name <name> [--root ~/.chimera]
chimera start [--root ~/.chimera]
chimera status [--root ~/.chimera]
chimera import-official --source <official-runner-dir> --name <local-name> --root <chimera-root> --dry-run
chimera import-official --source <official-runner-dir> --name <local-name> --root <chimera-root>
```

**register** — Register a runner with GitHub. Token comes from Settings > Actions > Runners.

**unregister** — Remove a runner from GitHub and delete its local credentials.

**start** — Start all registered runners concurrently. 

**status** — Show daemon uptime, per-runner phase (Idle/Running/Stopped), and current job info.

**import-official** — Import an existing persistent, repository-scoped github.com identity completely offline. `--name` does not rename the GitHub agent; it is only a local key. A dry-run is required first. See [the registration import runbook](docs/registration-import.md) for the detailed procedure.

## Config

`~/.chimera/config.toml` (managed by `register`):

```toml
runners = ["runner-0", "runner-1"]

[daemon]
log_format = "text"           # "text" or "json" (json works well with journald)
shutdown_timeout_secs = 300
```

### Per-job Docker configuration

For each acquired job, Chimera creates
`<root>/job-resources/<local-attempt-uuid>/docker/config.json`. Host steps receive
that generated directory as `DOCKER_CONFIG`. Chimera rejects conflicting job-,
step-, and `GITHUB_ENV`-level values before the affected host spawn, while allowing
a workflow to repeat the generated value. It does not copy credentials, named
contexts, credential helpers, or CLI plugins from `~/.docker` or an inherited
daemon `DOCKER_CONFIG`.

On Linux, the effective `PATH` for every host spawn must not expose executable
`docker-credential-pass` or `docker-credential-secretservice` helpers. Docker can
select either helper implicitly even from the exact initial `{}` config and thereby
share an external credential store across job directories. Chimera checks the
step-effective `PATH` immediately before each spawn and fails closed with a
`reserved-host-capability` error; operators must keep those helpers out of the
service and workflow `PATH` until explicit helper isolation is supported.

This is not tenant or same-UID process isolation: an already-running same-UID host
process can change its own environment or invoke `docker --config`. The helper check
and cleanup identity checks are not an adversarial same-UID race guarantee. Chimera
refuses startup when stale `job-resources` exist rather than deleting them automatically.
Follow the [operator recovery procedure](docs/job-docker-config.md) before removing
an exact stale attempt directory.

## Supported features

- Host and container step execution (`run:`, `container:`, `services:`)
- All action types: Node.js, [Docker](docs/dockerfile-actions.md), composite
- `${{ }}` expressions, including status/string functions and the documented GitHub/runner/job/steps/needs/matrix/vars contexts
- All workflow commands (`set-output`, `set-env`, `add-mask`, `save-state`, etc.)
- Step conditions, timeouts, `continue-on-error`, cancellation
- Per-job Docker network, port mapping, volumes, `--privileged`/`--cap-add`
- Live log streaming, job outputs, heartbeats
- Support for `actions/cache/v4`

Chimera-only features:
- Multi-runner concurrency with independent error isolation
- Local `actions/cache` server for faster caching and no external dependencies
- Automatic cleanup of completed workspaces and Chimera-created resources; process-tree escapes require operator recovery
- Configurable LRU cache (default 10GB)

## Running as a systemd service

### Rootful system Docker

The following base unit is for a rootful system Docker daemon only: it explicitly
orders Chimera after, and requires, the system `docker.service`.

Create the unit file:

```bash
sudo tee /etc/systemd/system/chimera.service > /dev/null <<'EOF'
[Unit]
Description=Chimera GitHub Actions Runner
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=chimera
ExecStart=/usr/local/bin/chimera start
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF
```

### Rootless Docker alternative

Do not use the rootful base unit unchanged with rootless Docker. The daemon UID's
rootless Docker user service and `/run/user/<numeric-uid>/docker.sock` must already
be enabled and remain available. If the daemon user is not persistently logged in,
enable user-service persistence first (for example, `sudo loginctl enable-linger chimera`
when `User=chimera`).

Add this drop-in to remove the inherited system-Docker dependency. Replace every
`<numeric-uid>` placeholder with the numeric UID of the daemon user, and adjust
`PATH` if Docker is installed elsewhere:

```bash
sudo systemctl edit chimera.service
```

```ini
[Unit]
After=
After=network-online.target
Requires=

[Service]
Environment=DOCKER_HOST=unix:///run/user/<numeric-uid>/docker.sock
Environment=XDG_RUNTIME_DIR=/run/user/<numeric-uid>
Environment=PATH=/home/chimera/.local/bin:/usr/local/bin:/usr/bin:/bin
# Do not set DOCKER_CONFIG here.
```

This drop-in has no system `docker.service` dependency. Then enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable chimera
sudo systemctl start chimera
```

Check status and logs:

```bash
sudo systemctl status chimera
journalctl -u chimera -f
```

> Set `log_format = "json"` in `config.toml` for structured journald output.

## Out of scope or unsupported features

- GHES (GitHub Enterprise Server)
- Windows — not in scope but may work (untested)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
