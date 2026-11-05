# bugnet-run

The in-sandbox command runner and its frame format.

Run `make test`, `make lint` and `make build`. `make build` also writes static Linux binaries to
`dist/bugnet-run-linux-amd64` and `dist/bugnet-run-linux-arm64`. Container tests run in Debian 12,
Ubuntu 22.04 and 24.04 with `BUGNET_TEST_DOCKER=1 go test -run Container ./...` and skip otherwise.

## Jobs

`start --job <id> [--cwd DIR] [--env K=V]... [--root DIR] -- argv...` runs a command detached and
follows it. `attach --job <id> --out <n> --err <n>` follows a job from the given offsets. With
`--tail <n>` it sends each second only the newest `n` bytes of each output, writing a `skip` frame
whose `o` and `e` name the offsets the output goes on from. The skipped bytes stay in the job's
files.

A job's environment is the runner's own, then these, each later one winning:

| Order | Source |
|---|---|
| 1 | `PYTHONUNBUFFERED=1` |
| 2 | `LANG=C.UTF-8` and `LC_ALL=C.UTF-8`, which every image has |
| 3 | `/etc/bugnet/env` |
| 4 | `/etc/bugnet/secrets.env` |
| 5 | Each `--env` |

When `--env` sets `LANG` or an `LC_*` variable, the runner leaves `LC_ALL` unset, so that
setting applies. Both files are read at every job start. Each holds `KEY=VALUE` lines with no
shell expansion. A line whose name fails `^[A-Za-z_][A-Za-z0-9_]*$` is skipped.

Before each job, `start` runs `respawn`: directly as root, or as `sudo -n bugnet-run respawn`
otherwise. It calls sudo only when a service is down. A failed respawn never fails the job.

## Sandbox services

These run as root. `--root DIR` maps every sandbox path under `DIR`, for the `local` provider.
`--spec` and `--config` take real paths.

`setup --spec FILE [--root DIR] [--repair]` reads the spec, deletes it, and then:

1. Writes `/etc/bugnet/gate.key` (0600) and `/etc/bugnet/gate.json` (0644).
2. Installs the Bugnet CA as `/usr/local/share/ca-certificates/bugnet-egress-v<N>.crt`.
3. Writes `/etc/bugnet/env` and `/etc/profile.d/bugnet.sh`.
4. Starts the gate, under systemd when `/run/systemd/system` exists, else with `setsid`.

It prints `{"gate":"listening","ca":"installed","init":"systemd"}` and exits 0 once the gate
answers its health route. On an error it prints one of these and exits 1:

| Error | Cause |
|---|---|
| `bad_spec` | The spec is missing, malformed or fails a check |
| `ca_mismatch` | The CA could not be put in place, or its SHA-256 differs |
| `gate_failed` | A file could not be written, or the gate did not answer within 10 s |

The `ca` values:

| Value | When |
|---|---|
| `installed` | The first Bugnet CA, through `update-ca-certificates` |
| `appended` | Another version is already installed, so the PEM is appended to the bundle |
| `checked` | `ca_pem` is empty and the baked file matches `ca_sha256` |
| `skipped` | Both are empty, and `/etc/bugnet/env` then holds no CA lines |

A second run with the same spec changes nothing and keeps the same gate process. A new key or
config restarts the gate. `--repair` redoes only steps 1 and 4. Without `--spec`, it keeps the
gate files the last setup wrote.

`gate --config /etc/bugnet/gate.json [--root DIR]` is the reverse proxy on `:29417`. Every
response carries `Bugnet-Gate-Response: 1`. A missing or wrong `Bugnet-Gate` key gets a bare
404.

| Request | Answer |
|---|---|
| `Bugnet-Port: N`, any path | Proxied to `127.0.0.1:N`, then `[::1]:N` |
| N denied, or the gate's own port | 400 |
| Nothing accepts on N | 502 with `Bugnet-Gate-Error: port_closed` |
| `GET /__bugnet/health` | 204 with `Bugnet-Gate-Version: 1` |
| `GET /__bugnet/port/N` | 204 when something accepts on N, else 404 |
| `GET /__bugnet/ssh`, WebSocket `bugnet-ssh.v1` | Bytes to and from the port `ssh-up` wrote |
| SSH without `/etc/bugnet/ssh/port` | 503 with `Bugnet-Gate-Error: ssh_not_ready` |
| Past 256 requests or 16 SSH tunnels | 503 with `Bugnet-Gate-Error: busy` |

App traffic loses `Bugnet-*`, `E2b-*`, `X-Routing-Key` and the `_port_auth` cookie. It gets
`Host` and `X-Forwarded-Host` from `Bugnet-Host`, `X-Forwarded-For` from `Bugnet-Client-Ip` and
`X-Forwarded-Proto: https`. The query reaches the app byte for byte. The app's `Cache-Control`
and `Server` move to `Bugnet-Cache-Control` and `Bugnet-Server` (`-` when absent), and the
response carries `Cache-Control: private`.

`respawn [--root DIR]` starts the gate, the forwarder or our sshd when its config exists and its
process is gone. It prints `{"started":["gate"]}`.

| Service | Config | Pid file |
|---|---|---|
| `bugnet-gate` | `/etc/bugnet/gate.json` | `/run/bugnet/gate.pid` |
| `bugnet-forward` | `/etc/bugnet/egress.json` | `/run/bugnet/forward.pid` |
| `bugnet-sshd` | `/etc/bugnet/ssh/sshd_config` | `/run/bugnet/sshd.pid` |

Under systemd each is a unit in `/etc/systemd/system` with `Restart=always`,
`RuntimeDirectory=bugnet` and `RuntimeDirectoryPreserve=yes`. Units start from the runner's own
path, `/tmp/bugnet/bin/bugnet-run`. A unit that fails 10 times within 60 s stops restarting.
Respawn and setup run `systemctl reset-failed` before they start it again.

Managed blocks sit between `# bugnet begin` and `# bugnet end`. A rewrite renames a new file over
the old one. When the rename fails with `EBUSY` or `EXDEV`, as on a bind-mounted `/etc/hosts`,
it rewrites the file in place under `flock`. Lines outside the block are kept.
