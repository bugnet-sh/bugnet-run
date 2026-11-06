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

`egress apply --spec FILE [--root DIR]` points the sandbox's secret hosts at the forwarder. It
reads the spec and deletes it, even when another argument is wrong. Then, in this order:

1. Writes `/etc/bugnet/egress.token` (0600) when the spec carries a token.
2. Writes `/etc/bugnet/egress.json` (0644) with the endpoint, its pinned IPs, the port, the listen
   address and the hosts.
3. Starts the forwarder, or sends it `SIGHUP` when its config or token changed. A new listen
   address restarts it. Before a start it binds the listen address for a moment, so a taken port
   is found at once.
4. Waits up to 5 s for the forwarder's pid file and for the listen address to accept.
5. Rewrites the `/etc/hosts` block to `127.77.0.1 <host> <host> ...`. Lines stay under 500
   bytes, since musl reads 512 at a time. There is never a `::1` line.
6. Writes `/etc/bugnet/secrets.env` (0644) and `/etc/profile.d/bugnet.sh`. When our
   `sshd_config` exists, its one `SetEnv` line is rewritten, and our sshd gets `SIGHUP` if it
   changed.
7. Writes the presets. With `git_placeholder`, `/etc/bugnet/git-credentials` (0644) holds the
   lines `username=x-access-token` and `password=<placeholder>`. A block in `/etc/gitconfig` sets
   `credential.https://github.com.helper` to
   `!f() { test "$1" = get && cat /etc/bugnet/git-credentials; }; f`. It answers `get` and
   ignores `store` and `erase`, so git never rewrites or erases the file after a login. With
   `npm_placeholder`, a block in `<home>/.npmrc` sets `//registry.npmjs.org/:_authToken`. A new
   `.npmrc` is 0600 and owned by the home's owner. A linked `.npmrc` is left alone. An empty
   placeholder removes its preset.

It prints `{"forward":"listening","hosts":1,"secrets":1}` and exits 0. On an error it prints one
of these and exits 1:

| Error | Cause |
|---|---|
| `bad_spec` | The spec is missing, malformed or fails a check |
| `port_443_taken` | Another process holds the listen address |
| `token_missing` | The spec has no token and `/etc/bugnet/egress.token` holds none |
| `apply_failed` | A file could not be written, or the forwarder did not listen within 5 s |

The spec holds placeholders only. An `env` value, `git_placeholder` or `npm_placeholder` that is
not `bnsec_` and 26 base32 characters is `bad_spec`. Hosts must be lower-case names. A second run
with the same spec changes no file and keeps the same forwarder.

`forward --config /etc/bugnet/egress.json [--root DIR]` relays raw TLS for secret hosts:

- It listens on `127.77.0.1` only. A config naming `127.0.0.1`, `::1` or any other address is
  refused, since envd on E2B publishes listeners there. Under a test `--root` it may listen on
  `127.0.0.1`, port 0 included, and it writes the address it got to `/run/bugnet/forward.addr`.
- For each connection that sends a byte, it dials the pinned IPs in order on the port, with TLS
  1.2 or newer, SNI and verification for the endpoint against the system roots. `roots_file`
  replaces them, under a test `--root` only.
- It sends `GET /v1/tunnel` with `Authorization: Bearer bnt_...` and the subprotocol
  `bugnet-tunnel.v1`, and after `101` copies bytes both ways in binary messages.
- Each IP gets 5 s to connect, then 10 s for the TLS handshake and the upgrade. A proxy that
  stalls past that is dropped and the next IP is tried, so a stalled proxy holds a slot for at
  most 15 s per IP tried.
- The first dial after start is retried once after 1 s, which tries every IP again. An answer
  from the proxy or a bad certificate is not retried.
- At most 64 connections are relayed at once. The next one waits for a slot. A connection that
  sends nothing within 10 s is closed, which frees its slot.
- `SIGHUP` reloads the config and token for new connections. Open ones keep going. A config that
  fails its checks is ignored.
- It writes `/run/bugnet/forward.pid` once it listens. Its logs hold counts and its own errors,
  never hosts, the token or bytes. A failed listen names the listen address. A config field that
  fails its check is named, never quoted.

`egress.json` holds `endpoint`, `ips`, `port`, `listen`, `token_file`, `hosts` and `roots_file`.
Its paths are sandbox paths, mapped through `--root`.

`ssh-up --spec FILE [--root DIR] [--new-host-key]` makes our sshd ready behind the gate's SSH
path. It reads the spec and deletes it, even when another argument is wrong:

```json
{"v": 1, "user": "boxd", "ports": [22, 2022], "sshd_path": "/usr/sbin/sshd", "install": true,
 "install_timeout_s": 120, "authorize": ["restrict,pty,... ssh-ed25519 AAAA... bn-gw"]}
```

Then, in this order:

1. When `sshd_path` is not an executable file and `install` is true, it runs `apt-get update` and
   `apt-get install -y --no-install-recommends openssh-server`, with `DEBIAN_FRONTEND` set to
   `noninteractive`, within `install_timeout_s` for both. If the install started a distro sshd,
   it is stopped and disabled. This step runs outside the sandbox lock, and never under `--root`.
2. It keeps the port of our running sshd. Otherwise it binds `127.0.0.1` on each of `ports` in
   turn for a moment, takes the first that binds, and writes it to `/etc/bugnet/ssh/port`.
3. It generates `/etc/bugnet/ssh/host_ed25519_key` (0600) unless a readable one exists.
   `--new-host-key` always makes a new one.
4. It adds each `authorize` line to `/etc/bugnet/ssh/authorized_keys` (0644) unless it is there.
   Other lines are kept.
5. If the user's password field in `/etc/shadow` starts with `!`, it runs `usermod -p '*'`, since
   sshd without PAM refuses a locked account. Never under `--root`.
6. It creates `/run/sshd` and `/run/bugnet` (0755).
7. It writes `/etc/bugnet/ssh/sshd_config` and records `sshd_path` in `/etc/bugnet/ssh/sshd_path`.
   A new config is first checked with `sshd -t`. Then it starts our sshd under systemd or
   `setsid`. A running sshd gets `SIGHUP` when its config or host key changed, and a restart when
   `sshd_path` changed.
8. It waits up to 10 s for `127.0.0.1:<port>` to accept.

It prints `{"port":22,"host_key":"ssh-ed25519 AAAA..."}` and exits 0. A second run with the same
spec changes no file and keeps the same sshd. On an error it prints one of these and exits 1:

| Error | Cause |
|---|---|
| `bad_spec` | The spec is missing, malformed or fails a check |
| `ports_taken` | Every port in `ports` is taken |
| `install_failed` | `apt-get` failed or ran past `install_timeout_s` |
| `sshd_missing` | `sshd_path` is not executable, and no install was allowed or it left none |
| `sshd_failed` | A file was not written, `sshd -t` refused the config, or sshd did not listen |

`user` must be a plain account name. `ports` holds 1 to 4 ports. `sshd_path` must be a clean
absolute path whose file name holds `sshd`, since respawn knows our sshd by that word in its
command line. `authorize` holds at most 16 single lines.

Our `sshd_config` has no `Include`. It listens on `127.0.0.1` only, lets in `user` alone, by key
alone, with `UsePAM no`, and allows only local forwarding to loopback. Its one `SetEnv` line holds
the lines of `/etc/bugnet/env` and then `/etc/bugnet/secrets.env`, and `egress apply` keeps it
current. Under `--root`, its paths are mapped under the root.

`respawn [--root DIR]` starts the gate, the forwarder or our sshd when its config exists and its
process is gone. It prints `{"started":["gate"]}`.

| Service | Config | Pid file |
|---|---|---|
| `bugnet-gate` | `/etc/bugnet/gate.json` | `/run/bugnet/gate.pid` |
| `bugnet-forward` | `/etc/bugnet/egress.json` | `/run/bugnet/forward.pid` |
| `bugnet-sshd` | `/etc/bugnet/ssh/sshd_config` | `/run/bugnet/sshd.pid` |

Our sshd runs `<sshd_path> -D -e -f /etc/bugnet/ssh/sshd_config`, where `sshd_path` is the one
`ssh-up` recorded, else `/usr/sbin/sshd`. sshd writes its own pid file. Respawn first makes
`/run/sshd` and `/run/bugnet`, which a boot empties.

Under systemd each is a unit in `/etc/systemd/system` with `Restart=always`,
`RuntimeDirectory=bugnet` and `RuntimeDirectoryPreserve=yes`. Units start from the runner's own
path, `/tmp/bugnet/bin/bugnet-run`. A unit that fails 10 times within 60 s stops restarting.
Respawn and setup run `systemctl reset-failed` before they start it again.

Managed blocks sit between `# bugnet begin` and `# bugnet end`. A rewrite renames a new file over
the old one. When the rename fails with `EBUSY` or `EXDEV`, as on a bind-mounted `/etc/hosts`,
it rewrites the file in place under `flock`. Lines outside the block are kept.

## Transfer helpers

The router runs these through `sudo -n` for a staged transfer, where the exec user cannot reach
the path itself. Each prints one JSON line. Paths must be absolute and are cleaned first, so a
trailing slash never makes a final symlink count.

`stat --path P` describes `P` with `lstat`, never following a final symlink:

```json
{"path": "/opt/x", "size": 5, "mode": 420, "modified_unix_nano": 1793955600000000000,
 "is_dir": false, "regular": true}
```

`mode` holds the permission bits as a number, 420 for 0644. A FIFO, a device or a symlink has
`regular` false.

`stage-out --from P --to S --owner USER` copies the regular file `P` to `S` for `USER`:

- It reads exactly the size `P` had when opened, so a file still growing gives a frozen copy.
- The copy is 0600, owned by `USER` and its primary group, and keeps the modification time of
  `P`, so its fields match the ETag the router pinned.
- Missing directories of `S` are made 0700 for `USER`. The copy is written beside `S` and renamed
  over it.
- It prints the fields of the copy.

`place --from S --to P [--mode 0644]` moves a staged upload over `P`:

- It creates the missing parents of `P` (0755).
- The file gets `--mode` and keeps the owner of the file it replaces. A new file belongs to the
  user running `place`, root under sudo. Modes above 0777 are refused.
- It renames `S` over `P`. When they sit on different filesystems, it copies `S` beside `P`,
  renames the copy over `P` and deletes `S`.
- It prints the fields of the placed file.

| Error | Exit | Cause |
|---|---|---|
| `bad_args` | 2 | A missing, relative or unknown argument, an unknown owner or a bad mode |
| `not_found` | 1 | The path, or `--from`, does not exist |
| `is_directory` | 1 | The source, or the target of `place`, is a directory |
| `not_regular` | 1 | The source is a symlink, a FIFO, a device or a socket |
| `file_changed` | 1 | The source of `stage-out` shrank while it was copied |
| `stat_failed`, `stage_failed`, `place_failed` | 1 | Any other failure |
