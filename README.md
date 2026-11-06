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
otherwise. It calls sudo only when a service is down or the firewall is due its check. A failed
respawn never fails the job.

### Job peaks

The exit frame carries the job's peak memory and whether the kernel killed it for memory:
`{"t":"x","code":137,"o":5,"e":12,"oom":true,"pk":700}`. `pk` is the peak in MiB, rounded up.
Both are left out when they are zero or false.

Where `/sys/fs/cgroup` is a cgroup v2 mount the supervisor can write, the job runs in a cgroup
of its own, `/sys/fs/cgroup/bugnet/jobs/<id>`:

- The supervisor makes it and writes `+memory` to the `cgroup.subtree_control` of the root,
  `bugnet` and `bugnet/jobs`. Only where the kernel takes `+memory` does it add `+cpu` and
  `+io`, one at a time. `cpu` alone on a namespace root that holds processes would make it a
  thread root, below which no job cgroup can start.
- The command starts straight in it, through `clone3`. When the kernel refuses that, the command
  starts again outside it.
- At exit, `pk` comes from `memory.peak`, and `oom` is true when `memory.events` counts an
  `oom_kill`, of the command or of any process it started.
- The cgroup is then removed, unless a process the job started still runs in it.

Otherwise, and for any file the cgroup lacks:

- `pk` comes from the command's `ru_maxrss`.
- `oom` is true when the `oom_kill` count in `/proc/vmstat` grew during the job and the job
  failed. That count is the whole sandbox's, so a job that succeeds never reports one.
- Without `/proc/vmstat`, exit code 137 alone sets `oom`.

The supervisor writes the job's `stats` file just before its `exit` file:

```json
{"v": 1, "source": "cgroup", "peak_mib": 700, "oom": true, "oom_kills": 1, "cpu_usec": 1500,
 "io_read_bytes": 4097, "io_write_bytes": 8194}
```

`source` names where `peak_mib` came from. It is `cgroup` for the cgroup's `memory.peak`, and
`rusage` for `ru_maxrss`, the peak of the largest single process. A cgroup without the memory
controller, or on a kernel before 5.19, has no `memory.peak`, so its job reports `rusage`.
`oom_kills` counts the job's cgroup where it has `memory.events`, else the whole sandbox. The
`io_*` fields come only from a cgroup. A command that never started has no `stats` file. Jobs
that run as a user other than root cannot make cgroups, so they always take `rusage`.

## Sandbox services

These run as root. `--root DIR` maps every sandbox path under `DIR`, for the `local` provider.
`--spec` and `--config` take real paths.

`setup --spec FILE [--root DIR] [--repair]` reads the spec, deletes it, and then:

1. Writes `/etc/bugnet/gate.key` (0600) and `/etc/bugnet/gate.json` (0644).
2. Installs the Bugnet CA as `/usr/local/share/ca-certificates/bugnet-egress-v<N>.crt`.
3. Writes `/etc/bugnet/env` and `/etc/profile.d/bugnet.sh`.
4. Copies the running binary to `/usr/local/lib/bugnet/bugnet-run` (0755, owned by root). The
   copy goes to a temporary file beside it and is renamed over it, so a service still running
   the old file keeps it. A file that already holds the same bytes is left alone.
5. Starts the gate, under systemd when `/run/systemd/system` exists, else with `setsid`.
6. With `"sample": true`, writes `/etc/bugnet/sample.json` (0644) and starts the sampler, the
   same way. A sampler that does not start is logged on stderr and never fails setup. A later
   setup without `sample` leaves a running sampler alone.

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
config restarts the gate. `--repair` redoes only steps 1, 4 and 5. Without `--spec`, it keeps the
gate files the last setup wrote.

`gate --config /etc/bugnet/gate.json [--root DIR]` is the reverse proxy on `:29417`. Every
response carries `Bugnet-Gate-Response: 1`. A missing or wrong `Bugnet-Gate` key gets a bare
404. A connection that sends no whole request header within 1 min is closed, and so is one that
sends nothing for 10 min after an answer. Neither limit cuts a request, an answer or an open
WebSocket short.

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
reads the spec and deletes it, even when the spec or an argument after `--spec` is wrong. Then,
in this order:

1. Writes `/etc/bugnet/egress.token` (0600) when the spec carries a token.
2. Writes `/etc/bugnet/egress.json` (0644) with the endpoint, its pinned IPs, the port, the listen
   address and the hosts.
3. Starts the forwarder, or sends it `SIGHUP` when its config or token changed. A new listen
   address restarts it. Before a start it binds the listen address for a moment, so a taken port
   is found at once. A start or restart first copies the runner as `setup` does.
4. Waits up to 5 s for the forwarder's pid file and for the listen address to accept.
5. Rewrites the `/etc/hosts` block to `127.77.0.1 <host> <host> ...`. Lines stay under 500
   bytes, since musl reads 512 at a time. There is never a `::1` line.
6. Writes `/etc/bugnet/secrets.env` (0644) and `/etc/profile.d/bugnet.sh`. When our
   `sshd_config` exists, its one `SetEnv` line is rewritten, and our sshd gets `SIGHUP` if it
   changed. It then keeps the sandbox lock for up to 10 s, until sshd writes its pid file again,
   so an `ssh-up` waiting for the lock never finds sshd in the middle of a reload. An sshd that
   exits instead is left for `respawn`.
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
| `apply_failed` | A write failed, the forwarder did not listen in 5 s, or sshd hung in a reload |

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
path. It reads the spec and deletes it, even when the spec or an argument after `--spec` is
wrong:

```json
{"v": 1, "user": "boxd", "ports": [22, 2022], "sshd_path": "/usr/sbin/sshd", "install": true,
 "install_timeout_s": 120, "authorize": ["restrict,pty,... ssh-ed25519 AAAA... bn-gw"]}
```

Then, in this order:

1. When `sshd_path` is not an executable file and `install` is true, it runs `apt-get update` and
   `apt-get install -y --no-install-recommends openssh-server`, with `DEBIAN_FRONTEND` set to
   `noninteractive`, within `install_timeout_s` for both. If the install started a distro sshd,
   it is stopped and disabled. This step never runs under `--root`. It runs outside the sandbox
   lock, under an `flock` of `/etc/bugnet/ssh` that only this step takes. A second run waits
   there and then finds sshd in place.
2. Under the sandbox lock, it removes the dot-files in `/etc/bugnet/ssh` that a killed run left.
3. It keeps the port of our running sshd while that port is still in `ports`. Otherwise it binds
   `127.0.0.1` on each of `ports` in turn for a moment and takes the first that binds.
4. It keeps `/etc/bugnet/ssh/host_ed25519_key` when it holds a readable key, and sets it to 0600.
   Otherwise, or with `--new-host-key`, it writes a new key (0600) to a temporary file beside it.
5. It adds each `authorize` line to `/etc/bugnet/ssh/authorized_keys` (0644) unless it is there.
   Other lines are kept.
6. If the user's password field in `/etc/shadow` starts with `!`, it runs `usermod -p '*'`, since
   sshd without PAM refuses a locked account. Never under `--root`.
7. It creates `/run/sshd` and `/run/bugnet` (0755).
8. A new config, a new key or a new `sshd_path` is first checked with `sshd -t`, reading the new
   key where it waits. Only then does it write `/etc/bugnet/ssh/sshd_config`, `port` and, last,
   `sshd_path`, and rename the new key over `host_ed25519_key`. A refused check changes none of
   them.
9. It starts our sshd under systemd or `setsid`. A running sshd gets `SIGHUP` when its config or
   host key changed, and a restart when `sshd_path` changed. Any of these files newer than sshd's
   pid file also counts as changed, since a run killed before its signal leaves one behind.
10. It waits up to 10 s for `127.0.0.1:<port>` to accept. After a `SIGHUP` it also waits for sshd
    to write its pid file again, which sshd does once it listens again. Until then the old
    listener may still answer.

It prints `{"port":22,"host_key":"ssh-ed25519 AAAA..."}` and exits 0. The key it prints is the one
our sshd serves. A second run with the same spec changes no file and keeps the same sshd. On an
error it prints one of these and exits 1:

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

`harden --spec FILE` blocks the sandbox's outbound mail, private ranges, metadata addresses and
mining pools. It runs as root and never under `--root`. It reads the spec and deletes it, even
when the spec or an argument after `--spec` is wrong:

```json
{"v": 1, "mail_ports": [25, 465, 587], "deny_ranges": ["10.0.0.0/8", "fe80::/10"],
 "pools": ["198.51.100.0/24"], "allow": ["203.0.113.7"]}
```

Every entry of `deny_ranges`, `pools` and `allow` is a CIDR or a bare address. `pools` holds at
most 10,000 entries, the others at most 1,000 and `mail_ports` at most 64.

The rules apply to outbound traffic only. These are allowed first, in this order:

- Loopback, and established or related traffic.
- TCP and UDP port 53 of each `nameserver` in `/etc/resolv.conf` and
  `/run/systemd/resolve/resolv.conf`, so a resolver in `10.0.0.0/8` keeps working.
- The next hop of each default route in `/proc/net/route` and `/proc/net/ipv6_route`, the
  default gateway even in a private range.
- DHCP renewals (UDP 68 to 67, and 546 to 547), and IPv6 neighbour solicitations, neighbour
  adverts and router solicitations, so the lease and IPv6 routing survive the blocks.
- Each `allow` entry, the provider's own control addresses.

Then these are rejected: TCP to each of `mail_ports` on any address, each `deny_ranges` entry, and
each pool. TCP gets a reset and other traffic ICMP admin-prohibited, so a blocked connection
fails at once as refused or unreachable. A dropped one would hang until the client gave up, about
2 minutes for a TCP connect.

1. When neither `nft` nor `iptables-restore` exists, it runs `apt-get update` and
   `apt-get install -y --no-install-recommends nftables`, within 60 s for both. This runs before
   the sandbox lock.
2. With `nft`, it loads one table, `inet bugnet`, with `nft -f`. The file adds the table, deletes
   it and makes it again in one transaction, so a second run leaves one table. Pools sit in the
   interval sets `pools4` and `pools6`, with prefixes inside others left out.
3. Without `nft`, or when `nft` fails, it refills a `BUGNET` chain with `iptables-restore
   --noflush` and `ip6tables-restore --noflush`, and makes `OUTPUT` jump to it once. Without IPv6
   in the kernel (no `/proc/net/if_inet6`), an IPv6 failure is ignored. Any other IPv6 failure
   puts back the IPv4 chain that `/etc/bugnet/firewall.rules` keeps, or empties it when that file
   holds no iptables ruleset. So both families load, or neither does.
4. It keeps what loaded in `/etc/bugnet/firewall.rules` (0644), renamed into place only after the
   load. Its first line names the tool, `# bugnet-run harden nft` or `# bugnet-run harden
   iptables`. The iptables file holds the IPv4 input, a `# ipv6` line and the IPv6 input.

It prints `{"firewall":"nft"}` or `{"firewall":"iptables"}` and exits 0. On an error it prints
one of these and exits 1:

| Error | Cause |
|---|---|
| `bad_spec` | The spec is missing, malformed or fails a check, such as more than 10,000 pools |
| `firewall_unavailable` | No tool could be installed, or the kernel or container refused it |

`sample [--config /etc/bugnet/sample.json] [--root DIR]` records the whole sandbox's peaks for the
router's estimator. Its config is `{"v":1}`, read strictly. It locks `/run/bugnet/sample.lock`
(0600), and exits 0 at once while another sampler holds that lock. So a sampler that setup and a
respawn both started, before the first wrote its pid file, runs once. It writes
`/run/bugnet/sample.pid`, and then:

- Every second it reads `/proc/meminfo`, the `oom_kill` count in `/proc/vmstat` and the `cpu`
  lines of `/proc/stat`, and it runs `statfs` on `/`, `/tmp`, `/root` and the first 16
  directories in `/home` by name. A filesystem counts once, and `tmpfs` not at all, since memory
  already counts it.
- Every 5 s it runs `nvidia-smi --query-gpu=memory.used,memory.total
  --format=csv,noheader,nounits` when that exists, within 3 s.
- At the first reading, every 5 s and at `SIGTERM`, it writes `/tmp/bugnet/stats.json` (0644)
  through a temporary file renamed over it. It never makes `/tmp/bugnet`, which the exec user
  owns, and skips the write while that is missing.
- At each write, it exits instead when its config is gone, as when a local sandbox's directory
  is deleted. Otherwise it runs until `SIGTERM`.

```json
{"v": 1, "mem_peak_mib": 700, "swap_peak_mib": 0, "disk_peak_mib": 400, "cpu_seconds": 4,
 "busy_p95_millicores": 2000, "gpu_mem_peak_mib": 0, "oom_kills": 0, "samples": 5,
 "updated_at": "2026-11-06T12:00:04Z"}
```

| Field | Meaning |
|---|---|
| `mem_peak_mib` | The peak of `MemTotal` minus `MemAvailable`, rounded up |
| `swap_peak_mib` | The peak of `SwapTotal` minus `SwapFree`, rounded up |
| `disk_peak_mib` | The peak of used bytes above those at the sampler's start, never below 0 |
| `cpu_seconds` | Busy CPU time since the start: user, nice, system, irq and softirq |
| `busy_p95_millicores` | The 95th percentile of each second's busy CPU, 1000 per core, to 10 |
| `gpu_mem_peak_mib` | The peak of `memory.used` summed over the GPUs, 0 without `nvidia-smi` |
| `oom_kills` | The growth of the `oom_kill` count since the start |
| `samples`, `updated_at` | How many readings, and the last one's time in UTC |

Every number is whole. A source the sandbox lacks is skipped, and its fields stay 0.

At its start it reads the `stats.json` an earlier sampler left, so a sampler that `respawn`
brings back loses no peak. It keeps that file's peaks, `cpu_seconds`, `oom_kills` and `samples`,
and counts the earlier seconds at their `busy_p95_millicores`. Disk growth after the restart
counts from the level at the restart. It starts from zero when the file is not a regular file of
at most 4 KiB, fails the strict decoding of version 1, or holds a number above 2^40.

`respawn [--root DIR]` starts the gate, the forwarder, our sshd or the sampler when its config
exists and its process is gone. Before it starts any, it copies the runner as `setup` does. It
prints `{"started":["gate"]}`.

A pid file counts only while its process is alive and, where `/proc` exists, its command line
holds the service's word (`gate`, `forward`, `sample` or `sshd`) and the service's config path
under this root, standing alone. So a pid reused by another process, or once held by another
local root's service, never counts.

It also puts the firewall back. When `/etc/bugnet/firewall.rules` exists and the last check is a
minute old or more, it checks that the table is loaded: `nft list tables` shows `table inet
bugnet`, or `iptables -w -C OUTPUT -j BUGNET` and its IPv6 twin pass. When the table is gone it
loads the file again, and `started` holds `firewall`. Each check touches
`/run/bugnet/firewall.checked`, as `harden` does, so `start` calls sudo for it at most once a
minute. Root can still remove the table between jobs.

| Service | Config | Pid file |
|---|---|---|
| `bugnet-gate` | `/etc/bugnet/gate.json` | `/run/bugnet/gate.pid` |
| `bugnet-forward` | `/etc/bugnet/egress.json` | `/run/bugnet/forward.pid` |
| `bugnet-sshd` | `/etc/bugnet/ssh/sshd_config` | `/run/bugnet/sshd.pid` |
| `bugnet-sample` | `/etc/bugnet/sample.json` | `/run/bugnet/sample.pid` |

Our sshd runs `<sshd_path> -D -e -f /etc/bugnet/ssh/sshd_config`, where `sshd_path` is the one
`ssh-up` recorded, else `/usr/sbin/sshd`. sshd writes its own pid file. Respawn first makes
`/run/sshd` and `/run/bugnet`, which a boot empties.

Under systemd each is a unit in `/etc/systemd/system` with `Restart=always`,
`RuntimeDirectory=bugnet` and `RuntimeDirectoryPreserve=yes`. Every unit and every `setsid`
start but our sshd's runs `/usr/local/lib/bugnet/bugnet-run`, mapped under `--root` like any
other path, never the path the runner ran from. A boot that empties `/tmp` therefore leaves every
unit able to start. A unit that fails 10 times within 60 s stops restarting. Respawn and setup
run `systemctl reset-failed` before they start it again.

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

- It creates the missing parents of `P`, 0755 whatever the umask, with the new file's owner.
- It opens `S` once without following a symlink, and sets the owner and mode through that open
  file, so a path swapped meanwhile is never changed.
- The file gets `--mode` and keeps the owner of the file it replaces. A new file keeps the owner
  of `S`, as `sudo mv` would. Modes above 0777 are refused.
- It renames `S` over `P`. When they sit on different filesystems, it copies the open file
  beside `P`, renames the copy over `P` and deletes `S`. When the renamed file is not the one it
  opened, it answers `place_failed`.
- It prints the fields of the placed file.

| Error | Exit | Cause |
|---|---|---|
| `bad_args` | 2 | A missing, relative or unknown argument, an unknown owner or a bad mode |
| `not_found` | 1 | The path, or `--from`, does not exist |
| `is_directory` | 1 | The source, or the target of `place`, is a directory |
| `not_regular` | 1 | The source is a symlink, a FIFO, a device or a socket |
| `file_changed` | 1 | The source of `stage-out` shrank while it was copied |
| `stat_failed`, `stage_failed`, `place_failed` | 1 | Any other failure |
