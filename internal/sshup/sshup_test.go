package sshup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oynozan/bugnet-run/internal/sandbox"
)

func TestSshUpPicks2022When22Held(t *testing.T) {
	t.Parallel()
	f := newFixture(t).holding(22)
	out := f.sshUp(t, f.spec())
	eq(t, out.Port, 2022)
	eq(t, f.read(t, sandbox.SSHPortFile), "2022\n")
	eq(t, strings.HasPrefix(out.HostKey, "ssh-ed25519 AAAA"), true)
	eq(t, f.sshd.take(), []string{"start", "wait 2022"})
}

func TestSshUpPortsTaken(t *testing.T) {
	t.Parallel()
	f := newFixture(t).holding(22, 2022)
	line, code := f.up(t, f.spec())
	eq(t, line, `{"error":"ports_taken"}`)
	eq(t, code, 1)
	eq(t, f.sshd.take(), []string(nil))
	eq(t, exists(f.root.Path(sandbox.SSHPortFile)), false)
	eq(t, exists(f.root.Path(sandbox.SSHDConfig)), false)
}

func TestSshUpKeepsThePortOfARunningSshd(t *testing.T) {
	t.Parallel()
	f := newFixture(t).holding(22)
	eq(t, f.sshUp(t, f.spec()).Port, 2022)
	f.held = map[int]bool{2022: true}
	f.sshd.take()
	eq(t, f.sshUp(t, f.spec()).Port, 2022)
	eq(t, f.sshd.take(), []string{"wait 2022"})

	s := f.spec()
	s.Ports = []int{22}
	eq(t, f.sshUp(t, s).Port, 22)
	eq(t, f.read(t, sandbox.SSHPortFile), "22\n")
	eq(t, f.sshd.take(), []string{"hup", "wait 22"})
}

func TestSshdConfigLines(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.sshUp(t, f.spec())
	c := f.read(t, sandbox.SSHDConfig)
	eq(t, strings.Contains(c, "Include"), false)
	eq(t, strings.Count(c, "SetEnv "), 1)
	for _, l := range []string{"UsePAM no", "PasswordAuthentication no", "AllowTcpForwarding local",
		"PermitOpen 127.0.0.1:* [::1]:*", "ListenAddress 127.0.0.1", "AllowUsers boxd"} {
		eq(t, hasLine(c, l), true)
	}
	r := f.root
	eq(t, c, "Port 22\n"+
		"ListenAddress 127.0.0.1\n"+
		"HostKey "+r.Path(sandbox.HostKeyFile)+"\n"+
		"AuthorizedKeysFile "+r.Path(sandbox.AuthorizedKeys)+"\n"+
		"AllowUsers boxd\n"+
		"PidFile "+r.Path(sandbox.PidFile("sshd"))+"\n"+
		"PubkeyAuthentication yes\n"+
		"PasswordAuthentication no\n"+
		"PermitEmptyPasswords no\n"+
		"KbdInteractiveAuthentication no\n"+
		"UsePAM no\n"+
		"SetEnv SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt "+
		"__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS=.preview.example "+
		"HF_TOKEN=bnsec_aaaaaaaaaaaaaaaaaaaaaaaaaa\n"+
		"PermitRootLogin prohibit-password\n"+
		"AllowTcpForwarding local\n"+
		"PermitOpen 127.0.0.1:* [::1]:*\n"+
		"AllowAgentForwarding no\n"+
		"AllowStreamLocalForwarding no\n"+
		"X11Forwarding no\n"+
		"PermitTunnel no\n"+
		"GatewayPorts no\n"+
		"PermitUserRC no\n"+
		"UseDNS no\n"+
		"Subsystem sftp internal-sftp\n"+
		"ClientAliveInterval 30\n"+
		"ClientAliveCountMax 3\n")
	eq(t, mode(t, r.Path(sandbox.SSHDConfig)), os.FileMode(0o644))
	eq(t, f.sshd.checked, []string{c})
	eq(t, f.read(t, sandbox.SSHDPathFile), f.sshdPath+"\n")
	for _, dir := range []string{sandbox.SSHDir, sandbox.RunDir, sandbox.SSHDRunDir} {
		eq(t, mode(t, r.Path(dir)), os.FileMode(0o755))
	}

	s := f.spec()
	s.User = "root"
	must(t, os.Remove(r.Path(sandbox.EnvFile)))
	must(t, os.Remove(r.Path(sandbox.SecretsEnvFile)))
	f.sshUp(t, s)
	c = f.read(t, sandbox.SSHDConfig)
	eq(t, hasLine(c, "AllowUsers root"), true)
	eq(t, strings.Contains(c, "SetEnv"), false)
}

func TestSshUpUnlocksBangPassword(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		shadow string
		system bool
		want   []string
	}{
		{"root:*:19000:0:99999:7:::\nboxd:!:19000:0:99999:7:::\n", true, []string{"boxd"}},
		{"boxd:!$6$salt$hash:19000:0:99999:7:::\n", true, []string{"boxd"}},
		{"boxd:!!:19000::::::\n", true, []string{"boxd"}},
		{"boxd:*:19000:0:99999:7:::\n", true, nil},
		{"boxd:$6$salt$hash:19000:0:99999:7:::\n", true, nil},
		{"root:!:19000:0:99999:7:::\nboxdx:!:19000::::::\n", true, nil},
		{"boxd:!:19000:0:99999:7:::\n", false, nil},
		{"", true, nil},
	} {
		f := newFixture(t)
		f.system = tc.system
		if tc.shadow != "" {
			writeFile(t, f.root.Path(sandbox.ShadowFile), tc.shadow)
		}
		f.sshUp(t, f.spec())
		eq(t, f.usermodCalls(), tc.want)
	}
}

func TestSshUpAuthorizeIsIdempotent(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	hand := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHand user@laptop\n"
	writeFile(t, f.root.Path(sandbox.AuthorizedKeys), hand)
	s := f.spec()
	s.Authorize = []string{gwLine, gwLine}
	f.sshUp(t, s)
	eq(t, f.read(t, sandbox.AuthorizedKeys), hand+gwLine+"\n")
	f.sshUp(t, s)
	eq(t, f.read(t, sandbox.AuthorizedKeys), hand+gwLine+"\n")
	eq(t, mode(t, f.root.Path(sandbox.AuthorizedKeys)), os.FileMode(0o644))

	other := strings.Replace(gwLine, "AAAAIOMqq", "AAAAIOMrr", 1)
	s.Authorize = []string{other, gwLine}
	f.sshUp(t, s)
	eq(t, f.read(t, sandbox.AuthorizedKeys), hand+gwLine+"\n"+other+"\n")
	eq(t, f.sshd.take(), []string{"start", "wait 22", "wait 22", "wait 22"})

	bare := newFixture(t)
	writeFile(t, bare.root.Path(sandbox.AuthorizedKeys), "ssh-ed25519 AAAAno-newline")
	bare.sshUp(t, bare.spec())
	eq(t, bare.read(t, sandbox.AuthorizedKeys), "ssh-ed25519 AAAAno-newline\n"+gwLine+"\n")
}

func TestSshUpHUPsOnConfigChange(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	first := f.sshUp(t, f.spec())
	eq(t, f.sshd.take(), []string{"start", "wait 22"})
	again := f.sshUp(t, f.spec())
	eq(t, again, first)
	eq(t, f.sshd.take(), []string{"wait 22"})

	writeFile(t, f.root.Path(sandbox.SecretsEnvFile), "HF_TOKEN=bnsec_bbbbbbbbbbbbbbbbbbbbbbbbbb\n")
	f.sshUp(t, f.spec())
	eq(t, f.sshd.take(), []string{"hup", "wait 22"})
	eq(t, strings.Contains(f.read(t, sandbox.SSHDConfig), "HF_TOKEN=bnsec_bbbb"), true)

	fresh := f.sshUp(t, f.spec(), "--new-host-key")
	eq(t, fresh.HostKey != first.HostKey, true)
	eq(t, f.sshd.take(), []string{"hup", "wait 22"})

	s := f.spec()
	s.SSHDPath = filepath.Join(f.dir, "other", "sshd")
	writeFile(t, s.SSHDPath, "#!/bin/sh\n")
	must(t, os.Chmod(s.SSHDPath, 0o755))
	f.sshUp(t, s)
	eq(t, f.sshd.take(), []string{"restart", "wait 22"})
	eq(t, f.read(t, sandbox.SSHDPathFile), s.SSHDPath+"\n")
}

func TestSshUpKeepsAWorkingSshdWhenTheCheckFails(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.sshUp(t, f.spec())
	before := f.read(t, sandbox.SSHDConfig)
	f.sshd.take()

	f.sshd.refuse = true
	writeFile(t, f.root.Path(sandbox.SecretsEnvFile), "HF_TOKEN=bnsec_bbbbbbbbbbbbbbbbbbbbbbbbbb\n")
	line, code := f.up(t, f.spec())
	eq(t, line, `{"error":"sshd_failed"}`)
	eq(t, code, 1)
	eq(t, f.sshd.take(), []string(nil))
	eq(t, f.read(t, sandbox.SSHDConfig), before)

	f.sshd.refuse, f.sshd.failWait = false, true
	line, _ = f.up(t, f.spec())
	eq(t, line, `{"error":"sshd_failed"}`)
}

func TestSshUpHostKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	out := f.sshUp(t, f.spec())
	keyFile := f.root.Path(sandbox.HostKeyFile)
	eq(t, mode(t, keyFile), os.FileMode(0o600))
	pem, err := os.ReadFile(keyFile)
	must(t, err)
	eq(t, strings.HasPrefix(string(pem), "-----BEGIN OPENSSH PRIVATE KEY-----\n"), true)
	line, err := publicLine(pem)
	must(t, err)
	eq(t, line, out.HostKey)
	eq(t, len(strings.Fields(out.HostKey)), 2)
	eq(t, f.sshUp(t, f.spec()).HostKey, out.HostKey)

	if keygen, err := exec.LookPath("ssh-keygen"); err == nil {
		got, err := exec.Command(keygen, "-y", "-f", keyFile).Output()
		must(t, err)
		eq(t, strings.Join(strings.Fields(string(got))[:2], " "), out.HostKey)
	}

	must(t, os.Chmod(keyFile, 0o644))
	eq(t, f.sshUp(t, f.spec()).HostKey, out.HostKey)
	eq(t, mode(t, keyFile), os.FileMode(0o600))

	writeFile(t, keyFile, "not a key\n")
	fresh := f.sshUp(t, f.spec())
	eq(t, fresh.HostKey != out.HostKey, true)
	pem, err = os.ReadFile(keyFile)
	must(t, err)
	line, err = publicLine(pem)
	must(t, err)
	eq(t, line, fresh.HostKey)
}

func TestNewHostKeysDiffer(t *testing.T) {
	t.Parallel()
	a, pubA, err := newHostKey()
	must(t, err)
	b, pubB, err := newHostKey()
	must(t, err)
	eq(t, bytes.Equal(a, b), false)
	eq(t, pubA != pubB, true)
}

func TestSshUpInstallsWhenAllowed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.system = true
	must(t, os.Remove(f.sshdPath))
	s := f.spec()
	s.Install, s.InstallTimeoutS = true, 90
	eq(t, f.sshUp(t, s).Port, 22)
	eq(t, f.installs, []time.Duration{90 * time.Second})
	f.sshUp(t, s)
	eq(t, len(f.installs), 1)

	for _, tc := range []struct {
		name    string
		system  bool
		install bool
		fail    error
		want    string
		tries   int
	}{
		{"install fails", true, true, errors.New("apt-get: exit status 100"), "install_failed", 1},
		{"not allowed", true, false, nil, "sshd_missing", 0},
		{"local never installs", false, true, nil, "sshd_missing", 0},
	} {
		f := newFixture(t)
		f.system, f.installErr = tc.system, tc.fail
		must(t, os.Remove(f.sshdPath))
		s := f.spec()
		s.Install = tc.install
		line, code := f.up(t, s)
		eq(t, line, `{"error":"`+tc.want+`"}`)
		eq(t, code, 1)
		eq(t, len(f.installs), tc.tries)
		eq(t, f.sshd.take(), []string(nil))
	}

	f = newFixture(t)
	s = f.spec()
	s.SSHDPath = filepath.Join(f.dir, "sbin", "plain-sshd")
	writeFile(t, s.SSHDPath, "not executable\n")
	line, _ := f.up(t, s)
	eq(t, line, `{"error":"sshd_missing"}`)
}

func TestSshUpStopsTheDistroSshdItInstalled(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.system = true
	must(t, os.MkdirAll(f.root.Path(sandbox.SystemdDir), 0o755))
	must(t, os.Remove(f.sshdPath))
	s := f.spec()
	s.Install = true
	f.sshUp(t, s)
	eq(t, f.systemctl, []string{"disable --now ssh.socket", "disable --now ssh.service"})
	f.sshUp(t, s)
	eq(t, len(f.systemctl), 2)

	f = newFixture(t)
	f.system = true
	must(t, os.Remove(f.sshdPath))
	distro := startDistroSSHD(t, f.root)
	s = f.spec()
	s.Install = true
	f.sshUp(t, s)
	eq(t, len(f.installs), 1)
	eq(t, f.systemctl, []string(nil))
	waitFor(t, 5*time.Second, func() bool { return gone(distro) })
}

// startDistroSSHD runs the fake sshd with its pid in /run/sshd.pid, as a distro's init script would
func startDistroSSHD(t *testing.T, root sandbox.Root) int {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "sshd_config")
	writeFile(t, cfg, "Port "+strconv.Itoa(freePort(t))+"\nListenAddress 127.0.0.1\n"+
		"PidFile "+root.Path("/run/sshd.pid")+"\n")
	must(t, os.MkdirAll(root.Path("/run"), 0o755))
	cmd := exec.Command(fakeSSHDPath, "-D", "-f", cfg)
	must(t, cmd.Start())
	go func() { _ = cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	waitFor(t, 5*time.Second, func() bool { return exists(root.Path("/run/sshd.pid")) })
	return cmd.Process.Pid
}

func TestSshUpBadSpec(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	valid := func(edit func(m map[string]any)) json.RawMessage {
		b, err := json.Marshal(f.spec())
		must(t, err)
		var m map[string]any
		must(t, json.Unmarshal(b, &m))
		edit(m)
		b, err = json.Marshal(m)
		must(t, err)
		return b
	}
	long := "ssh-ed25519 AAAA" + strings.Repeat("A", 8200)
	cases := map[string]json.RawMessage{
		"not json":    json.RawMessage(`{"v":`),
		"trailing":    json.RawMessage(string(valid(func(map[string]any) {})) + "{}"),
		"unknown":     valid(func(m map[string]any) { m["extra"] = 1 }),
		"version":     valid(func(m map[string]any) { m["v"] = 2 }),
		"no user":     valid(func(m map[string]any) { m["user"] = "" }),
		"dash user":   valid(func(m map[string]any) { m["user"] = "-oProxyCommand" }),
		"spaced user": valid(func(m map[string]any) { m["user"] = "boxd root" }),
		"glob user":   valid(func(m map[string]any) { m["user"] = "*" }),
		"no ports":    valid(func(m map[string]any) { m["ports"] = []int{} }),
		"port 0":      valid(func(m map[string]any) { m["ports"] = []int{0} }),
		"port 65536":  valid(func(m map[string]any) { m["ports"] = []int{65536} }),
		"same port":   valid(func(m map[string]any) { m["ports"] = []int{22, 22} }),
		"five ports":  valid(func(m map[string]any) { m["ports"] = []int{1, 2, 3, 4, 5} }),
		"relative":    valid(func(m map[string]any) { m["sshd_path"] = "sbin/sshd" }),
		"unclean":     valid(func(m map[string]any) { m["sshd_path"] = "/usr/sbin/../sbin/sshd" }),
		"not sshd":    valid(func(m map[string]any) { m["sshd_path"] = "/usr/sbin/dropbear" }),
		"no path":     valid(func(m map[string]any) { m["sshd_path"] = "" }),
		"no timeout": valid(func(m map[string]any) {
			m["install"], m["install_timeout_s"] = true, 0
		}),
		"long timeout": valid(func(m map[string]any) { m["install_timeout_s"] = 601 }),
		"neg timeout":  valid(func(m map[string]any) { m["install_timeout_s"] = -1 }),
		"newline":      valid(func(m map[string]any) { m["authorize"] = []string{gwLine + "\nx"} }),
		"cr":           valid(func(m map[string]any) { m["authorize"] = []string{gwLine + "\r"} }),
		"empty line":   valid(func(m map[string]any) { m["authorize"] = []string{" "} }),
		"comment":      valid(func(m map[string]any) { m["authorize"] = []string{"# " + gwLine} }),
		"long line":    valid(func(m map[string]any) { m["authorize"] = []string{long} }),
		"17 lines": valid(func(m map[string]any) {
			lines := make([]string, 17)
			for i := range lines {
				lines[i] = gwLine + strconv.Itoa(i)
			}
			m["authorize"] = lines
		}),
	}
	for name, raw := range cases {
		line, code := f.up(t, raw)
		if line != `{"error":"bad_spec"}` || code != 1 {
			t.Errorf("%s: printed %s and exited %d", name, line, code)
		}
	}
	eq(t, exists(f.root.Path(sandbox.SSHDir)), false)
	eq(t, f.sshd.take(), []string(nil))

	var out, errOut bytes.Buffer
	res, err := run(context.Background(), []string{"--root", f.root.Dir()}, f.tune)
	eq(t, report(&out, &errOut, res, err), 1)
	eq(t, out.String(), `{"error":"bad_spec"}`+"\n")

	path := filepath.Join(f.dir, "ssh-spec.json")
	secret := valid(func(m map[string]any) { m["authorize"] = []string{gwLine + "\nsecret-line"} })
	must(t, os.WriteFile(path, secret, 0o600))
	out.Reset()
	res, err = run(context.Background(), []string{"--spec", path, "--nope"}, f.tune)
	eq(t, report(&out, &errOut, res, err), 1)
	eq(t, out.String(), `{"error":"bad_spec"}`+"\n")
	eq(t, exists(path), false)
	must(t, os.WriteFile(path, secret, 0o600))
	_, err = run(context.Background(), []string{"--spec", path, "--root", f.root.Dir()}, f.tune)
	eq(t, strings.Contains(err.Error(), "secret-line"), false)
	eq(t, strings.Contains(err.Error(), "authorize"), true)
}

func TestSshUpRunsSupervisedSshd(t *testing.T) {
	t.Parallel()
	root, err := sandbox.NewRoot(t.TempDir())
	must(t, err)
	t.Cleanup(func() { stopPidFile(t, root, "sshd") })
	port := freePort(t)
	spec, err := json.Marshal(Spec{
		V: 1, User: "boxd", Ports: []int{port}, SSHDPath: fakeSSHDPath, Authorize: []string{gwLine},
	})
	must(t, err)
	dir := t.TempDir()
	up := func() Result {
		t.Helper()
		path := filepath.Join(dir, "ssh-spec.json")
		must(t, os.WriteFile(path, spec, 0o600))
		var out, errOut bytes.Buffer
		if code := Run([]string{"--spec", path, "--root", root.Dir()}, &out, &errOut); code != 0 {
			t.Fatalf("ssh-up printed %s and exited %d: %s", out.String(), code, errOut.String())
		}
		var res Result
		must(t, json.Unmarshal(out.Bytes(), &res))
		return res
	}
	log := func() string {
		b, _ := os.ReadFile(filepath.Join(root.Path(sandbox.SSHDir), "fake-sshd.log"))
		return string(b)
	}
	p := strconv.Itoa(port)

	eq(t, up().Port, port)
	eq(t, acceptsAt("127.0.0.1:"+p), true)
	pid, err := sandbox.ReadPidFile(root, "sshd")
	must(t, err)
	eq(t, log(), "start "+p+"\n")

	eq(t, up().Port, port)
	again, err := sandbox.ReadPidFile(root, "sshd")
	must(t, err)
	eq(t, again, pid)
	eq(t, log(), "start "+p+"\n")

	writeFile(t, root.Path(sandbox.SecretsEnvFile), "HF_TOKEN=bnsec_bbbbbbbbbbbbbbbbbbbbbbbbbb\n")
	up()
	waitFor(t, 5*time.Second, func() bool { return strings.Count(log(), "\n") == 2 })
	eq(t, log(), "start "+p+"\nhup "+p+"\n")

	must(t, syscall.Kill(pid, syscall.SIGKILL))
	waitFor(t, 5*time.Second, func() bool { return gone(pid) })
	up()
	fresh, err := sandbox.ReadPidFile(root, "sshd")
	must(t, err)
	eq(t, fresh != pid, true)
	eq(t, acceptsAt("127.0.0.1:"+p), true)
}

func TestSshUpFailsWhenSshdNeverListens(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.wait = 300 * time.Millisecond
	t.Cleanup(func() { stopPidFile(t, f.root, "sshd") })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer func() { _ = ln.Close() }()
	s := f.spec()
	s.SSHDPath, s.Ports = fakeSSHDPath, []int{ln.Addr().(*net.TCPAddr).Port}
	line, code := f.up(t, s)
	eq(t, line, `{"error":"sshd_failed"}`)
	eq(t, code, 1)
}

func TestCheckRedactsPlaceholders(t *testing.T) {
	t.Parallel()
	root, err := sandbox.NewRoot(t.TempDir())
	must(t, err)
	must(t, os.MkdirAll(root.Path(sandbox.SSHDir), 0o755))
	d := supervised{sup: sandbox.Supervisor{Root: root}}
	cfg := "Port 22\nListenAddress 127.0.0.1\nPidFile /run/bugnet/sshd.pid\n" +
		"SetEnv HF_TOKEN=bnsec_" + strings.Repeat("a", 26) + "\n"
	must(t, d.Check(context.Background(), fakeSSHDPath, []byte(cfg)))

	err = d.Check(context.Background(), fakeSSHDPath, []byte(cfg+"Refuse yes\n"))
	if err == nil {
		t.Fatal("a refused config passed the check")
	}
	eq(t, strings.Contains(err.Error(), "HF_TOKEN=bnsec_"), true)
	eq(t, strings.Contains(err.Error(), "aaaa"), false)
	entries, err := os.ReadDir(root.Path(sandbox.SSHDir))
	must(t, err)
	eq(t, len(entries), 0)
}

func TestRedact(t *testing.T) {
	t.Parallel()
	eq(t, string(redact([]byte("A=bnsec_abcz234567 B=bnsec_ C=bnsec_x9 bnsec"))),
		"A=bnsec_ B=bnsec_ C=bnsec_9 bnsec")
}
