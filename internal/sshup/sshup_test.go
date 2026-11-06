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
	out := f.sshUp(t, f.spec())
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
	// The check read the new key where it waited, beside the key file
	eq(t, len(f.sshd.checked), 1)
	pending := configHostKey(f.sshd.checked[0])
	eq(t, filepath.Dir(pending), r.Path(sandbox.SSHDir))
	eq(t, strings.HasPrefix(filepath.Base(pending), ".host_ed25519_key.new-"), true)
	eq(t, strings.Replace(f.sshd.checked[0], "HostKey "+pending+"\n",
		"HostKey "+r.Path(sandbox.HostKeyFile)+"\n", 1), c)
	eq(t, f.sshd.checkedKeys, []string{out.HostKey})
	eq(t, exists(pending), false)
	eq(t, dotFiles(t, r), []string(nil))
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

	// The port file keeps naming the port sshd listens on until a new config passes the check
	f = newFixture(t).holding(22)
	eq(t, f.sshUp(t, f.spec()).Port, 2022)
	f.held = map[int]bool{2022: true}
	f.sshd.take()
	f.sshd.refuse = true
	s := f.spec()
	s.Ports = []int{22}
	line, _ = f.up(t, s)
	eq(t, line, `{"error":"sshd_failed"}`)
	eq(t, f.read(t, sandbox.SSHPortFile), "2022\n")
	eq(t, f.sshd.take(), []string(nil))

	f.sshd.refuse, f.sshd.failWait = false, true
	line, _ = f.up(t, s)
	eq(t, line, `{"error":"sshd_failed"}`)
	eq(t, f.sshd.take(), []string{"hup", "wait 22"})
	eq(t, f.read(t, sandbox.SSHPortFile), "22\n")
}

func TestSshUpReportsTheKeySshdServes(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	first := f.sshUp(t, f.spec())
	eq(t, f.sshd.served(), first.HostKey)
	keyFile := f.root.Path(sandbox.HostKeyFile)
	pem := f.read(t, sandbox.HostKeyFile)
	f.sshd.take()

	f.sshd.refuse = true
	line, code := f.up(t, f.spec(), "--new-host-key")
	eq(t, line, `{"error":"sshd_failed"}`)
	eq(t, code, 1)
	eq(t, f.read(t, sandbox.HostKeyFile), pem)
	eq(t, dotFiles(t, f.root), []string(nil))
	f.sshd.refuse = false
	again := f.sshUp(t, f.spec())
	eq(t, again.HostKey, first.HostKey)
	eq(t, f.sshd.served(), again.HostKey)
	eq(t, f.sshd.take(), []string{"wait 22"})

	// sshd took the new key with its SIGHUP, so a wait that fails leaves both on the new key
	f.sshd.failWait = true
	line, _ = f.up(t, f.spec(), "--new-host-key")
	eq(t, line, `{"error":"sshd_failed"}`)
	f.sshd.failWait = false
	fresh := f.sshUp(t, f.spec())
	eq(t, fresh.HostKey != first.HostKey, true)
	eq(t, f.sshd.served(), fresh.HostKey)
	eq(t, f.sshd.take(), []string{"hup", "wait 22", "wait 22"})

	// A run killed between the key's rename and its SIGHUP leaves the reload owed
	f.sshd.killed = true
	line, _ = f.up(t, f.spec(), "--new-host-key")
	eq(t, line, `{"error":"sshd_failed"}`)
	f.sshd.killed = false
	owed := f.sshUp(t, f.spec())
	eq(t, owed.HostKey != fresh.HostKey, true)
	eq(t, f.sshd.served(), owed.HostKey)
	eq(t, f.sshd.take(), []string{"hup", "hup", "wait 22"})
	eq(t, f.sshUp(t, f.spec()), owed)
	eq(t, f.sshd.take(), []string{"wait 22"})

	writeFile(t, keyFile, "not a key\n")
	must(t, os.Chmod(keyFile, 0o600))
	f.sshd.refuse = true
	line, _ = f.up(t, f.spec())
	eq(t, line, `{"error":"sshd_failed"}`)
	eq(t, f.read(t, sandbox.HostKeyFile), "not a key\n")
	f.sshd.refuse = false
	last := f.sshUp(t, f.spec())
	eq(t, f.sshd.served(), last.HostKey)
	eq(t, f.sshd.take(), []string{"hup", "wait 22"})
	eq(t, dotFiles(t, f.root), []string(nil))
}

func TestSshUpRecordsSshdPathLast(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.sshUp(t, f.spec())
	f.sshd.take()
	s := f.spec()
	s.SSHDPath = filepath.Join(f.dir, "other", "sshd")
	writeFile(t, s.SSHDPath, "#!/bin/sh\n")
	must(t, os.Chmod(s.SSHDPath, 0o755))

	// A port file that cannot be written stops the run before sshd_path and the restart
	port := f.root.Path(sandbox.SSHPortFile)
	must(t, os.Remove(port))
	must(t, os.MkdirAll(filepath.Join(port, "busy"), 0o755))
	line, _ := f.up(t, s)
	eq(t, line, `{"error":"sshd_failed"}`)
	eq(t, f.read(t, sandbox.SSHDPathFile), f.sshdPath+"\n")
	eq(t, f.sshd.take(), []string(nil))

	must(t, os.RemoveAll(port))
	f.sshUp(t, s)
	eq(t, f.sshd.take(), []string{"restart", "wait 22"})
	eq(t, f.read(t, sandbox.SSHDPathFile), s.SSHDPath+"\n")

	// A run killed between writing sshd_path and the restart leaves the restart owed
	f.sshd.killed = true
	line, _ = f.up(t, f.spec())
	eq(t, line, `{"error":"sshd_failed"}`)
	eq(t, f.read(t, sandbox.SSHDPathFile), f.sshdPath+"\n")
	f.sshd.killed = false
	f.sshUp(t, f.spec())
	eq(t, f.sshd.take(), []string{"restart", "restart", "wait 22"})
	f.sshUp(t, f.spec())
	eq(t, f.sshd.take(), []string{"wait 22"})
}

func TestSshUpSignalsWhatAKilledRunWrote(t *testing.T) {
	t.Parallel()
	root, err := sandbox.NewRoot(t.TempDir())
	must(t, err)
	t.Cleanup(func() { stopPidFile(t, root, "sshd") })
	from, to := freePort(t), freePort(t)
	dir := t.TempDir()
	up := func(port int, tune func(*upper)) (Result, error) {
		t.Helper()
		spec, err := json.Marshal(Spec{
			V: 1, User: "boxd", Ports: []int{port}, SSHDPath: fakeSSHDPath,
			Authorize: []string{gwLine},
		})
		must(t, err)
		path := filepath.Join(dir, "ssh-spec.json")
		must(t, os.WriteFile(path, spec, 0o600))
		return run(context.Background(), []string{"--spec", path, "--root", root.Dir()}, tune)
	}
	res, err := up(from, nil)
	must(t, err)
	eq(t, res.Port, from)

	// The killed run wrote the config and port file for the new port but sent no SIGHUP
	_, err = up(to, func(u *upper) { u.sshd = unsignalled{u.sshd} })
	eq(t, err != nil, true)
	eq(t, strings.TrimSpace(readRoot(t, root, sandbox.SSHPortFile)), strconv.Itoa(to))
	eq(t, acceptsAt(net.JoinHostPort("127.0.0.1", strconv.Itoa(from))), true)

	res, err = up(to, nil)
	must(t, err)
	eq(t, res.Port, to)
	eq(t, acceptsAt(net.JoinHostPort("127.0.0.1", strconv.Itoa(to))), true)
	b, err := os.ReadFile(filepath.Join(root.Path(sandbox.SSHDir), "fake-sshd.log"))
	must(t, err)
	eq(t, string(b), "start "+strconv.Itoa(from)+"\nhup "+strconv.Itoa(to)+"\n")
}

// unsignalled stands in for a run killed after its writes and before its SIGHUP
type unsignalled struct{ daemon }

func (unsignalled) Reload() error { return errors.New("killed before the signal") }

func readRoot(t *testing.T, root sandbox.Root, path string) string {
	t.Helper()
	b, err := os.ReadFile(root.Path(path))
	must(t, err)
	return string(b)
}

func TestSshUpClearsWhatAKilledRunLeft(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.sshUp(t, f.spec())
	dir := f.root.Path(sandbox.SSHDir)
	for _, name := range []string{".sshd_config.check-1", ".host_ed25519_key.new-2",
		".port.bugnet-3"} {
		writeFile(t, filepath.Join(dir, name), "left by a killed run\n")
	}
	f.sshUp(t, f.spec())
	eq(t, dotFiles(t, f.root), []string(nil))
	eq(t, exists(f.root.Path(sandbox.HostKeyFile)), true)
	eq(t, exists(f.root.Path(sandbox.AuthorizedKeys)), true)
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

func TestSshUpWaitsForAnotherInstall(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.system = true
	must(t, os.Remove(f.sshdPath))
	s := f.spec()
	s.Install = true
	b, err := json.Marshal(s)
	must(t, err)
	specPath := filepath.Join(f.dir, "ssh-spec.json")
	must(t, os.WriteFile(specPath, b, 0o600))

	dir := f.root.Path(sandbox.SSHDir)
	must(t, os.MkdirAll(dir, 0o755))
	held, err := os.Open(dir)
	must(t, err)
	must(t, syscall.Flock(int(held.Fd()), syscall.LOCK_EX))
	type outcome struct {
		res Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := run(context.Background(), []string{"--spec", specPath, "--root",
			f.root.Dir()}, f.tune)
		done <- outcome{res, err}
	}()
	select {
	case o := <-done:
		t.Fatalf("ssh-up ended with %+v and %v while another install held the lock", o.res, o.err)
	case <-time.After(300 * time.Millisecond):
	}

	// The other run's install leaves sshd in place before it lets go
	writeFile(t, f.sshdPath, "#!/bin/sh\n")
	must(t, os.Chmod(f.sshdPath, 0o755))
	must(t, held.Close())
	select {
	case o := <-done:
		must(t, o.err)
		eq(t, o.res.Port, 22)
	case <-time.After(5 * time.Second):
		t.Fatal("ssh-up never went on once the lock was free")
	}
	eq(t, len(f.installs), 0)
	eq(t, f.systemctl, []string(nil))
}

func TestSshUpInstallRunsAptGet(t *testing.T) {
	t.Parallel()
	apt := fakeApt(t)
	must(t, runInstall(context.Background(), apt.path, 120*time.Second))
	opts := "-o DPkg::Lock::Timeout=120 -o Dpkg::Options::=--force-confdef " +
		"-o Dpkg::Options::=--force-confold "
	env := "DEBIAN_FRONTEND=noninteractive "
	eq(t, apt.calls(t), env+opts+"update\n"+
		env+opts+"install -y --no-install-recommends openssh-server\n")

	apt.exit(t, 100)
	err := runInstall(context.Background(), apt.path, 120*time.Second)
	eq(t, err != nil, true)
	eq(t, strings.Contains(err.Error(), "apt-get update: exit status 100: E: The repository"),
		true)
	eq(t, strings.Count(apt.calls(t), "\n"), 1)
}

func TestSshUpInstallTimeoutCoversBothCommands(t *testing.T) {
	t.Parallel()
	apt := fakeApt(t)
	// Each command alone fits the timeout
	for _, sleeps := range [][2]string{{"1.8", "0"}, {"0", "1.8"}} {
		apt.sleep(t, sleeps[0], sleeps[1])
		must(t, runInstall(context.Background(), apt.path, 3*time.Second))
	}

	f := newFixture(t)
	f.system = true
	must(t, os.Remove(f.sshdPath))
	apt.sleep(t, "1.8", "1.8")
	f.apt = apt.path
	s := f.spec()
	s.Install, s.InstallTimeoutS = true, 3
	line, code := f.up(t, s)
	eq(t, line, `{"error":"install_failed"}`)
	eq(t, code, 1)
	eq(t, f.sshd.take(), []string(nil))
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

	// ssh-up prints only once sshd has listened again after its SIGHUP
	writeFile(t, root.Path(sandbox.SecretsEnvFile), "HF_TOKEN=bnsec_bbbbbbbbbbbbbbbbbbbbbbbbbb\n")
	up()
	eq(t, log(), "start "+p+"\nhup "+p+"\n")
	eq(t, acceptsAt("127.0.0.1:"+p), true)
	again, err = sandbox.ReadPidFile(root, "sshd")
	must(t, err)
	eq(t, again, pid)

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

	err = d.Check(context.Background(), fakeSSHDPath, []byte(cfg+"HostKey "+
		root.Path(sandbox.HostKeyFile)+"\n"))
	eq(t, err != nil, true)

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

	// The last 1 KiB starts inside the prefix or at the body, which a cut first would let through
	body := strings.Repeat("c", 26)
	for cut := range len("bnsec_") + 1 {
		out := "X=bnsec_" + body + " " + strings.Repeat("p", 1024+cut-len(body)-len("bnsec_")-1)
		eq(t, len(out)-1024, len("X=")+cut)
		got := string(complaint([]byte(out)))
		if strings.Contains(got, "ccc") {
			t.Fatalf("a cut %d bytes into the prefix kept the body: %q", cut, got[:40])
		}
	}
}
