package runner_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bugnet-sh/bugnet-run/internal/gate"
	"github.com/bugnet-sh/bugnet-run/internal/sandbox"
)

var gateKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))

// services stops a root's services at the end of a test, never a pid the test already ended
type services struct {
	root  sandbox.Root
	ended map[int]bool
}

// newRoot gives a test a root whose runner is binPath, stopping the named services at the end
func newRoot(t *testing.T, names ...string) *services {
	t.Helper()
	root, err := sandbox.NewRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	linkRunner(t, root, binPath)
	s := &services{root: root, ended: map[int]bool{}}
	t.Cleanup(func() {
		for _, name := range names {
			if pid, err := sandbox.ReadPidFile(root, name); err == nil && !s.ended[pid] {
				s.end(t, pid, syscall.SIGTERM)
			}
		}
	})
	return s
}

// end sends sig to a process the test started, remembers it and waits until it is gone
func (s *services) end(t *testing.T, pid int, sig syscall.Signal) {
	t.Helper()
	s.ended[pid] = true
	_ = syscall.Kill(pid, sig)
	waitFor(t, 5*time.Second, func() bool { return gone(pid) })
}

// linkRunner makes bin the root's runner, so no new copy pays macOS's check of a new binary
func linkRunner(t *testing.T, root sandbox.Root, bin string) {
	t.Helper()
	runner := root.Path(sandbox.RunnerPath)
	if err := os.MkdirAll(filepath.Dir(runner), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(bin, runner); err != nil {
		t.Fatal(err)
	}
}

// setupGate runs setup under a fresh root and stops the gate it leaves running at the end
func setupGate(t *testing.T) (*services, string) {
	t.Helper()
	s := newRoot(t, "gate")
	root := s.root
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	spec, err := json.Marshal(map[string]any{
		"v": 1, "gate_key": gateKey, "gate_listen": addr, "deny_ports": []int{29417, 22},
	})
	if err != nil {
		t.Fatal(err)
	}
	specPath := filepath.Join(t.TempDir(), "setup-spec.json")
	if err := os.WriteFile(specPath, spec, 0o600); err != nil {
		t.Fatal(err)
	}
	out := runRaw(t, "setup", "--spec", specPath, "--root", root.Dir())
	if got := strings.TrimSpace(string(out)); got !=
		`{"gate":"listening","ca":"skipped","init":"setsid"}` {
		t.Fatalf("setup printed %s", got)
	}
	return s, addr
}

func healthy(addr string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return gate.Healthy(ctx, addr, gateKey) == nil
}

func TestStartRespawnsDeadGate(t *testing.T) {
	t.Parallel()
	s, addr := setupGate(t)
	root := s.root
	pid, err := sandbox.ReadPidFile(root, "gate")
	if err != nil {
		t.Fatal(err)
	}
	s.end(t, pid, syscall.SIGKILL)
	if healthy(addr) {
		t.Fatal("the gate still answers after SIGKILL")
	}

	startJob(t, t.TempDir(), "after", nil, "--root", root.Dir(), "--", "true").collect(t, 0, 0).
		mustExit(t)
	waitFor(t, 5*time.Second, func() bool { return healthy(addr) })
	again, err := sandbox.ReadPidFile(root, "gate")
	if err != nil || again == pid || gone(again) {
		t.Fatalf("pid file holds %d, %v after respawn, the dead gate was %d", again, err, pid)
	}

	startJob(t, t.TempDir(), "again", nil, "--root", root.Dir(), "--", "true").collect(t, 0, 0).
		mustExit(t)
	if now, _ := sandbox.ReadPidFile(root, "gate"); now != again {
		t.Errorf("a live gate was replaced, pid %d became %d", again, now)
	}
}

func TestRespawnCommand(t *testing.T) {
	t.Parallel()
	empty := t.TempDir()
	eq(t, strings.TrimSpace(string(runRaw(t, "respawn", "--root", empty))), `{"started":[]}`)

	s, addr := setupGate(t)
	root := s.root
	eq(t, strings.TrimSpace(string(runRaw(t, "respawn", "--root", root.Dir()))),
		`{"started":[]}`)
	pid, err := sandbox.ReadPidFile(root, "gate")
	if err != nil {
		t.Fatal(err)
	}
	s.end(t, pid, syscall.SIGKILL)
	eq(t, strings.TrimSpace(string(runRaw(t, "respawn", "--root", root.Dir()))),
		`{"started":["gate"]}`)
	waitFor(t, 5*time.Second, func() bool { return healthy(addr) })
}

// deadGate gives a test a root setup ran whose gate it then killed
func deadGate(t *testing.T) (*services, string) {
	t.Helper()
	s, addr := setupGate(t)
	pid, err := sandbox.ReadPidFile(s.root, "gate")
	if err != nil {
		t.Fatal(err)
	}
	s.end(t, pid, syscall.SIGKILL)
	return s, addr
}

func TestRespawnCopiesAMissingRunnerBeforeTheGate(t *testing.T) {
	t.Parallel()
	s, addr := deadGate(t)
	root := s.root
	runner := root.Path(sandbox.RunnerPath)
	if err := os.Remove(runner); err != nil {
		t.Fatal(err)
	}

	eq(t, strings.TrimSpace(string(runRaw(t, "respawn", "--root", root.Dir()))),
		`{"started":["gate"]}`)
	info, err := os.Stat(runner)
	if err != nil {
		t.Fatalf("respawn started the gate without copying the runner: %v", err)
	}
	built, err := os.Stat(binPath)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, info.Mode().Perm(), os.FileMode(0o755))
	eq(t, os.SameFile(info, built), false)
	eq(t, bytes.Equal(readFile(t, runner), readFile(t, binPath)), true)
	// macOS checks a new copy before its first run, which can take seconds
	waitFor(t, 30*time.Second, func() bool { return healthy(addr) })
	pid, err := sandbox.ReadPidFile(root, "gate")
	if err != nil {
		t.Fatal(err)
	}
	eq(t, strings.HasPrefix(command(t, pid), runner+" gate --config "), true)
}

func TestRespawnWhoseCopyFailsStartsTheCopyInPlace(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root reads a file whatever its mode, so the copy never fails")
	}
	s, addr := deadGate(t)
	root := s.root
	// A runner that may run but not be read is one the copy cannot open
	exe := filepath.Join(t.TempDir(), "bugnet-run")
	if err := os.WriteFile(exe, readFile(t, binPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(exe, 0o111); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(exe, "respawn", "--root", root.Dir())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	eq(t, exitCode(err), 1)
	eq(t, strings.TrimSpace(string(out)), `{"started":["gate"],"error":"respawn_failed"}`)
	eq(t, strings.Contains(stderr.String(), "install the runner: "), true)
	waitFor(t, 5*time.Second, func() bool { return healthy(addr) })
	runner := root.Path(sandbox.RunnerPath)
	info, err := os.Stat(runner)
	if err != nil {
		t.Fatal(err)
	}
	built, err := os.Stat(binPath)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, os.SameFile(info, built), true)
	pid, err := sandbox.ReadPidFile(root, "gate")
	if err != nil {
		t.Fatal(err)
	}
	eq(t, strings.HasPrefix(command(t, pid), runner+" gate --config "), true)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// command is the command line ps shows for pid
func command(t *testing.T, pid int) string {
	t.Helper()
	out, err := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestRespawnSkipsWhileSetupHoldsTheLock(t *testing.T) {
	t.Parallel()
	s, addr := setupGate(t)
	root := s.root
	pid, err := sandbox.ReadPidFile(root, "gate")
	if err != nil {
		t.Fatal(err)
	}
	s.end(t, pid, syscall.SIGKILL)

	unlock, err := sandbox.Lock(root)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, strings.TrimSpace(string(runRaw(t, "respawn", "--root", root.Dir()))),
		`{"started":[]}`)
	eq(t, healthy(addr), false)
	unlock()
	eq(t, strings.TrimSpace(string(runRaw(t, "respawn", "--root", root.Dir()))),
		`{"started":["gate"]}`)
	waitFor(t, 5*time.Second, func() bool { return healthy(addr) })
}

func TestRespawnFailureNeverFailsTheJob(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "etc", "bugnet", "gate.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := startJob(t, t.TempDir(), "broken", nil, "--root", root, "--", "echo", "ran").
		collect(t, 0, 0)
	if x := res.mustExit(t); x.Code != 0 || string(res.stdout) != "ran\n" {
		t.Fatalf("exit %+v stdout %q, want 0 and %q", x, res.stdout, "ran\n")
	}
}

func TestGateAndSetupBadArgs(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"gate", "--nope"}, {"gate", "extra"}} {
		cmd := exec.Command(binPath, args...)
		if err := cmd.Run(); cmd.ProcessState.ExitCode() != 2 {
			t.Errorf("bugnet-run %v: %v, want exit 2", args, err)
		}
	}
	out, err := exec.Command(binPath, "setup").Output()
	if code := exitCode(err); code != 1 || strings.TrimSpace(string(out)) !=
		`{"error":"bad_spec"}` {
		t.Errorf("setup without --spec printed %q and exited %d", out, code)
	}
}

func TestRespawnBringsBackTheForwarder(t *testing.T) {
	t.Parallel()
	s := newRoot(t, "forward")
	root := s.root
	var err error
	token := "bnt_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))
	cfg := `{"endpoint":"egress.example","ips":["127.0.0.1"],"port":443,` +
		`"listen":"127.0.0.1:0","token_file":"/etc/bugnet/egress.token","hosts":[],` +
		`"roots_file":""}`
	for path, content := range map[string]string{
		sandbox.EgressConfig: cfg, sandbox.EgressToken: token + "\n",
	} {
		if err := os.MkdirAll(filepath.Dir(root.Path(path)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(root.Path(path), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	forwarder := func() int {
		var pid int
		waitFor(t, 5*time.Second, func() bool {
			pid, err = sandbox.ReadPidFile(root, "forward")
			return err == nil && !gone(pid)
		})
		return pid
	}

	eq(t, strings.TrimSpace(string(runRaw(t, "respawn", "--root", root.Dir()))),
		`{"started":["forward"]}`)
	pid := forwarder()
	s.end(t, pid, syscall.SIGKILL)
	startJob(t, t.TempDir(), "after", nil, "--root", root.Dir(), "--", "true").collect(t, 0, 0).
		mustExit(t)
	if again := forwarder(); again == pid {
		t.Fatalf("the dead forwarder's pid %d is still recorded", pid)
	}
}

func TestEgressAndForwardBadArgs(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"forward", "--nope"}, {"forward", "extra"}} {
		cmd := exec.Command(binPath, args...)
		if err := cmd.Run(); cmd.ProcessState.ExitCode() != 2 {
			t.Errorf("bugnet-run %v: %v, want exit 2", args, err)
		}
	}
	out, err := exec.Command(binPath, "egress", "apply").Output()
	if code := exitCode(err); code != 1 || strings.TrimSpace(string(out)) !=
		`{"error":"bad_spec"}` {
		t.Errorf("egress apply without --spec printed %q and exited %d", out, code)
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if x, ok := err.(*exec.ExitError); ok {
		return x.ExitCode()
	}
	panic(fmt.Sprint(err))
}

// buildFakeSSHD builds the sshd stand-in, named so its command line holds sshd
func buildFakeSSHD(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fake-sshd")
	build := exec.Command("go", "build", "-o", bin, "../sshup/testdata/fakesshd")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fakesshd: %v\n%s", err, out)
	}
	return bin
}

func TestRespawnBringsBackSshdAfterRunWiped(t *testing.T) {
	t.Parallel()
	fake := buildFakeSSHD(t)
	s := newRoot(t, "sshd")
	root := s.root
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	spec := fmt.Sprintf(`{"v":1,"user":"boxd","ports":[%d],"sshd_path":%q,"authorize":[]}`,
		port, fake)
	specPath := filepath.Join(t.TempDir(), "ssh-spec.json")
	if err := os.WriteFile(specPath, []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	var res struct {
		Port    int    `json:"port"`
		HostKey string `json:"host_key"`
	}
	if err := json.Unmarshal(runRaw(t, "ssh-up", "--spec", specPath, "--root", root.Dir()),
		&res); err != nil {
		t.Fatal(err)
	}
	eq(t, res.Port, port)
	eq(t, strings.HasPrefix(res.HostKey, "ssh-ed25519 "), true)
	sshd := func() int {
		var pid int
		waitFor(t, 5*time.Second, func() bool {
			pid, err = sandbox.ReadPidFile(root, "sshd")
			return err == nil && !gone(pid) && dials(addr)
		})
		return pid
	}
	pid := sshd()

	s.end(t, pid, syscall.SIGKILL)
	if err := os.RemoveAll(root.Path("/run")); err != nil {
		t.Fatal(err)
	}
	eq(t, strings.TrimSpace(string(runRaw(t, "respawn", "--root", root.Dir()))),
		`{"started":["sshd"]}`)
	again := sshd()
	eq(t, again != pid, true)
	if _, err := os.Stat(root.Path(sandbox.SSHDRunDir)); err != nil {
		t.Fatalf("respawn left sshd without its run directory: %v", err)
	}

	s.end(t, again, syscall.SIGKILL)
	startJob(t, t.TempDir(), "after", nil, "--root", root.Dir(), "--", "true").collect(t, 0, 0).
		mustExit(t)
	if third := sshd(); third == again {
		t.Fatalf("the dead sshd's pid %d is still recorded", again)
	}
}

// An apply that HUPs sshd lets go of the sandbox only once sshd wrote its pid file again
func TestApplyThenSshUpLeavesOneSshd(t *testing.T) {
	t.Parallel()
	fake := buildFakeSSHD(t)
	s := newRoot(t, "sshd", "forward")
	root := s.root
	env := root.Path(sandbox.EnvFile)
	if err := os.MkdirAll(filepath.Dir(env), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env, []byte("SSL_CERT_FILE=/etc/ssl/ca.crt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	p := strconv.Itoa(port)
	sshUp := func() {
		t.Helper()
		spec := fmt.Sprintf(`{"v":1,"user":"boxd","ports":[%d],"sshd_path":%q,"authorize":[]}`,
			port, fake)
		path := filepath.Join(t.TempDir(), "ssh-spec.json")
		if err := os.WriteFile(path, []byte(spec), 0o600); err != nil {
			t.Fatal(err)
		}
		out := runRaw(t, "ssh-up", "--spec", path, "--root", root.Dir())
		eq(t, strings.HasPrefix(string(out), `{"port":`+p+`,`), true)
	}
	log := func() string {
		b, _ := os.ReadFile(filepath.Join(root.Path(sandbox.SSHDir), "fake-sshd.log"))
		return string(b)
	}
	sshUp()
	pid, err := sandbox.ReadPidFile(root, "sshd")
	if err != nil {
		t.Fatal(err)
	}
	eq(t, log(), "start "+p+"\n")

	token := "bnt_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))
	apply := `{"v":1,"token":"` + token + `","endpoint":"egress.example","ips":["127.0.0.1"],` +
		`"port":9,"listen":"127.0.0.1:0","hosts":["huggingface.co"],"env":[{"name":"HF_TOKEN",` +
		`"value":"bnsec_` + strings.Repeat("a", 26) + `"}],"home":""}`
	path := filepath.Join(t.TempDir(), "egress-spec.json")
	if err := os.WriteFile(path, []byte(apply), 0o600); err != nil {
		t.Fatal(err)
	}
	eq(t, strings.TrimSpace(string(runRaw(t, "egress", "apply", "--spec", path, "--root",
		root.Dir()))), `{"forward":"listening","hosts":1,"secrets":1}`)
	sshUp()

	// A reload ssh-up wrongly found owed would show within the fake's delay
	time.Sleep(600 * time.Millisecond)
	eq(t, log(), "start "+p+"\nhup "+p+"\n")
	again, err := sandbox.ReadPidFile(root, "sshd")
	eq(t, err, nil)
	eq(t, again, pid)
	sameAs(t, sshdsOf(t, root), []int{pid})
	b, err := os.ReadFile(root.Path(sandbox.SSHPortFile))
	eq(t, err, nil)
	eq(t, strings.TrimSpace(string(b)), p)
	eq(t, dials(net.JoinHostPort("127.0.0.1", p)), true)
}

// sshdsOf lists the processes whose command line names root's sshd_config
func sshdsOf(t *testing.T, root sandbox.Root) []int {
	t.Helper()
	out, err := exec.Command("ps", "-A", "-o", "pid=", "-o", "command=").Output()
	if err != nil {
		t.Fatal(err)
	}
	mark := " -f " + root.Path(sandbox.SSHDConfig)
	var pids []int
	for line := range strings.Lines(string(out)) {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasSuffix(strings.TrimSpace(line), mark) {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			t.Fatal(err)
		}
		pids = append(pids, pid)
	}
	return pids
}

func dials(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func TestSshUpBadArgs(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"ssh-up"}, {"ssh-up", "--nope"}, {"ssh-up", "extra"}} {
		out, err := exec.Command(binPath, args...).Output()
		if code := exitCode(err); code != 1 || strings.TrimSpace(string(out)) !=
			`{"error":"bad_spec"}` {
			t.Errorf("bugnet-run %v printed %q and exited %d", args, out, code)
		}
	}
}

func TestTransferHelpersAreSubcommands(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("hello"), 0o640); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Path    string `json:"path"`
		Size    int64  `json:"size"`
		Mode    uint32 `json:"mode"`
		Regular bool   `json:"regular"`
	}
	if err := json.Unmarshal(runRaw(t, "stat", "--path", file), &got); err != nil {
		t.Fatal(err)
	}
	eq(t, got.Path, file)
	eq(t, got.Size, int64(5))
	eq(t, got.Mode, uint32(0o640))
	eq(t, got.Regular, true)

	for _, args := range [][]string{{"stat"}, {"stage-out"}, {"place"}} {
		out, err := exec.Command(binPath, args...).Output()
		if code := exitCode(err); code != 2 || strings.TrimSpace(string(out)) !=
			`{"error":"bad_args"}` {
			t.Errorf("bugnet-run %v printed %q and exited %d", args, out, code)
		}
	}
}

// fakeNft puts an nft on PATH that records its arguments and lists tables without bugnet's
func fakeNft(t *testing.T) (string, func() []string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\necho \"$*\" >> \"$0.calls\"\n" +
		"if [ \"$1\" = list ]; then echo 'table ip filter'; fi\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	calls := func() []string {
		b, err := os.ReadFile(filepath.Join(dir, "nft.calls"))
		if err != nil {
			return nil
		}
		return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	}
	return "PATH=" + dir + ":" + os.Getenv("PATH"), calls
}

func keptRuleset(t *testing.T) sandbox.Root {
	t.Helper()
	root, err := sandbox.NewRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := root.Path("/etc/bugnet/firewall.rules")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	rules := "# bugnet-run harden nft\ntable inet bugnet\ndelete table inet bugnet\n"
	if err := os.WriteFile(path, []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestStartReloadsAMissingFirewallOnceAMinute(t *testing.T) {
	t.Parallel()
	root := keptRuleset(t)
	path, calls := fakeNft(t)
	env := []string{path}
	startJob(t, t.TempDir(), "first", env, "--root", root.Dir(), "--", "true").collect(t, 0, 0).
		mustExit(t)
	sameAs(t, calls(), []string{"list tables", "-f " + root.Path("/etc/bugnet/firewall.rules")})

	startJob(t, t.TempDir(), "second", env, "--root", root.Dir(), "--", "true").collect(t, 0, 0).
		mustExit(t)
	sameAs(t, len(calls()), 2)

	// A check a minute old is due again
	old := time.Now().Add(-61 * time.Second)
	if err := os.Chtimes(root.Path("/run/bugnet/firewall.checked"), old, old); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binPath, "respawn", "--root", root.Dir())
	cmd.Env = append(os.Environ(), path)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, strings.TrimSpace(string(out)), `{"started":["firewall"]}`)
	sameAs(t, len(calls()), 4)
}

func TestRespawnWithoutRulesNeverRunsNft(t *testing.T) {
	t.Parallel()
	s, _ := setupGate(t)
	path, calls := fakeNft(t)
	startJob(t, t.TempDir(), "job", []string{path}, "--root", s.root.Dir(), "--", "true").
		collect(t, 0, 0).mustExit(t)
	sameAs(t, calls(), []string(nil))
}

func sameAs[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestRespawnStartsDeadSampler(t *testing.T) {
	t.Parallel()
	s := newRoot(t, "sample")
	root := s.root
	var err error
	config := root.Path(sandbox.SampleConfig)
	if err := os.MkdirAll(filepath.Dir(config), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte(`{"v":1}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The sampler writes into the job directory's parent, which it never makes itself
	if err := os.MkdirAll(root.Path("/tmp/bugnet"), 0o755); err != nil {
		t.Fatal(err)
	}
	sampler := func() int {
		var pid int
		waitFor(t, 5*time.Second, func() bool {
			pid, err = sandbox.ReadPidFile(root, "sample")
			return err == nil && !gone(pid)
		})
		return pid
	}

	eq(t, strings.TrimSpace(string(runRaw(t, "respawn", "--root", root.Dir()))),
		`{"started":["sample"]}`)
	pid := sampler()
	waitFor(t, 5*time.Second, func() bool { return exists(root.Path("/tmp/bugnet/stats.json")) })
	eq(t, strings.TrimSpace(string(runRaw(t, "respawn", "--root", root.Dir()))),
		`{"started":[]}`)

	s.end(t, pid, syscall.SIGKILL)
	startJob(t, t.TempDir(), "after", nil, "--root", root.Dir(), "--", "true").collect(t, 0, 0).
		mustExit(t)
	if again := sampler(); again == pid {
		t.Fatalf("the dead sampler's pid %d is still recorded", pid)
	}
}
