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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oynozan/bugnet-run/internal/gate"
	"github.com/oynozan/bugnet-run/internal/sandbox"
)

var gateKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))

// setupGate runs setup under a fresh root and stops the gate it leaves running at the end
func setupGate(t *testing.T) (sandbox.Root, string) {
	t.Helper()
	root, err := sandbox.NewRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
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
	t.Cleanup(func() { stopGate(t, root) })
	out := runRaw(t, "setup", "--spec", specPath, "--root", root.Dir())
	if got := strings.TrimSpace(string(out)); got !=
		`{"gate":"listening","ca":"skipped","init":"setsid"}` {
		t.Fatalf("setup printed %s", got)
	}
	return root, addr
}

func stopGate(t *testing.T, root sandbox.Root) {
	t.Helper()
	pid, err := sandbox.ReadPidFile(root, "gate")
	if err != nil {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	waitFor(t, 5*time.Second, func() bool { return gone(pid) })
}

func healthy(addr string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return gate.Healthy(ctx, addr, gateKey) == nil
}

func TestStartRespawnsDeadGate(t *testing.T) {
	t.Parallel()
	root, addr := setupGate(t)
	pid, err := sandbox.ReadPidFile(root, "gate")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool { return gone(pid) })
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

	root, addr := setupGate(t)
	eq(t, strings.TrimSpace(string(runRaw(t, "respawn", "--root", root.Dir()))),
		`{"started":[]}`)
	pid, err := sandbox.ReadPidFile(root, "gate")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool { return gone(pid) })
	eq(t, strings.TrimSpace(string(runRaw(t, "respawn", "--root", root.Dir()))),
		`{"started":["gate"]}`)
	waitFor(t, 5*time.Second, func() bool { return healthy(addr) })
}

func TestRespawnSkipsWhileSetupHoldsTheLock(t *testing.T) {
	t.Parallel()
	root, addr := setupGate(t)
	pid, err := sandbox.ReadPidFile(root, "gate")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool { return gone(pid) })

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
	root, err := sandbox.NewRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
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
	t.Cleanup(func() {
		if pid, err := sandbox.ReadPidFile(root, "forward"); err == nil {
			_ = syscall.Kill(pid, syscall.SIGTERM)
			waitFor(t, 5*time.Second, func() bool { return gone(pid) })
		}
	})
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
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool { return gone(pid) })
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
	root, err := sandbox.NewRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
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
	t.Cleanup(func() {
		if pid, err := sandbox.ReadPidFile(root, "sshd"); err == nil {
			_ = syscall.Kill(pid, syscall.SIGTERM)
			waitFor(t, 5*time.Second, func() bool { return gone(pid) })
		}
	})
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

	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool { return gone(pid) })
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

	if err := syscall.Kill(again, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool { return gone(again) })
	startJob(t, t.TempDir(), "after", nil, "--root", root.Dir(), "--", "true").collect(t, 0, 0).
		mustExit(t)
	if third := sshd(); third == again {
		t.Fatalf("the dead sshd's pid %d is still recorded", again)
	}
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
