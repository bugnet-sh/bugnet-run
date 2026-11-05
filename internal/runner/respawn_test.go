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

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if x, ok := err.(*exec.ExitError); ok {
		return x.ExitCode()
	}
	panic(fmt.Sprint(err))
}
