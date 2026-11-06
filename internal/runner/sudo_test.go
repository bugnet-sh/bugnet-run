package runner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oynozan/bugnet-run/frame"
	"github.com/oynozan/bugnet-run/internal/gate"
	"github.com/oynozan/bugnet-run/internal/sandbox"
)

// The test binary acts as bugnet-run that is not root when sudoEnv names a stand-in for sudo
const (
	sudoEnv    = "BUGNET_RUN_TEST_SUDO"
	timeoutEnv = "BUGNET_RUN_TEST_RESPAWN_TIMEOUT"
)

func init() {
	program := os.Getenv(sudoEnv)
	if program == "" {
		return
	}
	sudoProgram = program
	privileged = func(sandbox.Root) bool { return false }
	if d, err := time.ParseDuration(os.Getenv(timeoutEnv)); err == nil {
		respawnTimeout = d
	}
	os.Exit(Run(os.Args[1:], os.Stdout, os.Stderr))
}

var sudoGateKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))

func TestSudoArgs(t *testing.T) {
	t.Parallel()
	same(t, sudoArgs("/tmp/bugnet/bin/bugnet-run", sandbox.System),
		[]string{"-n", "/tmp/bugnet/bin/bugnet-run", "respawn"})
	root, err := sandbox.NewRoot("/s/fs")
	if err != nil {
		t.Fatal(err)
	}
	same(t, sudoArgs("/x/bugnet-run", root),
		[]string{"-n", "/x/bugnet-run", "respawn", "--root", "/s/fs"})
}

func TestPrivilegedOnlyAsRootOrUnderAnotherRoot(t *testing.T) {
	t.Parallel()
	root, err := sandbox.NewRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	same(t, privileged(root), true)
	same(t, privileged(sandbox.System), os.Geteuid() == 0)
}

// sudoSandbox is a sandbox root with a gate that a start which is not root must respawn
type sudoSandbox struct {
	exe    string
	root   sandbox.Root
	addr   string
	jobs   string
	killed map[int]bool
}

func newSudoSandbox(t *testing.T) *sudoSandbox {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root, err := sandbox.NewRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &sudoSandbox{
		exe: exe, root: root, addr: ln.Addr().String(), jobs: t.TempDir(), killed: map[int]bool{},
	}
	_ = ln.Close()
	spec, err := json.Marshal(map[string]any{
		"v": 1, "gate_key": sudoGateKey, "gate_listen": s.addr, "deny_ports": []int{22},
	})
	if err != nil {
		t.Fatal(err)
	}
	specPath := filepath.Join(t.TempDir(), "setup-spec.json")
	if err := os.WriteFile(specPath, spec, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.stopGate(t) })
	out, _ := s.run(t, s.sudo(t, "setup-sudo", ""), "", "setup", "--spec", specPath, "--root",
		root.Dir())
	if got := strings.TrimSpace(string(out)); got !=
		`{"gate":"listening","ca":"skipped","init":"setsid"}` {
		t.Fatalf("setup printed %s", got)
	}
	return s
}

// sudo writes a stand-in for sudo that records its arguments, prints noise and then runs tail
func (s *sudoSandbox) sudo(t *testing.T, name, tail string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.args\"\necho sudo-noise\n" +
		"echo sudo-noise >&2\n" + tail
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// run runs the test binary as bugnet-run that is not root, the script at sudo standing in for sudo
func (s *sudoSandbox) run(t *testing.T, sudo, timeout string, args ...string) ([]byte, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.exe, args...)
	cmd.Env = append(os.Environ(), sudoEnv+"="+sudo, timeoutEnv+"="+timeout)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("bugnet-run %v: %v, stderr %q", args, err, errOut.String())
	}
	return out.Bytes(), errOut.Bytes()
}

// start runs echo as a job and checks that its frames hold only the job's own output
func (s *sudoSandbox) start(t *testing.T, sudo, timeout, id string) {
	t.Helper()
	out, _ := s.run(t, sudo, timeout, "start", "--job", id, "--dir", s.jobs, "--root",
		s.root.Dir(), "--", "echo", "ran")
	if bytes.Contains(out, []byte("sudo-noise")) {
		t.Fatalf("sudo's output reached start's stdout %q", out)
	}
	var stdout []byte
	var exit *frame.Frame
	dec := frame.NewDecoder(bytes.NewReader(out))
	for {
		f, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("start's stdout %q: %v", out, err)
		}
		switch f.Kind {
		case frame.KindStdout:
			stdout = append(stdout, f.Data...)
		case frame.KindExit:
			exit = &f
		case frame.KindHeartbeat:
		default:
			t.Fatalf("frame %+v in start's stdout %q", f, out)
		}
	}
	if exit == nil || exit.Code != 0 || string(stdout) != "ran\n" {
		t.Fatalf("job %s gave stdout %q and exit %+v, want %q and code 0", id, stdout, exit,
			"ran\n")
	}
}

func (s *sudoSandbox) killGate(t *testing.T) int {
	t.Helper()
	pid, err := sandbox.ReadPidFile(s.root, "gate")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	s.killed[pid] = true
	waitUntil(t, 5*time.Second, func() bool { return gone(pid) })
	return pid
}

// stopGate ends the gate this sandbox's setup or respawn started, never a pid it already killed
func (s *sudoSandbox) stopGate(t *testing.T) {
	t.Helper()
	pid, err := sandbox.ReadPidFile(s.root, "gate")
	if err != nil || s.killed[pid] {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	waitUntil(t, 5*time.Second, func() bool { return gone(pid) })
}

func (s *sudoSandbox) healthy() bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return gate.Healthy(ctx, s.addr, sudoGateKey) == nil
}

func recorded(t *testing.T, sudo string) []string {
	t.Helper()
	b, err := os.ReadFile(sudo + ".args")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func TestStartRespawnsThroughSudo(t *testing.T) {
	t.Parallel()
	s := newSudoSandbox(t)
	want := []string{"-n", s.exe, "respawn", "--root", s.root.Dir()}

	sudo := s.sudo(t, "sudo", "shift\nexec \"$@\"\n")
	s.start(t, sudo, "", "healthy")
	same(t, recorded(t, sudo), []string(nil))

	dead := s.killGate(t)
	s.start(t, sudo, "", "respawned")
	same(t, recorded(t, sudo), want)
	waitUntil(t, 5*time.Second, s.healthy)
	if pid, err := sandbox.ReadPidFile(s.root, "gate"); err != nil || pid == dead {
		t.Fatalf("pid file holds %d, %v after respawn, the dead gate was %d", pid, err, dead)
	}
}

func TestSudoFailureNeverFailsTheJob(t *testing.T) {
	t.Parallel()
	s := newSudoSandbox(t)
	s.killGate(t)
	want := []string{"-n", s.exe, "respawn", "--root", s.root.Dir()}

	failing := s.sudo(t, "sudo", "exit 1\n")
	s.start(t, failing, "", "failing")
	same(t, recorded(t, failing), want)
	same(t, s.healthy(), false)

	hanging := s.sudo(t, "sudo", "exec sleep 30\n")
	began := time.Now()
	s.start(t, hanging, "5s", "hanging")
	if took := time.Since(began); took > 20*time.Second {
		t.Fatalf("start took %v behind a sudo that hangs, want the respawn timeout to end it", took)
	}
	same(t, recorded(t, hanging), want)
}

func gone(pid int) bool {
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}

func same[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %v", timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
