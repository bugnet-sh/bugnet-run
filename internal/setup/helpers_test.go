package setup

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/oynozan/bugnet-run/internal/gate"
	"github.com/oynozan/bugnet-run/internal/sandbox"
)

var (
	testKey  = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	otherKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	binPath  string
)

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	dir, err := os.MkdirTemp("", "bugnet-run-setup-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()
	binPath = filepath.Join(dir, "bugnet-run")
	build := exec.Command("go", "build", "-o", binPath,
		"github.com/oynozan/bugnet-run/cmd/bugnet-run")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build bugnet-run: %v\n%s", err, out)
		return 1
	}
	// One run pays macOS's check of a new binary, which can take seconds, before a test times it
	_ = exec.Command(binPath).Run()
	executable = func() (string, error) { return binPath, nil }
	healthWait = 3 * time.Second
	return m.Run()
}

func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	must(t, err)
	return string(b)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Dir(path), 0o755))
	must(t, os.WriteFile(path, []byte(content), 0o644))
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

type fixture struct {
	root sandbox.Root
	port int
	dir  string
	// ended holds the pids this test ended, which its cleanup never signals again
	ended map[int]bool
}

// newFixture gives a test a root whose runner is binPath itself, so no copy pays macOS's check
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := freshFixture(t)
	dst := f.root.Path(sandbox.RunnerPath)
	must(t, os.MkdirAll(filepath.Dir(dst), 0o755))
	must(t, os.Link(binPath, dst))
	return f
}

// freshFixture gives a test its own sandbox root and gate port, stopping its gates at the end
func freshFixture(t *testing.T) *fixture {
	t.Helper()
	root, err := sandbox.NewRoot(t.TempDir())
	must(t, err)
	f := &fixture{root: root, port: freePort(t), dir: t.TempDir(), ended: map[int]bool{}}
	t.Cleanup(func() { f.stopGate(t) })
	return f
}

// slowStart gives the gate long enough to start from a new copy, which macOS checks first
func slowStart(t *testing.T) {
	t.Helper()
	before := healthWait
	healthWait = 30 * time.Second
	t.Cleanup(func() { healthWait = before })
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

func (f *fixture) spec() Spec {
	return Spec{
		V: 1, GateKey: testKey, GateListen: fmt.Sprintf("127.0.0.1:%d", f.port),
		DenyPorts: []int{29417, 22, 2022, 49983}, PreviewDomain: "preview.example",
	}
}

func (f *fixture) specFile(t *testing.T, s any) string {
	t.Helper()
	b, ok := s.(json.RawMessage)
	if !ok {
		var err error
		b, err = json.Marshal(s)
		must(t, err)
	}
	path := filepath.Join(f.dir, "setup-spec.json")
	must(t, os.WriteFile(path, b, 0o600))
	return path
}

// run runs setup on spec, which may be raw JSON, and returns the line it printed and its status
func (f *fixture) run(t *testing.T, spec any, extra ...string) (string, int) {
	t.Helper()
	var args []string
	if spec != nil {
		path := f.specFile(t, spec)
		args = append(args, "--spec", path)
		t.Cleanup(func() { _ = os.Remove(path) })
	}
	args = append(append(args, "--root", f.root.Dir()), extra...)
	var out, errOut bytes.Buffer
	code := Run(args, &out, &errOut)
	if strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("setup printed %q, want one line, stderr %q", out.String(), errOut.String())
	}
	if spec != nil && exists(filepath.Join(f.dir, "setup-spec.json")) {
		t.Fatal("setup left its spec file behind")
	}
	return strings.TrimSpace(out.String()), code
}

// command is the command line ps shows for pid
func command(t *testing.T, pid int) string {
	t.Helper()
	out, err := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(pid)).Output()
	must(t, err)
	return strings.TrimSpace(string(out))
}

func (f *fixture) gatePid(t *testing.T) int {
	t.Helper()
	pid, err := sandbox.ReadPidFile(f.root, "gate")
	must(t, err)
	return pid
}

func (f *fixture) healthy(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return gate.Healthy(ctx, fmt.Sprintf("127.0.0.1:%d", f.port), key)
}

// stopGate ends the gate and the sampler this fixture's setup started, never a pid it ended
func (f *fixture) stopGate(t *testing.T) {
	t.Helper()
	for _, name := range []string{"gate", "sample"} {
		pid, err := sandbox.ReadPidFile(f.root, name)
		if err != nil || f.ended[pid] || !alive(pid) {
			continue
		}
		f.kill(t, pid, syscall.SIGTERM)
	}
}

// kill sends sig to a process this test started, remembers it and waits until it is gone
func (f *fixture) kill(t *testing.T, pid int, sig syscall.Signal) {
	t.Helper()
	f.ended[pid] = true
	_ = syscall.Kill(pid, sig)
	waitGone(t, pid)
}

func waitGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		if time.Now().After(deadline) {
			t.Fatalf("pid %d still runs", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func alive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// testCA returns a self-signed CA certificate in PEM
func testCA(t *testing.T, name string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

type caTool struct {
	mu    sync.Mutex
	calls int
}

// fakeUpdateCA stands in for update-ca-certificates, rebuilding the bundle from the local files
func fakeUpdateCA(t *testing.T) *caTool {
	t.Helper()
	tool := &caTool{}
	updateCA = func(_ context.Context, r sandbox.Root) error {
		tool.mu.Lock()
		tool.calls++
		tool.mu.Unlock()
		bundle := "# system roots\n"
		files, err := filepath.Glob(r.Path(sandbox.CADir + "/*.crt"))
		if err != nil {
			return err
		}
		for _, file := range files {
			b, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			bundle += string(b)
		}
		_, err = sandbox.WriteFile(r.Path(sandbox.CABundle), []byte(bundle), 0o644)
		return err
	}
	t.Cleanup(func() { updateCA = runUpdateCA })
	return tool
}

func (c *caTool) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

type fakeSystemd struct {
	t     *testing.T
	fix   *fixture
	mu    sync.Mutex
	calls []string
}

// fakeSystemctl runs a unit's ExecStart in its own session, as systemd would for start
func fakeSystemctl(t *testing.T, fix *fixture) *fakeSystemd {
	t.Helper()
	f := &fakeSystemd{t: t, fix: fix}
	systemctl = f.run
	t.Cleanup(func() { systemctl = nil })
	return f
}

func (f *fakeSystemd) run(_ context.Context, args ...string) error {
	f.mu.Lock()
	f.calls = append(f.calls, strings.Join(args, " "))
	f.mu.Unlock()
	if !exists(f.fix.root.Path(sandbox.RunnerPath)) {
		f.t.Errorf("systemctl %s ran before the runner was copied", strings.Join(args, " "))
	}
	if len(args) != 2 || args[0] != "start" && args[0] != "restart" {
		return nil
	}
	name := strings.TrimSuffix(strings.TrimPrefix(args[1], "bugnet-"), ".service")
	if pid, err := sandbox.ReadPidFile(f.fix.root, name); err == nil && !f.fix.ended[pid] &&
		alive(pid) {
		if args[0] == "start" {
			return nil
		}
		f.fix.kill(f.t, pid, syscall.SIGTERM)
	}
	unit, err := os.Open(f.fix.root.Path(sandbox.UnitDir + "/" + args[1]))
	if err != nil {
		return err
	}
	defer func() { _ = unit.Close() }()
	sc := bufio.NewScanner(unit)
	for sc.Scan() {
		if line, ok := strings.CutPrefix(sc.Text(), "ExecStart="); ok {
			argv := strings.Fields(line)
			cmd := exec.Command(argv[0], argv[1:]...)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if err := cmd.Start(); err != nil {
				return err
			}
			go func() { _ = cmd.Wait() }()
			return nil
		}
	}
	return errors.New("unit has no ExecStart")
}

func (f *fakeSystemd) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	calls := f.calls
	f.calls = nil
	return calls
}

// snapshot reads every file setup writes, with its mode
func snapshot(t *testing.T, r sandbox.Root) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, dir := range []string{sandbox.EtcDir, "/etc/profile.d", sandbox.CADir, "/etc/ssl/certs",
		sandbox.UnitDir} {
		entries, err := os.ReadDir(r.Path(dir))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		must(t, err)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := r.Path(dir + "/" + e.Name())
			info, err := os.Stat(path)
			must(t, err)
			out[dir+"/"+e.Name()] = info.Mode().Perm().String() + " " + readFile(t, path)
		}
	}
	return out
}
