package sshup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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

	"github.com/oynozan/bugnet-run/internal/sandbox"
)

// gwLine is the gateway's authorized_keys line as the router writes it
const gwLine = `restrict,pty,port-forwarding,permitopen="127.0.0.1:*",permitopen="[::1]:*" ` +
	"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl bn-gw"

// fakeSSHDPath is the fakesshd binary TestMain builds, named so its command line holds sshd
var fakeSSHDPath string

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	dir, err := os.MkdirTemp("", "bugnet-run-sshup-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()
	fakeSSHDPath = filepath.Join(dir, "fake-sshd")
	build := exec.Command("go", "build", "-o", fakeSSHDPath, "./testdata/fakesshd")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build fakesshd: %v\n%s", err, out)
		return 1
	}
	// One run pays macOS's check of a new binary, which can take seconds, before a test times it
	_ = exec.Command(fakeSSHDPath, "-t").Run()
	code := m.Run()
	for _, cleanup := range cleanups {
		cleanup()
	}
	return code
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

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Dir(path), 0o755))
	must(t, os.WriteFile(path, []byte(content), 0o644))
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func mode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	must(t, err)
	return info.Mode().Perm()
}

func hasLine(text, line string) bool {
	for l := range strings.Lines(text) {
		if strings.TrimSuffix(l, "\n") == line {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

/* The sshd seam */

// fakeDaemon stands in for our supervised sshd and records what ssh-up asked of it
type fakeDaemon struct {
	mu sync.Mutex
	// keyFile is the host key the fake reads on a start or SIGHUP, as sshd does
	keyFile string
	running bool
	calls   []string
	checked []string
	// checkedKeys holds the public line of the key each checked config named, read at the check
	checkedKeys []string
	serving     string
	// loaded is when the fake last read its files, as the time of sshd's pid file
	loaded   time.Time
	refuse   bool
	failWait bool
	// killed makes a SIGHUP or restart do nothing, as when ssh-up is killed just before it
	killed bool
}

func (d *fakeDaemon) Running() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running
}

func (d *fakeDaemon) Check(_ context.Context, path string, config []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, "check "+path)
	d.checked = append(d.checked, string(config))
	d.checkedKeys = append(d.checkedKeys, keyLine(configHostKey(string(config))))
	if d.refuse {
		return errors.New("sshd -t refused the config")
	}
	return nil
}

func (d *fakeDaemon) Start(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, "start")
	d.running = true
	d.serving, d.loaded = keyLine(d.keyFile), time.Now()
	return nil
}

func (d *fakeDaemon) Restart(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, "restart")
	if d.killed {
		return errors.New("killed before the restart")
	}
	d.running = true
	d.serving, d.loaded = keyLine(d.keyFile), time.Now()
	return nil
}

func (d *fakeDaemon) Reload() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, "hup")
	if d.killed {
		return errors.New("killed before the signal")
	}
	d.serving, d.loaded = keyLine(d.keyFile), time.Now()
	return nil
}

func (d *fakeDaemon) Loaded() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.loaded
}

// served returns the public line of the host key the fake loaded last
func (d *fakeDaemon) served() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.serving
}

// keyLine returns the public line of the key file at path, empty when it holds no key
func keyLine(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	line, _ := publicLine(b)
	return line
}

// configHostKey returns the path an sshd_config's HostKey line names
func configHostKey(config string) string {
	for l := range strings.Lines(config) {
		if path, ok := strings.CutPrefix(strings.TrimSuffix(l, "\n"), "HostKey "); ok {
			return path
		}
	}
	return ""
}

// dotFiles lists the names in /etc/bugnet/ssh that start with a dot
func dotFiles(t *testing.T, root sandbox.Root) []string {
	t.Helper()
	entries, err := os.ReadDir(root.Path(sandbox.SSHDir))
	must(t, err)
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	return names
}

func (d *fakeDaemon) Wait(_ context.Context, port int, _ time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, fmt.Sprintf("wait %d", port))
	if d.failWait {
		return errors.New("sshd did not listen")
	}
	return nil
}

// take returns the calls since the last take, leaving out checks
func (d *fakeDaemon) take() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for _, c := range d.calls {
		if !strings.HasPrefix(c, "check ") {
			out = append(out, c)
		}
	}
	d.calls = nil
	return out
}

/* Fixture */

type fixture struct {
	root     sandbox.Root
	dir      string
	sshdPath string
	sshd     *fakeDaemon
	held     map[int]bool
	system   bool
	mu       sync.Mutex
	installs []time.Duration
	// installErr fails the fake apt-get, which otherwise creates sshd
	installErr error
	usermods   []string
	systemctl  []string
	// wait, when set, runs the real supervised sshd with this listen wait instead of the fake
	wait time.Duration
	// apt, when set, runs the real install against this apt-get stand-in
	apt string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root, err := sandbox.NewRoot(t.TempDir())
	must(t, err)
	f := &fixture{
		root: root, dir: t.TempDir(), sshd: &fakeDaemon{keyFile: root.Path(sandbox.HostKeyFile)},
		held: map[int]bool{},
	}
	f.sshdPath = filepath.Join(f.dir, "sbin", "sshd")
	writeFile(t, f.sshdPath, "#!/bin/sh\n")
	must(t, os.Chmod(f.sshdPath, 0o755))
	writeFile(t, root.Path(sandbox.EnvFile),
		"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\n"+
			"__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS=.preview.example\n")
	writeFile(t, root.Path(sandbox.SecretsEnvFile), "HF_TOKEN=bnsec_aaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	return f
}

func (f *fixture) spec() Spec {
	return Spec{
		V: 1, User: "boxd", Ports: []int{22, 2022}, SSHDPath: f.sshdPath, Install: false,
		InstallTimeoutS: 120, Authorize: []string{gwLine},
	}
}

// holding marks ports as taken for the port probe
func (f *fixture) holding(ports ...int) *fixture {
	for _, p := range ports {
		f.held[p] = true
	}
	return f
}

func (f *fixture) tune(u *upper) {
	u.sup.Systemctl = func(_ context.Context, args ...string) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.systemctl = append(f.systemctl, strings.Join(args, " "))
		return nil
	}
	u.sshd = f.sshd
	if f.wait > 0 {
		u.sshd = supervised{sup: u.sup, wait: f.wait}
	}
	u.free = func(port int) bool { return !f.held[port] }
	u.system = f.system
	u.install = func(_ context.Context, timeout time.Duration) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.installs = append(f.installs, timeout)
		if f.installErr != nil {
			return f.installErr
		}
		if err := os.MkdirAll(filepath.Dir(f.sshdPath), 0o755); err != nil {
			return err
		}
		return os.WriteFile(f.sshdPath, []byte("#!/bin/sh\n"), 0o755)
	}
	if f.apt != "" {
		u.install = func(ctx context.Context, timeout time.Duration) error {
			return runInstall(ctx, f.apt, timeout)
		}
	}
	u.usermod = func(_ context.Context, user string) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.usermods = append(f.usermods, user)
		return nil
	}
}

// up runs ssh-up on spec, which may be raw JSON, and returns the line it printed and its status
func (f *fixture) up(t *testing.T, spec any, extra ...string) (string, int) {
	t.Helper()
	b, ok := spec.(json.RawMessage)
	if !ok {
		var err error
		b, err = json.Marshal(spec)
		must(t, err)
	}
	path := filepath.Join(f.dir, "ssh-spec.json")
	must(t, os.WriteFile(path, b, 0o600))
	args := append([]string{"--spec", path, "--root", f.root.Dir()}, extra...)
	var out, errOut bytes.Buffer
	res, err := run(context.Background(), args, f.tune)
	code := report(&out, &errOut, res, err)
	if strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("ssh-up printed %q, want one line, stderr %q", out.String(), errOut.String())
	}
	if exists(path) {
		t.Fatal("ssh-up left its spec file behind")
	}
	return strings.TrimSpace(out.String()), code
}

// sshUp runs ssh-up and decodes a result that must be a success
func (f *fixture) sshUp(t *testing.T, spec any, extra ...string) Result {
	t.Helper()
	line, code := f.up(t, spec, extra...)
	if code != 0 {
		t.Fatalf("ssh-up printed %s and exited %d", line, code)
	}
	var res Result
	must(t, json.Unmarshal([]byte(line), &res))
	return res
}

func (f *fixture) read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(f.root.Path(path))
	must(t, err)
	return string(b)
}

func (f *fixture) usermodCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.usermods...)
}

// aptStandIn is an apt-get stand-in that logs DEBIAN_FRONTEND and its arguments, then sleeps
type aptStandIn struct {
	path string
	dir  string
}

// fakeApt writes the stand-in and runs it once, so the first run's exec check costs no test time
func fakeApt(t *testing.T) aptStandIn {
	t.Helper()
	a := aptStandIn{dir: t.TempDir()}
	a.path = filepath.Join(a.dir, "apt-get")
	// exec makes sleep the process the timeout kills, so no orphan outlives the test
	writeFile(t, a.path, "#!/bin/sh\n"+
		"d='"+a.dir+"'\n"+
		"printf '%s %s\\n' \"DEBIAN_FRONTEND=$DEBIAN_FRONTEND\" \"$*\" >> \"$d/log\"\n"+
		"case \" $* \" in *' update '*) v=update ;; *) v=install ;; esac\n"+
		"if [ -s \"$d/exit\" ]; then\n"+
		"\techo 'E: The repository is not signed.'\n"+
		"\tread -r code < \"$d/exit\"\n"+
		"\texit \"$code\"\n"+
		"fi\n"+
		"read -r s < \"$d/$v\"\n"+
		"exec sleep \"$s\"\n")
	must(t, os.Chmod(a.path, 0o755))
	a.sleep(t, "0", "0")
	must(t, exec.Command(a.path, "update").Run())
	must(t, os.Remove(filepath.Join(a.dir, "log")))
	return a
}

// sleep sets how long update and install each take
func (a aptStandIn) sleep(t *testing.T, update, install string) {
	t.Helper()
	writeFile(t, filepath.Join(a.dir, "update"), update+"\n")
	writeFile(t, filepath.Join(a.dir, "install"), install+"\n")
}

// exit makes every command print an error and exit with code
func (a aptStandIn) exit(t *testing.T, code int) {
	t.Helper()
	writeFile(t, filepath.Join(a.dir, "exit"), strconv.Itoa(code)+"\n")
}

// calls returns the lines the stand-in logged and forgets them
func (a aptStandIn) calls(t *testing.T) string {
	t.Helper()
	path := filepath.Join(a.dir, "log")
	b, err := os.ReadFile(path)
	must(t, err)
	must(t, os.Remove(path))
	return string(b)
}

/* Processes */

// stopPidFile ends the process a pid file under root names, one this test started
func stopPidFile(t *testing.T, root sandbox.Root, name string) {
	t.Helper()
	pid, err := sandbox.ReadPidFile(root, name)
	if err != nil {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	waitFor(t, 5*time.Second, func() bool { return gone(pid) })
}

func gone(pid int) bool {
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}

func acceptsAt(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
