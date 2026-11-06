// Package sshup makes the sandbox's own sshd ready behind the gate's SSH path
package sshup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oynozan/bugnet-run/internal/sandbox"
)

// Spec is what the router writes to /tmp/bugnet/ssh-spec.json
type Spec struct {
	V int `json:"v"`
	// User is the exec user, the only account our sshd lets in
	User string `json:"user"`
	// Ports are tried in order, the first free one on 127.0.0.1 taken
	Ports           []int  `json:"ports"`
	SSHDPath        string `json:"sshd_path"`
	Install         bool   `json:"install"`
	InstallTimeoutS int    `json:"install_timeout_s"`
	// Authorize holds authorized_keys lines added unless already there
	Authorize []string `json:"authorize"`
}

// Result is the one JSON line ssh-up prints
type Result struct {
	Port    int    `json:"port,omitempty"`
	HostKey string `json:"host_key,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Values of Result.Error
const (
	ErrBadSpec       = "bad_spec"
	ErrPortsTaken    = "ports_taken"
	ErrInstallFailed = "install_failed"
	ErrSSHDMissing   = "sshd_missing"
	// ErrSSHDFailed covers a file that cannot be written and an sshd that refuses or never listens
	ErrSSHDFailed = "sshd_failed"
)

const (
	maxPorts        = 4
	maxAuthorize    = 16
	maxLine         = 8192
	maxUser         = 32
	maxInstallS     = 600
	checkTimeout    = 10 * time.Second
	usermodTimeout  = 30 * time.Second
	distroStopWait  = 3 * time.Second
	distroSSHDPid   = "/run/sshd.pid"
	installedMarker = "sshd"
	checkPrefix     = ".sshd_config.check-"
	newKeyPrefix    = ".host_ed25519_key.new-"
)

// Variables so tests can hold a port, stand in for apt-get and usermod, and run under a test root
var (
	portFree  = probePort
	rootSteps = func(r sandbox.Root) bool { return r.IsSystem() }
	install   = func(ctx context.Context, timeout time.Duration) error {
		return runInstall(ctx, lookPath("apt-get", "/usr/bin/apt-get"), timeout)
	}
	usermod    = runUsermod
	systemctl  func(ctx context.Context, args ...string) error
	listenWait = 10 * time.Second
)

type failure struct {
	reason string
	err    error
}

func (f *failure) Error() string { return f.reason + ": " + f.err.Error() }

func (f *failure) Unwrap() error { return f.err }

func fail(reason string, err error) error { return &failure{reason: reason, err: err} }

// Run is bugnet-run ssh-up, printing one JSON line and exiting 1 on any error
func Run(args []string, stdout, stderr io.Writer) int {
	res, err := run(context.Background(), args, nil)
	return report(stdout, stderr, res, err)
}

func report(stdout, stderr io.Writer, res Result, err error) int {
	status := 0
	if err != nil {
		reason := ErrSSHDFailed
		var f *failure
		if errors.As(err, &f) {
			reason = f.reason
		}
		res, status = Result{Error: reason}, 1
		_, _ = fmt.Fprintf(stderr, "bugnet-run ssh-up: %v\n", err)
	}
	b, _ := json.Marshal(res)
	_, _ = stdout.Write(append(b, '\n'))
	return status
}

func run(ctx context.Context, args []string, tune func(*upper)) (Result, error) {
	flags := flag.NewFlagSet("ssh-up", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	specPath := flags.String("spec", "", "spec file, deleted once read")
	rootDir := flags.String("root", "/", "directory standing for the sandbox's /")
	newKey := flags.Bool("new-host-key", false, "replace the host key even when one exists")
	parseErr := flags.Parse(args)
	spec, specErr := Spec{}, errors.New("missing --spec")
	if *specPath != "" {
		spec, specErr = readSpec(*specPath)
	}
	if parseErr != nil {
		return Result{}, fail(ErrBadSpec, parseErr)
	}
	if flags.NArg() > 0 {
		return Result{}, fail(ErrBadSpec, fmt.Errorf("unexpected argument %q", flags.Arg(0)))
	}
	root, err := sandbox.NewRoot(*rootDir)
	if err != nil {
		return Result{}, fail(ErrBadSpec, err)
	}
	if specErr != nil {
		return Result{}, fail(ErrBadSpec, specErr)
	}
	sup := sandbox.Supervisor{Root: root, Systemctl: systemctl}
	u := upper{
		root: root, sup: sup, sshd: supervised{sup: sup, wait: listenWait},
		newHostKey: *newKey, free: portFree, system: rootSteps(root), install: install,
		usermod: usermod,
	}
	if tune != nil {
		tune(&u)
	}
	return u.up(ctx, spec)
}

/* Spec */

// readSpec deletes the file whatever it holds, as setup and egress apply do with theirs
func readSpec(path string) (Spec, error) {
	var s Spec
	b, err := os.ReadFile(path)
	if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) && err == nil {
		err = rmErr
	}
	if err != nil {
		return s, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return s, errors.New("spec has data after its object")
	}
	return s, nil
}

// check names a bad field without quoting its value
func (s Spec) check() error {
	if s.V != 1 {
		return fmt.Errorf("spec version %d", s.V)
	}
	if !validUser(s.User) {
		return errors.New("user is not a plain account name")
	}
	if len(s.Ports) == 0 || len(s.Ports) > maxPorts {
		return fmt.Errorf("ports holds %d entries, want 1 to %d", len(s.Ports), maxPorts)
	}
	for i, p := range s.Ports {
		if p < 1 || p > 65535 || slices.Index(s.Ports, p) != i {
			return fmt.Errorf("ports[%d] is out of range or repeated", i)
		}
	}
	p := s.SSHDPath
	// The supervisor knows our sshd by sshd in its command line, so the path must hold it
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || hasControl(p) ||
		!strings.Contains(filepath.Base(p), installedMarker) {
		return errors.New("sshd_path is not a clean absolute path to an sshd")
	}
	if s.InstallTimeoutS < 0 || s.InstallTimeoutS > maxInstallS ||
		s.Install && s.InstallTimeoutS == 0 {
		return fmt.Errorf("install_timeout_s is not 1 to %d", maxInstallS)
	}
	if len(s.Authorize) > maxAuthorize {
		return fmt.Errorf("authorize holds more than %d lines", maxAuthorize)
	}
	for i, line := range s.Authorize {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || len(line) > maxLine || hasControl(line) {
			return fmt.Errorf("authorize[%d] is not one authorized_keys line", i)
		}
	}
	return nil
}

// validUser accepts names that AllowUsers reads literally and usermod never takes for a flag
func validUser(name string) bool {
	if name == "" || len(name) > maxUser || name[0] == '-' {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

/* Steps */

// daemon is how ssh-up drives our sshd, a seam for tests
type daemon interface {
	Running() bool
	// Loaded returns when sshd last read its config and host key, the time of its pid file
	Loaded() time.Time
	// Check runs sshd -t on config before it replaces the one a running sshd uses
	Check(ctx context.Context, sshdPath string, config []byte) error
	Start(ctx context.Context) error
	Restart(ctx context.Context) error
	// Reload sends SIGHUP, which makes sshd read its config and host key again
	Reload() error
	// Wait returns once the port accepts and sshd's last load is not the one at since, or times out
	Wait(ctx context.Context, port int, since time.Time) error
}

type upper struct {
	root       sandbox.Root
	sup        sandbox.Supervisor
	sshd       daemon
	newHostKey bool
	free       func(port int) bool
	// system allows the steps that change the host itself, which local never runs
	system  bool
	install func(ctx context.Context, timeout time.Duration) error
	usermod func(ctx context.Context, user string) error
}

// up makes SSH ready, writing no sshd_config, port, key or sshd_path until sshd -t passes
func (u upper) up(ctx context.Context, s Spec) (Result, error) {
	if err := s.check(); err != nil {
		return Result{}, fail(ErrBadSpec, err)
	}
	if err := makeDirs(u.root); err != nil {
		return Result{}, fail(ErrSSHDFailed, err)
	}
	// The install runs before the sandbox lock, so egress apply never waits on apt
	if err := u.ensureSSHD(ctx, s); err != nil {
		return Result{}, err
	}
	unlock, err := sandbox.Lock(u.root)
	if err != nil {
		return Result{}, fail(ErrSSHDFailed, err)
	}
	defer unlock()
	if err := clearLeftovers(u.root); err != nil {
		return Result{}, fail(ErrSSHDFailed, err)
	}

	port, ok := u.pickPort(s.Ports)
	if !ok {
		return Result{}, fail(ErrPortsTaken, errors.New("every port in the spec is taken"))
	}
	key, err := u.hostKey()
	if err != nil {
		return Result{}, fail(ErrSSHDFailed, err)
	}
	defer key.drop()
	if err := u.authorize(s.Authorize); err != nil {
		return Result{}, fail(ErrSSHDFailed, err)
	}
	if u.system {
		if err := u.unlockPassword(ctx, s.User); err != nil {
			return Result{}, fail(ErrSSHDFailed, err)
		}
	}
	if err := u.sup.Prepare(sandbox.SSHD); err != nil {
		return Result{}, fail(ErrSSHDFailed, err)
	}
	if err := u.runSSHD(ctx, s, port, key); err != nil {
		return Result{}, fail(ErrSSHDFailed, err)
	}
	return Result{Port: port, HostKey: key.line}, nil
}

// ensureSSHD installs openssh-server only where the spec allows it and the root is the sandbox's
func (u upper) ensureSSHD(ctx context.Context, s Spec) error {
	if !s.Install || !u.system {
		if executable(s.SSHDPath) {
			return nil
		}
		return fail(ErrSSHDMissing, errors.New("sshd_path is not an executable file"))
	}
	// A second run waits here, so it never takes an sshd that dpkg unpacked but has not set up
	unlock, err := installLock(u.root)
	if err != nil {
		return fail(ErrSSHDFailed, err)
	}
	defer unlock()
	if executable(s.SSHDPath) {
		return nil
	}
	if err := u.install(ctx, time.Duration(s.InstallTimeoutS)*time.Second); err != nil {
		return fail(ErrInstallFailed, err)
	}
	u.stopDistroSSHD(ctx)
	if !executable(s.SSHDPath) {
		return fail(ErrSSHDMissing, errors.New("the install left no executable at sshd_path"))
	}
	return nil
}

// installLock takes an flock on /etc/bugnet/ssh, which installs alone take
func installLock(r sandbox.Root) (func(), error) {
	f, err := os.Open(r.Path(sandbox.SSHDir))
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}

func executable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

// stopDistroSSHD stops and disables an sshd the install started, so port 22 is free for ours
func (u upper) stopDistroSSHD(ctx context.Context) {
	if u.sup.Init() == sandbox.InitSystemd {
		for _, unit := range []string{"ssh.socket", "ssh.service"} {
			_ = u.sup.RunSystemctl(ctx, "disable", "--now", unit)
		}
		return
	}
	pidFile := u.root.Path(distroSSHDPid)
	if sent, _ := sandbox.SignalPidFile(pidFile, installedMarker, syscall.SIGTERM); !sent {
		return
	}
	deadline := time.Now().Add(distroStopWait)
	for time.Now().Before(deadline) {
		if alive, _ := sandbox.SignalPidFile(pidFile, installedMarker, 0); !alive {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func makeDirs(root sandbox.Root) error {
	for _, dir := range []string{sandbox.EtcDir, sandbox.RunDir, sandbox.SSHDir} {
		if err := os.MkdirAll(root.Path(dir), 0o755); err != nil {
			return err
		}
		if err := os.Chmod(root.Path(dir), 0o755); err != nil {
			return err
		}
	}
	return nil
}

// clearLeftovers removes the dot-files a killed run left, as every writer there holds the lock
func clearLeftovers(r sandbox.Root) error {
	dir := r.Path(sandbox.SSHDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") || !e.Type().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil &&
			!errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// pickPort keeps the port of our running sshd, which the probe would find taken by sshd itself
func (u upper) pickPort(ports []int) (int, bool) {
	if u.sshd.Running() {
		b, err := os.ReadFile(u.root.Path(sandbox.SSHPortFile))
		if cur, perr := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && perr == nil &&
			slices.Contains(ports, cur) {
			return cur, true
		}
	}
	for _, p := range ports {
		if u.free(p) {
			return p, true
		}
	}
	return 0, false
}

// probePort binds the port on 127.0.0.1 for a moment, which fails while any sshd listens on it
func probePort(port int) bool {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// hostKey is the key ssh-up reports, a new one waiting in its own file until sshd takes it
type hostKey struct {
	line    string
	pending string
}

// drop removes a new key that never replaced the old one
func (k hostKey) drop() {
	if k.pending != "" {
		_ = os.Remove(k.pending)
	}
}

// hostKey keeps a readable key unless told to replace it, writing a new one beside it
func (u upper) hostKey() (hostKey, error) {
	path := u.root.Path(sandbox.HostKeyFile)
	if !u.newHostKey {
		if b, err := os.ReadFile(path); err == nil {
			if line, err := publicLine(b); err == nil {
				// sshd refuses a host key that others can read
				return hostKey{line: line}, os.Chmod(path, 0o600)
			}
		}
	}
	text, line, err := newHostKey()
	if err != nil {
		return hostKey{}, err
	}
	// CreateTemp makes the file 0600, which sshd asks of a host key
	tmp, err := os.CreateTemp(filepath.Dir(path), newKeyPrefix+"*")
	if err != nil {
		return hostKey{}, err
	}
	key := hostKey{line: line, pending: tmp.Name()}
	_, err = tmp.Write(text)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		key.drop()
		return hostKey{}, err
	}
	return key, nil
}

// authorize appends the lines not already there, leaving every other line as it is
func (u upper) authorize(lines []string) error {
	path := u.root.Path(sandbox.AuthorizedKeys)
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	text := string(old)
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	have := map[string]bool{}
	for l := range strings.Lines(text) {
		have[strings.TrimSpace(l)] = true
	}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if !have[l] {
			text += l + "\n"
			have[l] = true
		}
	}
	// sshd reads this file as the user logging in, who may not be root
	_, err = sandbox.WriteFile(path, []byte(text), 0o644)
	return err
}

// unlockPassword swaps a locked password for *, since sshd without PAM refuses a locked account
func (u upper) unlockPassword(ctx context.Context, user string) error {
	b, err := os.ReadFile(u.root.Path(sandbox.ShadowFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for line := range strings.Lines(string(b)) {
		name, rest, ok := strings.Cut(line, ":")
		if ok && name == user && strings.HasPrefix(rest, "!") {
			return u.usermod(ctx, user)
		}
	}
	return nil
}

// runSSHD leaves every file a running sshd reads alone until the new config and key pass the check
func (u upper) runSSHD(ctx context.Context, s Spec, port int, key hostKey) error {
	setEnv, err := sandbox.SetEnvLine(u.root)
	if err != nil {
		return err
	}
	keyPath := u.root.Path(sandbox.HostKeyFile)
	config := []byte(sshdConfig(u.root, port, s.User, keyPath, setEnv))
	old, err := os.ReadFile(u.root.Path(sandbox.SSHDConfig))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	running := u.sshd.Running()
	owed := u.owed(running)
	keyChanged := key.pending != ""
	reload := !bytes.Equal(old, config) || keyChanged || owed(sandbox.SSHDConfig) ||
		owed(sandbox.HostKeyFile)
	restart := sandbox.SSHDPath(u.root) != s.SSHDPath || owed(sandbox.SSHDPathFile)
	if !running || reload || restart {
		checked := config
		if keyChanged {
			checked = []byte(sshdConfig(u.root, port, s.User, key.pending, setEnv))
		}
		if err := u.sshd.Check(ctx, s.SSHDPath, checked); err != nil {
			return err
		}
	}
	// sshd_path goes last, so a run that stops before writing it leaves the restart to the next
	for _, f := range []struct {
		path string
		data []byte
	}{
		{sandbox.SSHDConfig, config},
		{sandbox.SSHPortFile, []byte(strconv.Itoa(port) + "\n")},
		{sandbox.SSHDPathFile, []byte(s.SSHDPath + "\n")},
	} {
		if _, err := sandbox.WriteFile(u.root.Path(f.path), f.data, 0o644); err != nil {
			return err
		}
	}
	if keyChanged {
		if err := os.Rename(key.pending, keyPath); err != nil {
			return err
		}
	}
	var since time.Time
	switch {
	case !running:
		err = u.sshd.Start(ctx)
	case restart:
		err = u.sshd.Restart(ctx)
	case reload:
		// The old listener answers until sshd acts on the signal, so Wait looks for a new load
		since = u.sshd.Loaded()
		err = u.sshd.Reload()
	}
	if err != nil {
		return err
	}
	return u.sshd.Wait(ctx, port, since)
}

// owed reports a file newer than sshd's pid file, which a run killed before its signal leaves
func (u upper) owed(running bool) func(name string) bool {
	var loaded time.Time
	if running {
		loaded = u.sshd.Loaded()
	}
	return func(name string) bool {
		info, err := os.Stat(u.root.Path(name))
		return !loaded.IsZero() && err == nil && info.ModTime().After(loaded)
	}
}

// sshdConfig is DP 6.4's text, with no Include since E2B's drop-in allows empty passwords
func sshdConfig(r sandbox.Root, port int, user, hostKey, setEnv string) string {
	lines := []string{
		"Port " + strconv.Itoa(port),
		"ListenAddress 127.0.0.1",
		"HostKey " + hostKey,
		"AuthorizedKeysFile " + r.Path(sandbox.AuthorizedKeys),
		"AllowUsers " + user,
		"PidFile " + r.Path(sandbox.PidFile(sandbox.SSHD.Name)),
		"PubkeyAuthentication yes",
		"PasswordAuthentication no",
		"PermitEmptyPasswords no",
		"KbdInteractiveAuthentication no",
		"UsePAM no",
	}
	if setEnv != "" {
		lines = append(lines, setEnv)
	}
	lines = append(lines,
		"PermitRootLogin prohibit-password",
		"AllowTcpForwarding local",
		"PermitOpen 127.0.0.1:* [::1]:*",
		"AllowAgentForwarding no",
		"AllowStreamLocalForwarding no",
		"X11Forwarding no",
		"PermitTunnel no",
		"GatewayPorts no",
		"PermitUserRC no",
		"UseDNS no",
		"Subsystem sftp internal-sftp",
		"ClientAliveInterval 30",
		"ClientAliveCountMax 3",
	)
	return strings.Join(lines, "\n") + "\n"
}

/* Host commands */

// runInstall runs apt-get update and install within one timeout, never stopping for a question
func runInstall(ctx context.Context, apt string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	opts := []string{
		"-o", "DPkg::Lock::Timeout=" + strconv.Itoa(int(timeout.Seconds())),
		"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold",
	}
	for _, args := range [][]string{
		append(slices.Clone(opts), "update"),
		append(slices.Clone(opts), "install", "-y", "--no-install-recommends", "openssh-server"),
	} {
		cmd := exec.CommandContext(ctx, apt, args...)
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		cmd.WaitDelay = time.Second
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("apt-get %s: %w: %s", args[len(opts)], err, tail(out))
		}
	}
	return nil
}

func runUsermod(ctx context.Context, user string) error {
	ctx, cancel := context.WithTimeout(ctx, usermodTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, lookPath("usermod", "/usr/sbin/usermod"), "-p", "*",
		user).CombinedOutput()
	if err != nil {
		return fmt.Errorf("usermod: %w: %s", err, tail(out))
	}
	return nil
}

// lookPath falls back to the usual place, since a root shell may run without /usr/sbin on PATH
func lookPath(name, fallback string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return fallback
}

func tail(out []byte) []byte {
	out = bytes.TrimSpace(out)
	if len(out) > 1024 {
		out = out[len(out)-1024:]
	}
	return out
}

/* Our sshd */

// supervised drives our real sshd under systemd or setsid
type supervised struct {
	sup  sandbox.Supervisor
	wait time.Duration
}

func (s supervised) Running() bool { return s.sup.Running(sandbox.SSHD) }

// Loaded is the time of the pid file sshd writes once it has read its files and listens
func (s supervised) Loaded() time.Time {
	info, err := os.Stat(s.sup.Root.Path(sandbox.PidFile(sandbox.SSHD.Name)))
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

func (s supervised) Check(ctx context.Context, sshdPath string, config []byte) error {
	tmp, err := os.CreateTemp(s.sup.Root.Path(sandbox.SSHDir), checkPrefix+"*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, err = tmp.Write(config)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, sshdPath, "-t", "-f", tmp.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sshd -t refused the config: %w: %s", err, complaint(out))
	}
	return nil
}

// complaint is sshd's output for stderr, cut only once no placeholder body is left in it
func complaint(out []byte) []byte { return tail(redact(out)) }

// redact drops each placeholder's body, so sshd quoting our SetEnv line never logs one
func redact(b []byte) []byte {
	const prefix = "bnsec_"
	var out []byte
	for {
		i := bytes.Index(b, []byte(prefix))
		if i < 0 {
			return append(out, b...)
		}
		out = append(out, b[:i+len(prefix)]...)
		b = bytes.TrimLeft(b[i+len(prefix):], "abcdefghijklmnopqrstuvwxyz234567")
	}
}

func (s supervised) Start(ctx context.Context) error { return s.sup.Start(ctx, sandbox.SSHD) }

func (s supervised) Restart(ctx context.Context) error { return s.sup.Restart(ctx, sandbox.SSHD) }

func (s supervised) Reload() error {
	_, err := s.sup.Signal(sandbox.SSHD, syscall.SIGHUP)
	return err
}

// Wait trusts a pid file sshd wrote after since, as it writes one once it listens, and a connect
func (s supervised) Wait(ctx context.Context, port int, since time.Time) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(s.wait)
	for {
		reloaded := since.IsZero() || !s.Loaded().Equal(since)
		if s.Running() && reloaded && accepts(ctx, addr) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("sshd did not listen on %s within %v", addr, s.wait)
		}
		select {
		case <-time.After(25 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func accepts(ctx context.Context, addr string) bool {
	d := net.Dialer{Timeout: 500 * time.Millisecond}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
