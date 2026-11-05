package egress

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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/oynozan/bugnet-run/internal/sandbox"
)

// Spec is what apply_secrets writes to /tmp/bugnet/egress-spec.json
type Spec struct {
	V int `json:"v"`
	// Token is the tunnel token, sent only when the router minted a new one
	Token    string   `json:"token,omitempty"`
	Endpoint string   `json:"endpoint"`
	IPs      []string `json:"ips"`
	Port     int      `json:"port"`
	Listen   string   `json:"listen"`
	Hosts    []string `json:"hosts"`
	Env      []EnvVar `json:"env"`
	// Home is the exec user's home, where the npm preset goes
	Home           string `json:"home"`
	GitPlaceholder string `json:"git_placeholder"`
	NPMPlaceholder string `json:"npm_placeholder"`
}

// EnvVar is one NAME=placeholder line of secrets.env
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Values of the error apply prints
const (
	ErrBadSpec      = "bad_spec"
	ErrPort443Taken = "port_443_taken"
	ErrTokenMissing = "token_missing"
	ErrApplyFailed  = "apply_failed"
)

const (
	listenWait   = 5 * time.Second
	probeTimeout = 500 * time.Millisecond
	maxEnv       = 64
	// musl reads /etc/hosts in 512-byte lines, so longer ones lose their last names
	hostsLineMax = 500
)

// Variables so tests can stand in for the binary and systemd, and trust their own tunnel CA
var (
	executable = os.Executable
	systemctl  func(ctx context.Context, args ...string) error
	// rootsForTests is the roots_file apply writes, which only a test root accepts
	rootsForTests = ""
)

type failure struct {
	reason string
	err    error
}

func (f *failure) Error() string { return f.reason + ": " + f.err.Error() }

func (f *failure) Unwrap() error { return f.err }

func fail(reason string, err error) error { return &failure{reason: reason, err: err} }

// classify reports a taken listen address as port_443_taken, whatever the address
func classify(err error) error {
	if errors.Is(err, syscall.EADDRINUSE) {
		return fail(ErrPort443Taken, err)
	}
	return fail(ErrApplyFailed, err)
}

type result struct {
	Forward string `json:"forward"`
	Hosts   int    `json:"hosts"`
	Secrets int    `json:"secrets"`
}

// Apply is bugnet-run egress apply, printing one JSON line and exiting 1 on any error
func Apply(args []string, stdout, stderr io.Writer) int {
	res, err := run(context.Background(), args)
	return report(stdout, stderr, res, err)
}

func report(stdout, stderr io.Writer, res result, err error) int {
	var b []byte
	status := 0
	if err != nil {
		reason := ErrApplyFailed
		var f *failure
		if errors.As(err, &f) {
			reason = f.reason
		}
		b, _ = json.Marshal(map[string]string{"error": reason})
		status = 1
		_, _ = fmt.Fprintf(stderr, "bugnet-run egress apply: %v\n", err)
	} else {
		b, _ = json.Marshal(res)
	}
	_, _ = stdout.Write(append(b, '\n'))
	return status
}

func run(ctx context.Context, args []string) (result, error) {
	flags := flag.NewFlagSet("egress apply", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	specPath := flags.String("spec", "", "spec file, deleted once read")
	rootDir := flags.String("root", "/", "directory standing for the sandbox's /")
	if err := flags.Parse(args); err != nil {
		return result{}, fail(ErrBadSpec, err)
	}
	if flags.NArg() > 0 {
		return result{}, fail(ErrBadSpec, fmt.Errorf("unexpected argument %q", flags.Arg(0)))
	}
	root, err := sandbox.NewRoot(*rootDir)
	if err != nil {
		return result{}, fail(ErrBadSpec, err)
	}
	if *specPath == "" {
		return result{}, fail(ErrBadSpec, errors.New("missing --spec"))
	}
	spec, err := readSpec(*specPath)
	if err != nil {
		return result{}, fail(ErrBadSpec, err)
	}
	exe, err := executable()
	if err != nil {
		return result{}, fail(ErrApplyFailed, err)
	}
	sup := sandbox.Supervisor{Root: root, Exe: exe, Systemctl: systemctl}
	a := applier{root: root, sup: sup, fwd: supervised{sup: sup}, trace: func(string) {}}
	return a.apply(ctx, spec)
}

/* Spec */

// readSpec deletes the file whatever it holds, since it may carry the tunnel token
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

// config is the egress.json the spec asks for
func (s Spec) config() Config {
	hosts := s.Hosts
	if hosts == nil {
		hosts = []string{}
	}
	return Config{
		Endpoint: s.Endpoint, IPs: s.IPs, Port: s.Port, Listen: s.Listen,
		TokenFile: sandbox.EgressToken, Hosts: hosts, RootsFile: rootsForTests,
	}
}

// check names a bad field without quoting values, since they may be tokens or placeholders
func (s Spec) check(root sandbox.Root) error {
	if s.V != 1 {
		return fmt.Errorf("spec version %d", s.V)
	}
	if s.Token != "" && !validToken(s.Token) {
		return errors.New("token is not bnt_ and 43 base64url characters")
	}
	if err := s.config().check(root); err != nil {
		return err
	}
	if len(s.Env) > maxEnv {
		return fmt.Errorf("env holds %d variables, more than %d", len(s.Env), maxEnv)
	}
	seen := map[string]bool{}
	for i, v := range s.Env {
		if !sandbox.ValidName(v.Name) || seen[v.Name] {
			return fmt.Errorf("env[%d] has a bad or repeated name", i)
		}
		seen[v.Name] = true
		if !validPlaceholder(v.Value) {
			return fmt.Errorf("env[%d] is not a placeholder", i)
		}
	}
	for name, p := range map[string]string{
		"git_placeholder": s.GitPlaceholder, "npm_placeholder": s.NPMPlaceholder,
	} {
		if p != "" && !validPlaceholder(p) {
			return fmt.Errorf("%s is not a placeholder", name)
		}
	}
	if s.Home != "" && (!filepath.IsAbs(s.Home) || filepath.Clean(s.Home) != s.Home ||
		strings.ContainsAny(s.Home, "\x00\r\n")) {
		return errors.New("home is not a clean absolute path")
	}
	if s.NPMPlaceholder != "" && s.Home == "" {
		return errors.New("npm_placeholder needs home")
	}
	return nil
}

// validPlaceholder accepts bnsec_ and 26 base32 characters, so no value reaches the sandbox
func validPlaceholder(p string) bool {
	body, ok := strings.CutPrefix(p, "bnsec_")
	return ok && len(body) == 26 && strings.Trim(body, "abcdefghijklmnopqrstuvwxyz234567") == ""
}

/* Steps */

// forwarder is how apply drives the forwarder process, a seam for tests
type forwarder interface {
	Running() bool
	// Start starts a stopped forwarder, failing at once when listen is taken
	Start(ctx context.Context, listen string) error
	Restart(ctx context.Context) error
	// Reload makes a running forwarder read its config and token again
	Reload() error
	// Wait returns once the forwarder accepts on listen, or after listenWait
	Wait(ctx context.Context, listen string) error
}

type applier struct {
	root  sandbox.Root
	sup   sandbox.Supervisor
	fwd   forwarder
	trace func(step string)
}

// apply takes DP 6.5's steps in order, so nothing points at the forwarder before it listens
func (a applier) apply(ctx context.Context, s Spec) (result, error) {
	if err := s.check(a.root); err != nil {
		return result{}, fail(ErrBadSpec, err)
	}
	if err := makeDirs(a.root); err != nil {
		return result{}, classify(err)
	}
	unlock, err := sandbox.Lock(a.root)
	if err != nil {
		return result{}, classify(err)
	}
	defer unlock()

	tokenChanged, err := a.writeToken(s)
	if err != nil {
		return result{}, err
	}
	a.trace("token")
	cfg := s.config()
	old, oldErr := LoadConfig(a.root.Path(sandbox.EgressConfig), a.root)
	data, err := json.Marshal(cfg)
	if err != nil {
		return result{}, classify(err)
	}
	cfgChanged, err := sandbox.WriteFile(a.root.Path(sandbox.EgressConfig), append(data, '\n'),
		0o644)
	if err != nil {
		return result{}, classify(err)
	}
	a.trace("config")

	switch {
	case !a.fwd.Running():
		err = a.fwd.Start(ctx, cfg.Listen)
	case oldErr != nil || old.Listen != cfg.Listen:
		err = a.fwd.Restart(ctx)
	case cfgChanged || tokenChanged:
		err = a.fwd.Reload()
	}
	if err != nil {
		return result{}, classify(err)
	}
	a.trace("forwarder")
	if err := a.fwd.Wait(ctx, cfg.Listen); err != nil {
		return result{}, classify(err)
	}
	a.trace("listening")

	ip, _, _ := net.SplitHostPort(cfg.Listen)
	hosts := a.root.Path(sandbox.HostsFile)
	if body := hostsBlock(ip, cfg.Hosts); body != "" || exists(hosts) {
		if err := sandbox.SetBlock(hosts, body, 0o644); err != nil {
			return result{}, classify(err)
		}
	}
	a.trace("hosts")
	if err := a.writeEnv(s); err != nil {
		return result{}, classify(err)
	}
	a.trace("env")
	if err := a.writePresets(s); err != nil {
		return result{}, classify(err)
	}
	a.trace("presets")
	return result{Forward: "listening", Hosts: len(cfg.Hosts), Secrets: len(s.Env)}, nil
}

func makeDirs(root sandbox.Root) error {
	for _, dir := range []string{sandbox.EtcDir, sandbox.RunDir} {
		if err := os.MkdirAll(root.Path(dir), 0o755); err != nil {
			return err
		}
		if err := os.Chmod(root.Path(dir), 0o755); err != nil {
			return err
		}
	}
	return nil
}

// writeToken keeps the token file when the spec has none, and needs one to be there
func (a applier) writeToken(s Spec) (bool, error) {
	path := a.root.Path(sandbox.EgressToken)
	if s.Token == "" {
		b, err := os.ReadFile(path)
		if err != nil || !validToken(strings.TrimSpace(string(b))) {
			return false, fail(ErrTokenMissing, errors.New("no tunnel token in the spec or "+
				sandbox.EgressToken))
		}
		return false, nil
	}
	changed, err := sandbox.WriteFile(path, []byte(s.Token+"\n"), 0o600)
	if err != nil {
		return false, classify(err)
	}
	return changed, nil
}

// hostsBlock maps every host to ip, never with a ::1 line, in lines short enough for musl
func hostsBlock(ip string, hosts []string) string {
	var b strings.Builder
	line := ""
	for _, h := range hosts {
		if line != "" && len(line)+1+len(h) > hostsLineMax {
			b.WriteString(line + "\n")
			line = ""
		}
		if line == "" {
			line = ip
		}
		line += " " + h
	}
	if line != "" {
		b.WriteString(line + "\n")
	}
	return b.String()
}

// writeEnv sends our sshd SIGHUP only when its SetEnv line changed, so new sessions see it
func (a applier) writeEnv(s Spec) error {
	vars := make([]sandbox.Var, len(s.Env))
	for i, v := range s.Env {
		vars[i] = sandbox.Var{Name: v.Name, Value: v.Value}
	}
	if _, err := sandbox.WriteFile(a.root.Path(sandbox.SecretsEnvFile), sandbox.FormatEnv(vars),
		0o644); err != nil {
		return err
	}
	if err := sandbox.WriteProfile(a.root); err != nil {
		return err
	}
	changed, err := sandbox.RewriteSetEnv(a.root)
	if err != nil || !changed {
		return err
	}
	_, err = a.sup.Signal(sandbox.SSHD, syscall.SIGHUP)
	return err
}

func (a applier) writePresets(s Spec) error {
	if err := a.writeGit(s.GitPlaceholder); err != nil {
		return err
	}
	if s.Home == "" {
		return nil
	}
	return a.writeNPM(s.Home, s.NPMPlaceholder)
}

func (a applier) writeGit(placeholder string) error {
	creds := a.root.Path(sandbox.GitCredentials)
	gitconfig := a.root.Path(sandbox.GitConfig)
	if placeholder == "" {
		if err := os.Remove(creds); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if !exists(gitconfig) {
			return nil
		}
		return sandbox.SetBlock(gitconfig, "", 0o644)
	}
	line := "https://x-access-token:" + placeholder + "@github.com\n"
	if _, err := sandbox.WriteFile(creds, []byte(line), 0o644); err != nil {
		return err
	}
	block := "[credential \"https://github.com\"]\n\thelper = store --file=" + creds + "\n"
	return sandbox.SetBlock(gitconfig, block, 0o644)
}

// writeNPM leaves a linked ~/.npmrc alone, so root never writes where the user points it
func (a applier) writeNPM(home, placeholder string) error {
	dir := a.root.Path(home)
	npmrc := filepath.Join(dir, ".npmrc")
	info, err := os.Lstat(npmrc)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if placeholder == "" {
			return nil
		}
		if err := createOwned(npmrc, dir); err != nil {
			return err
		}
	case err != nil:
		return err
	case !info.Mode().IsRegular():
		return nil
	}
	body := ""
	if placeholder != "" {
		body = "//registry.npmjs.org/:_authToken=" + placeholder + "\n"
	}
	return sandbox.SetBlock(npmrc, body, 0o600)
}

// createOwned makes an empty 0600 file owned by its directory's owner, the exec user for a home
func createOwned(path, dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 {
		if err := f.Chown(int(st.Uid), int(st.Gid)); err != nil {
			_ = f.Close()
			return err
		}
	}
	return f.Close()
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

/* The forwarder process */

// supervised drives the real forwarder under systemd or setsid
type supervised struct{ sup sandbox.Supervisor }

func (s supervised) Running() bool { return s.sup.Running(sandbox.Forward) }

func (s supervised) Start(ctx context.Context, listen string) error {
	if err := probeListen(listen); err != nil {
		return err
	}
	return s.sup.Start(ctx, sandbox.Forward)
}

func (s supervised) Restart(ctx context.Context) error {
	return s.sup.Restart(ctx, sandbox.Forward)
}

func (s supervised) Reload() error {
	_, err := s.sup.Signal(sandbox.Forward, syscall.SIGHUP)
	return err
}

// Wait trusts the pid file, which the forwarder writes only once it listens, and then a connect
func (s supervised) Wait(ctx context.Context, listen string) error {
	deadline := time.Now().Add(listenWait)
	for {
		if s.Running() {
			if addr, err := s.addr(listen); err == nil && accepts(ctx, addr) {
				return nil
			}
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-time.After(25 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if !s.Running() {
		if err := probeListen(listen); err != nil {
			return err
		}
	}
	return fmt.Errorf("the forwarder did not listen on %s within %v", listen, listenWait)
}

// addr reads the address a forwarder under a test root got for port 0
func (s supervised) addr(listen string) (string, error) {
	if _, port, err := net.SplitHostPort(listen); err != nil || port != "0" {
		return listen, err
	}
	b, err := os.ReadFile(s.sup.Root.Path(addrFile))
	return strings.TrimSpace(string(b)), err
}

// probeListen binds listen for a moment, so code holding the port is found before any start
func probeListen(listen string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	return ln.Close()
}

// accepts connects and hangs up at once, which the forwarder answers without a tunnel
func accepts(ctx context.Context, addr string) bool {
	d := net.Dialer{Timeout: probeTimeout}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
