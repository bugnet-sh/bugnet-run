// Package setup prepares a sandbox for previews, SSH and secrets, and starts its gate
package setup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bugnet-sh/bugnet-run/internal/gate"
	"github.com/bugnet-sh/bugnet-run/internal/sandbox"
)

// Spec is what the router writes to /tmp/bugnet/setup-spec.json
type Spec struct {
	V             int    `json:"v"`
	GateKey       string `json:"gate_key"`
	GateListen    string `json:"gate_listen"`
	DenyPorts     []int  `json:"deny_ports"`
	CAPEM         string `json:"ca_pem"`
	CASHA256      string `json:"ca_sha256"`
	CAVersion     int    `json:"ca_version"`
	PreviewDomain string `json:"preview_domain"`
	// Sample starts the sampler, which a later setup without it leaves running
	Sample bool `json:"sample"`
}

// Result is the one JSON line setup prints
type Result struct {
	Gate  string `json:"gate,omitempty"`
	CA    string `json:"ca,omitempty"`
	Init  string `json:"init,omitempty"`
	Error string `json:"error,omitempty"`
}

// Values of Result.Error, a file that cannot be written counting as gate_failed
const (
	ErrBadSpec    = "bad_spec"
	ErrCAMismatch = "ca_mismatch"
	ErrGateFailed = "gate_failed"
)

// Values of Result.CA
const (
	CAInstalled = "installed"
	CAChecked   = "checked"
	CAAppended  = "appended"
	CASkipped   = "skipped"
)

const (
	caTimeout   = time.Minute
	probeWithin = time.Second
)

// Variables so tests can stand in for the binary, systemd and update-ca-certificates
var (
	executable = os.Executable
	updateCA   = runUpdateCA
	systemctl  func(ctx context.Context, args ...string) error
	healthWait = 10 * time.Second
)

var errNoUpdater = errors.New("update-ca-certificates is not available")

// caEnvNames point at the combined system bundle, since each replaces a client's own
var caEnvNames = []string{
	"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PIP_CERT", "GIT_SSL_CAINFO",
	"AWS_CA_BUNDLE",
}

type failure struct {
	reason string
	err    error
}

func (f *failure) Error() string { return f.reason + ": " + f.err.Error() }

func (f *failure) Unwrap() error { return f.err }

func fail(reason string, err error) error { return &failure{reason: reason, err: err} }

// Run is bugnet-run setup, printing one JSON line and exiting 1 on any error
func Run(args []string, stdout, stderr io.Writer) int {
	res, err := run(context.Background(), args, stderr)
	status := 0
	if err != nil {
		reason := ErrGateFailed
		var f *failure
		if errors.As(err, &f) {
			reason = f.reason
		}
		res, status = Result{Error: reason}, 1
		_, _ = fmt.Fprintf(stderr, "bugnet-run setup: %v\n", err)
	}
	b, _ := json.Marshal(res)
	_, _ = stdout.Write(append(b, '\n'))
	return status
}

func run(ctx context.Context, args []string, stderr io.Writer) (Result, error) {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	specPath := flags.String("spec", "", "spec file, deleted once read")
	rootDir := flags.String("root", "/", "directory standing for the sandbox's /")
	repair := flags.Bool("repair", false, "only rewrite the gate files and restart the gate")
	if err := flags.Parse(args); err != nil {
		return Result{}, fail(ErrBadSpec, err)
	}
	if flags.NArg() > 0 {
		return Result{}, fail(ErrBadSpec, fmt.Errorf("unexpected argument %q", flags.Arg(0)))
	}
	root, err := sandbox.NewRoot(*rootDir)
	if err != nil {
		return Result{}, fail(ErrBadSpec, err)
	}
	var spec *Spec
	switch {
	case *specPath != "":
		s, err := readSpec(*specPath)
		if err != nil {
			return Result{}, fail(ErrBadSpec, err)
		}
		spec = &s
	case !*repair:
		return Result{}, fail(ErrBadSpec, errors.New("missing --spec"))
	}
	exe, err := executable()
	if err != nil {
		return Result{}, fail(ErrGateFailed, err)
	}
	if err := makeDirs(root); err != nil {
		return Result{}, fail(ErrGateFailed, err)
	}
	unlock, err := sandbox.Lock(root)
	if err != nil {
		return Result{}, fail(ErrGateFailed, err)
	}
	defer unlock()

	cfg, key, changed, err := gateFiles(root, spec)
	if err != nil {
		return Result{}, err
	}
	var res Result
	if !*repair {
		if res.CA, err = installCA(ctx, root, *spec); err != nil {
			return Result{}, fail(ErrCAMismatch, err)
		}
		if err := writeEnv(root, *spec, res.CA); err != nil {
			return Result{}, fail(ErrGateFailed, err)
		}
	}
	// Units start from the copy, so a /tmp emptied at boot never takes their binary away
	if _, err := sandbox.InstallRunner(root, exe); err != nil {
		return Result{}, fail(ErrGateFailed, err)
	}
	sup := sandbox.Supervisor{Root: root, Systemctl: systemctl}
	if err := startGate(ctx, sup, cfg, key, changed); err != nil {
		return Result{}, fail(ErrGateFailed, err)
	}
	// The sampler only feeds the estimator, so a sandbox without one is still ready
	if !*repair && spec.Sample {
		if err := startSampler(ctx, sup); err != nil {
			_, _ = fmt.Fprintf(stderr, "bugnet-run setup: sampler: %v\n", err)
		}
	}
	res.Gate, res.Init = "listening", string(sup.Init())
	return res, nil
}

// startSampler writes sample.json and starts the sampler, leaving a running one alone
func startSampler(ctx context.Context, sup sandbox.Supervisor) error {
	if _, err := sandbox.WriteFile(sup.Root.Path(sandbox.SampleConfig), []byte("{\"v\":1}\n"),
		0o644); err != nil {
		return err
	}
	return sup.Start(ctx, sandbox.Sample)
}

/* Spec */

// readSpec deletes the file whatever it holds, since it carries the gate key
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
	return s, s.validate()
}

func (s Spec) validate() error {
	if s.V != 1 {
		return fmt.Errorf("spec version %d", s.V)
	}
	if !gate.ValidKey(s.GateKey) {
		return errors.New("gate_key is not 43 base64url characters")
	}
	if _, err := gate.ListenPort(s.GateListen); err != nil {
		return err
	}
	for _, p := range s.DenyPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("deny_ports holds %d", p)
		}
	}
	if (s.CAPEM != "" || s.CASHA256 != "") && s.CAVersion < 1 {
		return errors.New("a CA needs ca_version 1 or more")
	}
	if s.CAPEM != "" {
		if _, err := parseCerts(s.CAPEM); err != nil {
			return err
		}
	}
	if s.CASHA256 != "" {
		if b, err := hex.DecodeString(s.CASHA256); err != nil || len(b) != sha256.Size {
			return errors.New("ca_sha256 is not 64 hex characters")
		}
	}
	if s.PreviewDomain != "" && !validDomain(s.PreviewDomain) {
		return errors.New("preview_domain is not a host name")
	}
	return nil
}

const hostChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"

func validDomain(name string) bool {
	if len(name) > 253 {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		if strings.TrimLeft(label, hostChars) != "" {
			return false
		}
	}
	return true
}

// parseCerts accepts only certificates, so a key pasted by mistake never lands in a public file
func parseCerts(text string) ([][]byte, error) {
	var ders [][]byte
	rest := []byte(text)
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("ca_pem holds a %s block", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("ca_pem: %w", err)
		}
		ders = append(ders, block.Bytes)
		rest = next
	}
	if len(ders) == 0 || len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("ca_pem is not a PEM certificate")
	}
	return ders, nil
}

/* Gate */

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

// gateFiles writes gate.key and gate.json from spec, or reads them back for a repair without one
func gateFiles(root sandbox.Root, spec *Spec) (gate.Config, string, bool, error) {
	if spec == nil {
		cfg, err := gate.LoadConfig(root.Path(sandbox.GateConfig))
		if err != nil {
			return cfg, "", false, fail(ErrBadSpec, err)
		}
		b, err := os.ReadFile(root.Path(cfg.KeyFile))
		key := strings.TrimSpace(string(b))
		if err == nil && !gate.ValidKey(key) {
			err = errors.New("gate key file holds no valid key")
		}
		if err != nil {
			return cfg, "", false, fail(ErrBadSpec, err)
		}
		return cfg, key, false, nil
	}
	cfg := gate.Config{
		Listen: spec.GateListen, KeyFile: sandbox.GateKeyFile, Deny: spec.DenyPorts,
		SSHPortFile: sandbox.SSHPortFile,
	}
	if cfg.Deny == nil {
		cfg.Deny = []int{}
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return cfg, "", false, fail(ErrGateFailed, err)
	}
	keyChanged, err := sandbox.WriteFile(root.Path(sandbox.GateKeyFile),
		[]byte(spec.GateKey+"\n"), 0o600)
	if err != nil {
		return cfg, "", false, fail(ErrGateFailed, err)
	}
	cfgChanged, err := sandbox.WriteFile(root.Path(sandbox.GateConfig), append(data, '\n'), 0o644)
	if err != nil {
		return cfg, "", false, fail(ErrGateFailed, err)
	}
	return cfg, spec.GateKey, keyChanged || cfgChanged, nil
}

// startGate leaves a healthy gate on unchanged files alone, so a second setup keeps one process
func startGate(ctx context.Context, sup sandbox.Supervisor, cfg gate.Config, key string,
	changed bool) error {
	addr := gate.ProbeAddr(cfg.Listen)
	if !changed && probe(ctx, addr, key) == nil {
		return sup.Install(ctx, sandbox.Gate)
	}
	if err := sup.Restart(ctx, sandbox.Gate); err != nil {
		return err
	}
	deadline := time.Now().Add(healthWait)
	for {
		err := probe(ctx, addr, key)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func probe(ctx context.Context, addr, key string) error {
	ctx, cancel := context.WithTimeout(ctx, probeWithin)
	defer cancel()
	return gate.Healthy(ctx, addr, key)
}

/* CA */

func caFile(version int) string {
	return fmt.Sprintf("%s/bugnet-egress-v%d.crt", sandbox.CADir, version)
}

// installCA appends on a rotation, since update-ca-certificates could drop a provider's own CA
func installCA(ctx context.Context, root sandbox.Root, s Spec) (string, error) {
	if s.CAPEM == "" && s.CASHA256 == "" {
		return CASkipped, nil
	}
	target := root.Path(caFile(s.CAVersion))
	if s.CAPEM == "" {
		b, err := os.ReadFile(target)
		if err != nil {
			return "", err
		}
		if !strings.EqualFold(hexSHA256(b), s.CASHA256) {
			return "", fmt.Errorf("%s differs from ca_sha256", caFile(s.CAVersion))
		}
		return CAChecked, nil
	}
	if s.CASHA256 != "" && !strings.EqualFold(hexSHA256([]byte(s.CAPEM)), s.CASHA256) {
		return "", errors.New("ca_pem differs from ca_sha256")
	}
	certs, err := parseCerts(s.CAPEM)
	if err != nil {
		return "", err
	}
	others, err := filepath.Glob(root.Path(sandbox.CADir + "/bugnet-egress-v*.crt"))
	if err != nil {
		return "", err
	}
	rotation := false
	for _, other := range others {
		rotation = rotation || other != target
	}
	if _, err := sandbox.WriteFile(target, []byte(s.CAPEM), 0o644); err != nil {
		return "", err
	}
	bundle := root.Path(sandbox.CABundle)
	var toolErr error
	if !rotation && !bundleHolds(bundle, certs) {
		if err := updateCA(ctx, root); err != nil && !errors.Is(err, errNoUpdater) {
			toolErr = err
		}
	}
	if !bundleHolds(bundle, certs) {
		if err := appendPEM(bundle, s.CAPEM); err != nil {
			return "", errors.Join(toolErr, err)
		}
		if !bundleHolds(bundle, certs) {
			return "", errors.Join(toolErr, errors.New("the CA bundle lacks the CA"))
		}
	}
	if rotation {
		return CAAppended, nil
	}
	return CAInstalled, nil
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func bundleHolds(bundle string, certs [][]byte) bool {
	b, err := os.ReadFile(bundle)
	if err != nil {
		return false
	}
	have := map[string]bool{}
	for {
		block, rest := pem.Decode(b)
		if block == nil {
			break
		}
		have[string(block.Bytes)] = true
		b = rest
	}
	for _, der := range certs {
		if !have[string(der)] {
			return false
		}
	}
	return true
}

func appendPEM(bundle, text string) error {
	if err := os.MkdirAll(filepath.Dir(bundle), 0o755); err != nil {
		return err
	}
	old, err := os.ReadFile(bundle)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var add strings.Builder
	if len(old) > 0 && old[len(old)-1] != '\n' {
		add.WriteString("\n")
	}
	add.WriteString(text)
	if !strings.HasSuffix(text, "\n") {
		add.WriteString("\n")
	}
	f, err := os.OpenFile(bundle, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(add.String()); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func runUpdateCA(ctx context.Context, root sandbox.Root) error {
	if !root.IsSystem() {
		return errNoUpdater
	}
	path, err := exec.LookPath("update-ca-certificates")
	if err != nil {
		path = "/usr/sbin/update-ca-certificates"
		if _, err := os.Stat(path); err != nil {
			return errNoUpdater
		}
	}
	ctx, cancel := context.WithTimeout(ctx, caTimeout)
	defer cancel()
	if out, err := exec.CommandContext(ctx, path).CombinedOutput(); err != nil {
		return fmt.Errorf("update-ca-certificates: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

/* Env */

// writeEnv leaves the CA lines out when no Bugnet CA is installed
func writeEnv(root sandbox.Root, s Spec, ca string) error {
	var vars []sandbox.Var
	if ca != CASkipped {
		for _, name := range caEnvNames {
			vars = append(vars, sandbox.Var{Name: name, Value: sandbox.CABundle})
		}
		vars = append(vars,
			sandbox.Var{Name: "NODE_EXTRA_CA_CERTS", Value: caFile(s.CAVersion)},
			sandbox.Var{Name: "NODE_USE_SYSTEM_CA", Value: "1"},
			sandbox.Var{Name: "DENO_TLS_CA_STORE", Value: "system"})
	}
	if s.PreviewDomain != "" {
		vars = append(vars, sandbox.Var{
			Name: "__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS", Value: "." + s.PreviewDomain,
		})
	}
	if _, err := sandbox.WriteFile(root.Path(sandbox.EnvFile), sandbox.FormatEnv(vars),
		0o644); err != nil {
		return err
	}
	return sandbox.WriteProfile(root)
}
