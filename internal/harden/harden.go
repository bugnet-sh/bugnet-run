// Package harden blocks mail, private ranges, metadata and mining pools for outbound traffic
package harden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/bugnet-sh/bugnet-run/internal/sandbox"
)

// Spec is what the router writes to /tmp/bugnet/harden-spec.json
type Spec struct {
	V int `json:"v"`
	// MailPorts are blocked over TCP to any address
	MailPorts  []int    `json:"mail_ports"`
	DenyRanges []string `json:"deny_ranges"`
	// Pools are mining pool addresses, at most MaxPools
	Pools []string `json:"pools"`
	// Allow holds the provider's own addresses, reachable before any block
	Allow []string `json:"allow"`
	// NoGateway leaves the default gateways under the blocks, for a gateway that is the host
	NoGateway bool `json:"no_gateway"`
}

// Result is the one JSON line harden prints
type Result struct {
	Firewall string `json:"firewall,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Values of Result.Error
const (
	ErrBadSpec             = "bad_spec"
	ErrFirewallUnavailable = "firewall_unavailable"
)

// Values of Result.Firewall
const (
	FirewallNft      = "nft"
	FirewallIptables = "iptables"
)

// RulesFile keeps the loaded ruleset, so start can load it again when the table goes
const RulesFile = "/etc/bugnet/firewall.rules"

// checkedFile is touched at each check of the loaded table, root's alone to write
const checkedFile = "/run/bugnet/firewall.checked"

// Limits on the spec
const (
	MaxPools     = 10000
	maxRanges    = 1000
	maxMailPorts = 64
)

const (
	installTimeout = 60 * time.Second
	toolTimeout    = 30 * time.Second
	// checkEvery spaces the checks start runs before jobs
	checkEvery = time.Minute
)

type failure struct {
	reason string
	err    error
}

func (f *failure) Error() string { return f.reason + ": " + f.err.Error() }

func (f *failure) Unwrap() error { return f.err }

func fail(reason string, err error) error { return &failure{reason: reason, err: err} }

// hardener loads rulesets for one sandbox root through tools that tests replace
type hardener struct {
	root    sandbox.Root
	procDir string
	tools   tools
}

var system = hardener{root: sandbox.System, procDir: "/proc", tools: systemTools}

// Run is bugnet-run harden, printing one JSON line and exiting 1 on any error
func Run(args []string, stdout, stderr io.Writer) int {
	return system.main(context.Background(), args, stdout, stderr)
}

func (h hardener) main(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	res, err := h.run(ctx, args)
	status := 0
	if err != nil {
		reason := ErrFirewallUnavailable
		var f *failure
		if errors.As(err, &f) {
			reason = f.reason
		}
		res, status = Result{Error: reason}, 1
		_, _ = fmt.Fprintf(stderr, "bugnet-run harden: %v\n", err)
	}
	b, _ := json.Marshal(res)
	_, _ = stdout.Write(append(b, '\n'))
	return status
}

func (h hardener) run(ctx context.Context, args []string) (Result, error) {
	flags := flag.NewFlagSet("harden", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	specPath := flags.String("spec", "", "spec file, deleted once read")
	parseErr := flags.Parse(args)
	spec, specErr := Spec{}, errors.New("missing --spec")
	if *specPath != "" {
		spec, specErr = readSpec(*specPath)
	}
	switch {
	case parseErr != nil:
		return Result{}, fail(ErrBadSpec, parseErr)
	case flags.NArg() > 0:
		return Result{}, fail(ErrBadSpec, fmt.Errorf("unexpected argument %q", flags.Arg(0)))
	case specErr != nil:
		return Result{}, fail(ErrBadSpec, specErr)
	}
	if err := spec.check(); err != nil {
		return Result{}, fail(ErrBadSpec, err)
	}
	rs := h.rules(spec)
	// The install runs before the sandbox lock, so setup and egress apply never wait on apt
	if err := h.ensureTool(ctx); err != nil {
		return Result{}, fail(ErrFirewallUnavailable, err)
	}
	if err := makeDirs(h.root); err != nil {
		return Result{}, fail(ErrFirewallUnavailable, err)
	}
	unlock, err := sandbox.Lock(h.root)
	if err != nil {
		return Result{}, fail(ErrFirewallUnavailable, err)
	}
	defer unlock()
	backend, err := h.load(ctx, rs)
	if err != nil {
		return Result{}, fail(ErrFirewallUnavailable, err)
	}
	h.touch(time.Now())
	return Result{Firewall: backend}, nil
}

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
	if len(s.MailPorts) > maxMailPorts {
		return fmt.Errorf("mail_ports holds more than %d ports", maxMailPorts)
	}
	for i, p := range s.MailPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("mail_ports[%d] is not a port", i)
		}
	}
	if len(s.Pools) > MaxPools {
		return fmt.Errorf("pools holds %d entries, more than %d", len(s.Pools), MaxPools)
	}
	for _, list := range []struct {
		name    string
		entries []string
		max     int
	}{{"deny_ranges", s.DenyRanges, maxRanges}, {"pools", s.Pools, MaxPools},
		{"allow", s.Allow, maxRanges}} {
		if len(list.entries) > list.max {
			return fmt.Errorf("%s holds more than %d entries", list.name, list.max)
		}
		for i, e := range list.entries {
			if _, err := parsePrefix(e); err != nil {
				return fmt.Errorf("%s[%d] is not an address or CIDR", list.name, i)
			}
		}
	}
	return nil
}

func makeDirs(root sandbox.Root) error {
	for _, dir := range []string{sandbox.EtcDir, sandbox.RunDir} {
		if err := os.MkdirAll(root.Path(dir), 0o755); err != nil {
			return err
		}
	}
	return nil
}

/* Rechecks before jobs */

// Due reports whether a ruleset was loaded here and its table was last checked a minute ago
func Due(root sandbox.Root, now time.Time) bool {
	if _, err := os.Stat(root.Path(RulesFile)); err != nil {
		return false
	}
	info, err := os.Stat(root.Path(checkedFile))
	if err != nil {
		return true
	}
	age := now.Sub(info.ModTime())
	return age < 0 || age >= checkEvery
}

// Recheck loads the kept ruleset again when its table is gone, reporting whether it did
func Recheck(ctx context.Context, root sandbox.Root, now time.Time) (bool, error) {
	h := system
	h.root = root
	return h.recheck(ctx, now)
}

func (h hardener) recheck(ctx context.Context, now time.Time) (bool, error) {
	b, err := os.ReadFile(h.root.Path(RulesFile))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	h.touch(now)
	kept, err := parseKept(b)
	if err != nil {
		return false, err
	}
	if h.present(ctx, kept) {
		return false, nil
	}
	return true, h.loadKept(ctx, kept, h.root.Path(RulesFile))
}

// touch records a check, which only spaces the next one, so a failed write changes nothing else
func (h hardener) touch(now time.Time) {
	path := h.root.Path(checkedFile)
	// A boot empties /run, and with it the run directory
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	if err := os.WriteFile(path, nil, 0o644); err == nil {
		_ = os.Chtimes(path, now, now)
	}
}
