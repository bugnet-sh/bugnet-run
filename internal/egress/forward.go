// Package egress maps a sandbox's secret hosts to the forwarder, which tunnels them to the proxy
package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bugnet-sh/bugnet-run/internal/sandbox"
	"github.com/bugnet-sh/bugnet-run/internal/wsframe"
)

const (
	// ListenIP is the only address the forwarder listens on in a sandbox
	ListenIP = "127.77.0.1"
	// TunnelPath is the egress proxy's tunnel route
	TunnelPath = "/v1/tunnel"
	// ProtocolTunnel is the tunnel's WebSocket subprotocol
	ProtocolTunnel = "bugnet-tunnel.v1"
	// MaxConns caps connections at once, and the next one waits for a slot
	MaxConns = 64
)

const (
	dialTimeout      = 5 * time.Second
	handshakeTimeout = 10 * time.Second
	firstRetry       = time.Second
	acceptBackoff    = 100 * time.Millisecond
	statsEvery       = time.Minute
	maxIPs           = 16
	maxHosts         = 64
)

// addrFile holds the address a forwarder under a test root got, since its port may be 0
const addrFile = sandbox.RunDir + "/forward.addr"

// Config is egress.json, whose paths are sandbox paths mapped through the root
type Config struct {
	Endpoint  string   `json:"endpoint"`
	IPs       []string `json:"ips"`
	Port      int      `json:"port"`
	Listen    string   `json:"listen"`
	TokenFile string   `json:"token_file"`
	Hosts     []string `json:"hosts"`
	// RootsFile replaces the system roots, and only a run under a test root may set it
	RootsFile string `json:"roots_file"`
	// Family limits dials to the pinned IPs of "ipv4" or "ipv6", every pinned IP when empty
	Family string `json:"family,omitempty"`
	// Bind is the local address each dial starts from, the kernel's choice when empty
	Bind string `json:"bind,omitempty"`
}

// LoadConfig reads egress.json, refusing unknown fields and any listen address but ListenIP
func LoadConfig(path string, root sandbox.Root) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("egress config %s: %w", path, err)
	}
	if err := c.check(root); err != nil {
		return c, fmt.Errorf("egress config %s: %w", path, err)
	}
	return c, nil
}

// check names a bad field without quoting hosts, so the error is safe to log
func (c Config) check(root sandbox.Root) error {
	if !validHost(c.Endpoint) {
		return errors.New("endpoint is not a host name")
	}
	if err := checkIPs(c.IPs); err != nil {
		return err
	}
	if err := c.checkSource(); err != nil {
		return err
	}
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("port is not 1 to 65535")
	}
	if err := checkListen(c.Listen, !root.IsSystem()); err != nil {
		return err
	}
	if c.TokenFile == "" {
		return errors.New("token_file is empty")
	}
	if c.RootsFile != "" && root.IsSystem() {
		return errors.New("roots_file is only for runs under a test root")
	}
	return checkHosts(c.Hosts)
}

// Family names of Config.Family
const (
	FamilyIPv4 = "ipv4"
	FamilyIPv6 = "ipv6"
)

// inFamily reports whether a belongs to family, reading an IPv4-mapped address as IPv4
func inFamily(a netip.Addr, family string) bool {
	switch a = a.Unmap(); family {
	case FamilyIPv4:
		return a.Is4()
	case FamilyIPv6:
		return a.Is6()
	}
	return false
}

// checkSource refuses an unknown family, a bind of the other family and a family no IP has
func (c Config) checkSource() error {
	if c.Family == "" {
		if c.Bind != "" {
			return errors.New("bind needs a family")
		}
		return nil
	}
	if c.Family != FamilyIPv4 && c.Family != FamilyIPv6 {
		return errors.New("family is neither ipv4 nor ipv6")
	}
	if c.Bind != "" {
		if a, err := netip.ParseAddr(c.Bind); err != nil || a.Zone() != "" ||
			!inFamily(a, c.Family) {
			return errors.New("bind is not an address of the family")
		}
	}
	for _, ip := range c.IPs {
		if a, err := netip.ParseAddr(ip); err == nil && inFamily(a, c.Family) {
			return nil
		}
	}
	return errors.New("no pinned ip is in the family")
}

func checkIPs(ips []string) error {
	if len(ips) == 0 || len(ips) > maxIPs {
		return fmt.Errorf("ips holds %d addresses, want 1 to %d", len(ips), maxIPs)
	}
	for i, ip := range ips {
		if a, err := netip.ParseAddr(ip); err != nil || a.Zone() != "" {
			return fmt.Errorf("ips[%d] is not an address", i)
		}
	}
	return nil
}

// checkListen keeps the forwarder off 127.0.0.1 and ::1, which envd on E2B publishes
func checkListen(listen string, testRoot bool) error {
	host, port, err := net.SplitHostPort(listen)
	p, perr := strconv.Atoi(port)
	switch {
	case err != nil || perr != nil || p < 0 || p > 65535:
	case host == ListenIP && p > 0:
		return nil
	case testRoot && host == "127.0.0.1":
		return nil
	}
	return fmt.Errorf("listen is not %s with a port", ListenIP)
}

func checkHosts(hosts []string) error {
	if len(hosts) > maxHosts {
		return fmt.Errorf("hosts holds %d names, more than %d", len(hosts), maxHosts)
	}
	seen := map[string]bool{}
	for i, h := range hosts {
		if !validHost(h) {
			return fmt.Errorf("hosts[%d] is not a lower-case host name", i)
		}
		if seen[h] {
			return fmt.Errorf("hosts[%d] repeats an earlier name", i)
		}
		seen[h] = true
	}
	return nil
}

// validHost accepts lower-case names of two or more letter, digit and hyphen labels
func validHost(name string) bool {
	if len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		if strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return false
		}
	}
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}

// validToken accepts bnt_ and the base64url form of 32 bytes
func validToken(token string) bool {
	body, ok := strings.CutPrefix(token, "bnt_")
	b, err := base64.RawURLEncoding.Strict().DecodeString(body)
	return ok && err == nil && len(body) == 43 && len(b) == 32
}

/* Forwarder */

// Forwarder relays each local connection through its own tunnel to the egress proxy
type Forwarder struct {
	root   sandbox.Root
	path   string
	logger *log.Logger
	every  time.Duration
	// speakWithin is how long a new client may stay silent before it gives its slot back
	speakWithin time.Duration
	// handshakeWithin bounds the proxy's TLS handshake and upgrade, so a stalled one frees its slot
	handshakeWithin time.Duration

	mu  sync.Mutex
	cur *target

	slots    chan struct{}
	dialed   atomic.Bool
	accepted atomic.Int64
	active   atomic.Int64
	failed   atomic.Int64
	// bindMissing counts dials that fell back to the kernel's address
	bindMissing atomic.Int64
}

// target is what one tunnel dials, read once per connection so a reload never changes it midway
type target struct {
	cfg   Config
	token string
	roots *x509.CertPool
}

// NewForwarder loads the config at path, whose token and roots files map through root
func NewForwarder(root sandbox.Root, path string, logger *log.Logger) (*Forwarder, error) {
	t, err := loadTarget(root, path)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Forwarder{
		root: root, path: path, logger: logger, every: statsEvery, speakWithin: handshakeTimeout,
		handshakeWithin: handshakeTimeout, cur: t, slots: make(chan struct{}, MaxConns),
	}, nil
}

func loadTarget(root sandbox.Root, path string) (*target, error) {
	cfg, err := LoadConfig(path, root)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(root.Path(cfg.TokenFile))
	if err != nil {
		return nil, err
	}
	token := strings.TrimSpace(string(b))
	if !validToken(token) {
		return nil, fmt.Errorf("%s holds no tunnel token", cfg.TokenFile)
	}
	t := &target{cfg: cfg, token: token}
	if cfg.RootsFile != "" {
		b, err := os.ReadFile(root.Path(cfg.RootsFile))
		if err != nil {
			return nil, err
		}
		t.roots = x509.NewCertPool()
		if !t.roots.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("%s holds no certificate", cfg.RootsFile)
		}
	}
	return t, nil
}

func (f *Forwarder) target() *target {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cur
}

// Listen returns the listen address the loaded config names
func (f *Forwarder) Listen() string { return f.target().cfg.Listen }

// Hosts returns how many secret hosts the loaded config maps
func (f *Forwarder) Hosts() int { return len(f.target().cfg.Hosts) }

// Reload reads the config and token again for new connections, keeping open ones as they are
func (f *Forwarder) Reload() error {
	t, err := loadTarget(f.root, f.path)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.cur = t
	f.mu.Unlock()
	return nil
}

// Serve relays connections from ln until ctx ends, then closes the open ones
func (f *Forwarder) Serve(ctx context.Context, ln net.Listener) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	wg.Go(func() { f.report(ctx) })
	for {
		// A connection past the cap waits in the kernel's queue until a slot frees
		select {
		case f.slots <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		c, err := ln.Accept()
		if err != nil {
			<-f.slots
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			select {
			case <-time.After(acceptBackoff):
			case <-ctx.Done():
				return nil
			}
			continue
		}
		f.accepted.Add(1)
		wg.Go(func() {
			defer func() { <-f.slots }()
			f.relay(ctx, c)
		})
	}
}

func (f *Forwarder) relay(ctx context.Context, c net.Conn) {
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	br := bufio.NewReader(c)
	// A client that never speaks opens no tunnel, so a listen check costs the proxy nothing
	_ = c.SetReadDeadline(time.Now().Add(f.speakWithin))
	if _, err := br.Peek(1); err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	ws, err := f.connect(ctx)
	if err != nil {
		f.failed.Add(1)
		return
	}
	f.active.Add(1)
	defer f.active.Add(-1)
	stopWS := context.AfterFunc(ctx, func() { _ = ws.Close() })
	defer stopWS()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(c, ws)
		_ = c.Close()
		close(done)
	}()
	_, _ = io.Copy(ws, br)
	_ = ws.Close()
	<-done
}

// connect retries the first dial after start once, since Boat's first outbound one can fail
func (f *Forwarder) connect(ctx context.Context) (*wsframe.Conn, error) {
	first := !f.dialed.Swap(true)
	ws, err := f.target().tunnel(ctx, f.handshakeWithin, &f.bindMissing)
	if err == nil || !first || !retryable(err) {
		return ws, err
	}
	select {
	case <-time.After(firstRetry):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return f.target().tunnel(ctx, f.handshakeWithin, &f.bindMissing)
}

// retryable is false once the proxy answered or showed a certificate that will not change
func retryable(err error) bool {
	var up *wsframe.UpgradeError
	var cert *tls.CertificateVerificationError
	return !errors.As(err, &up) && !errors.As(err, &cert)
}

// tunnel tries the pinned addresses in order until one answers the upgrade
func (t *target) tunnel(ctx context.Context, within time.Duration,
	missing *atomic.Int64) (*wsframe.Conn, error) {
	var errs []error
	for _, ip := range t.cfg.IPs {
		if t.cfg.Family != "" {
			if a, err := netip.ParseAddr(ip); err != nil || !inFamily(a, t.cfg.Family) {
				continue
			}
		}
		ws, err := t.via(ctx, ip, within, missing)
		if err == nil {
			return ws, nil
		}
		var up *wsframe.UpgradeError
		if errors.As(err, &up) {
			return nil, err
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (t *target) via(ctx context.Context, ip string, within time.Duration,
	missing *atomic.Int64) (*wsframe.Conn, error) {
	raw, err := t.dial(ctx, ip, missing)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{
		ServerName: t.cfg.Endpoint, RootCAs: t.roots, MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	_ = tc.SetDeadline(time.Now().Add(within))
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	ws, err := wsframe.Handshake(tc, t.cfg.Endpoint, TunnelPath, ProtocolTunnel,
		http.Header{"Authorization": {"Bearer " + t.token}})
	if err != nil {
		_ = tc.Close()
		return nil, err
	}
	_ = tc.SetDeadline(time.Time{})
	return ws, nil
}

// dial starts from Bind when set, and once more from the kernel's address when no interface
// holds it, since the address may have moved before the router noticed
func (t *target) dial(ctx context.Context, ip string, missing *atomic.Int64) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	addr := net.JoinHostPort(ip, strconv.Itoa(t.cfg.Port))
	if t.cfg.Bind != "" {
		if b, err := netip.ParseAddr(t.cfg.Bind); err == nil {
			d.LocalAddr = &net.TCPAddr{IP: b.Unmap().AsSlice()}
			c, err := d.DialContext(ctx, "tcp", addr)
			if !errors.Is(err, syscall.EADDRNOTAVAIL) {
				return c, err
			}
			missing.Add(1)
			d.LocalAddr = nil
		}
	}
	return d.DialContext(ctx, "tcp", addr)
}

// report logs counts only, never hosts, addresses or bytes
func (f *Forwarder) report(ctx context.Context) {
	tick := time.NewTicker(f.every)
	defer tick.Stop()
	var last [4]int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		now := [4]int64{f.accepted.Load(), f.active.Load(), f.failed.Load(),
			f.bindMissing.Load()}
		if now != last {
			f.logger.Printf("connections %d, open %d, failed %d, bind_missing %d",
				now[0], now[1], now[2], now[3])
			last = now
		}
	}
}

/* Command */

// Forward is bugnet-run forward, relaying until SIGTERM and reloading its config on SIGHUP
func Forward(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("forward", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "egress.json, /etc/bugnet/egress.json under the root")
	rootDir := flags.String("root", "/", "directory standing for the sandbox's /")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 {
		_, _ = fmt.Fprintln(stderr,
			"bugnet-run forward: usage: forward --config FILE [--root DIR]")
		return 2
	}
	logger := log.New(stderr, "bugnet-run forward: ", 0)
	root, err := sandbox.NewRoot(*rootDir)
	if err != nil {
		logger.Print(err)
		return 1
	}
	if *configPath == "" {
		*configPath = root.Path(sandbox.EgressConfig)
	}
	f, err := NewForwarder(root, *configPath, logger)
	if err != nil {
		logger.Print(err)
		return 1
	}
	// SIGHUP is caught before the pid file exists, so a reload never ends the process
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	ln, err := net.Listen("tcp", f.Listen())
	if err != nil {
		logger.Print(err)
		return 1
	}
	if err := writeRunFiles(root, ln.Addr().String()); err != nil {
		_ = ln.Close()
		logger.Print(err)
		return 1
	}
	defer removeRunFiles(root)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
			}
			if err := f.Reload(); err != nil {
				logger.Print("reload refused, keeping the last config")
				continue
			}
			logger.Printf("reloaded, %d hosts", f.Hosts())
		}
	}()
	logger.Printf("listening, %d hosts", f.Hosts())
	if err := f.Serve(ctx, ln); err != nil {
		logger.Print(err)
		return 1
	}
	return 0
}

// writeRunFiles records the forwarder once it listens, its address first under a test root
func writeRunFiles(root sandbox.Root, addr string) error {
	if !root.IsSystem() {
		if _, err := sandbox.WriteFile(root.Path(addrFile), []byte(addr+"\n"), 0o644); err != nil {
			return err
		}
	}
	return sandbox.WritePidFile(root, sandbox.Forward.Name, os.Getpid())
}

func removeRunFiles(root sandbox.Root) {
	pid := os.Getpid()
	if got, err := sandbox.ReadPidFile(root, sandbox.Forward.Name); err == nil && got == pid {
		sandbox.RemovePidFile(root, sandbox.Forward.Name, pid)
		if !root.IsSystem() {
			_ = os.Remove(root.Path(addrFile))
		}
	}
}
