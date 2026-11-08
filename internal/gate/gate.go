// Package gate is the reverse proxy in front of a sandbox's ports that only the edges can pass
package gate

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bugnet-sh/bugnet-run/internal/sandbox"
	"github.com/bugnet-sh/bugnet-run/internal/wsframe"
)

// Request headers the edges send
const (
	HeaderKey      = "Bugnet-Gate"
	HeaderPort     = "Bugnet-Port"
	HeaderHost     = "Bugnet-Host"
	HeaderClientIP = "Bugnet-Client-Ip"
)

// Response headers the gate sets
const (
	HeaderResponse     = "Bugnet-Gate-Response"
	HeaderError        = "Bugnet-Gate-Error"
	HeaderVersion      = "Bugnet-Gate-Version"
	HeaderCacheControl = "Bugnet-Cache-Control"
	HeaderServer       = "Bugnet-Server"
)

// Values of Bugnet-Gate-Error
const (
	ErrPortClosed  = "port_closed"
	ErrBusy        = "busy"
	ErrSSHNotReady = "ssh_not_ready"
)

// Control paths, answered only without Bugnet-Port
const (
	PathHealth = "/__bugnet/health"
	PathPort   = "/__bugnet/port/"
	PathSSH    = "/__bugnet/ssh"
)

const (
	// ProtocolSSH is the WebSocket subprotocol of the SSH path
	ProtocolSSH = "bugnet-ssh.v1"
	// Version is the value of Bugnet-Gate-Version
	Version = "1"
	// DefaultPort is the gate's port on every provider but local
	DefaultPort = 29417
	// MaxInFlight caps requests at once, SSH tunnels aside
	MaxInFlight = 256
	// MaxTunnels caps SSH tunnels at once
	MaxTunnels = 16
)

const (
	dialTimeout   = 5 * time.Second
	headerTimeout = time.Minute
	idleTimeout   = 10 * time.Minute
)

var errPortClosed = errors.New("nothing accepts on the port")

// Config is gate.json, whose paths are sandbox paths mapped through the root
type Config struct {
	Listen      string `json:"listen"`
	KeyFile     string `json:"key_file"`
	Deny        []int  `json:"deny"`
	SSHPortFile string `json:"ssh_port_file"`
}

// LoadConfig reads gate.json, refusing unknown fields
func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("gate config %s: %w", path, err)
	}
	if _, err := ListenPort(c.Listen); err != nil {
		return c, err
	}
	if c.KeyFile == "" {
		return c, fmt.Errorf("gate config %s names no key file", path)
	}
	for _, p := range c.Deny {
		if p < 1 || p > 65535 {
			return c, fmt.Errorf("gate config %s denies port %d", path, p)
		}
	}
	return c, nil
}

// ListenPort returns the port of a host:port listen address, refusing port 0
func ListenPort(listen string) (int, error) {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 0, fmt.Errorf("listen address %q: %w", listen, err)
	}
	p, ok := parsePort(port)
	if !ok {
		return 0, fmt.Errorf("listen address %q has no usable port", listen)
	}
	return p, nil
}

// ValidKey reports whether key is the base64url form of 32 bytes, 43 characters
func ValidKey(key string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(key)
	return err == nil && len(key) == 43 && len(b) == 32
}

func parsePort(s string) (int, bool) {
	if s == "" || strings.TrimLeft(s, "0123456789") != "" || len(s) > 5 {
		return 0, false
	}
	p, err := strconv.Atoi(s)
	return p, err == nil && p >= 1 && p <= 65535
}

// Gate answers the edges for one sandbox, holding its key and nothing else
type Gate struct {
	key         []byte
	deny        map[int]bool
	self        atomic.Int32
	root        sandbox.Root
	sshPortFile string
	proxy       *httputil.ReverseProxy
	slots       chan struct{}
	tunnels     chan struct{}
	// headerTimeout and idleTimeout bound only silent connections, so tests may shorten them
	headerTimeout time.Duration
	idleTimeout   time.Duration
}

type portKey struct{}

// New builds the gate for cfg, reading its key file through root
func New(cfg Config, root sandbox.Root) (*Gate, error) {
	b, err := os.ReadFile(root.Path(cfg.KeyFile))
	if err != nil {
		return nil, err
	}
	key := strings.TrimSpace(string(b))
	if !ValidKey(key) {
		return nil, fmt.Errorf("gate key file %s holds no valid key", cfg.KeyFile)
	}
	g := &Gate{
		key: []byte(key), deny: map[int]bool{}, root: root, sshPortFile: cfg.SSHPortFile,
		slots: make(chan struct{}, MaxInFlight), tunnels: make(chan struct{}, MaxTunnels),
		headerTimeout: headerTimeout, idleTimeout: idleTimeout,
	}
	for _, p := range cfg.Deny {
		g.deny[p] = true
	}
	if p, err := ListenPort(cfg.Listen); err == nil {
		g.self.Store(int32(p))
	}
	g.proxy = &httputil.ReverseProxy{
		Rewrite:        rewrite,
		ModifyResponse: modifyResponse,
		ErrorHandler:   proxyError,
		ErrorLog:       log.New(io.Discard, "", 0),
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				return dialLoopback(ctx, port)
			},
			DisableCompression:  true,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	return g, nil
}

// Serve answers connections on ln until ctx ends
func (g *Gate) Serve(ctx context.Context, ln net.Listener) error {
	if addr, ok := ln.Addr().(*net.TCPAddr); ok {
		g.self.Store(int32(addr.Port))
	}
	// Header and idle limits only bound silent connections, never a request in progress
	srv := &http.Server{
		Handler: g, ReadHeaderTimeout: g.headerTimeout, IdleTimeout: g.idleTimeout,
		ErrorLog: log.New(io.Discard, "", 0),
	}
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ServeHTTP marks every answer as the gate's and refuses any request without the key
func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(HeaderResponse, "1")
	if subtle.ConstantTimeCompare([]byte(r.Header.Get(HeaderKey)), g.key) != 1 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.URL.Path == PathSSH && len(r.Header.Values(HeaderPort)) == 0 {
		g.ssh(w, r)
		return
	}
	if !take(g.slots) {
		busy(w)
		return
	}
	defer func() { <-g.slots }()
	if v := r.Header.Values(HeaderPort); len(v) > 0 {
		g.app(w, r, v[0])
		return
	}
	g.control(w, r)
}

func (g *Gate) app(w http.ResponseWriter, r *http.Request, value string) {
	port, ok := parsePort(value)
	if !ok || g.deny[port] || port == int(g.self.Load()) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// ReverseProxy clears w's headers after relaying a 1xx, so the answer itself carries the mark
	w.Header().Del(HeaderResponse)
	g.proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), portKey{}, port)))
}

func (g *Gate) control(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch {
	case r.URL.Path == PathHealth:
		w.Header().Set(HeaderVersion, Version)
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(r.URL.Path, PathPort):
		port, ok := parsePort(strings.TrimPrefix(r.URL.Path, PathPort))
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		c, err := dialLoopback(r.Context(), strconv.Itoa(port))
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = c.Close()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// ssh relays one WebSocket to the sshd whose port ssh-up wrote, under its own cap
func (g *Gate) ssh(w http.ResponseWriter, r *http.Request) {
	port, ok := g.sshPort()
	if !ok {
		w.Header().Set(HeaderError, ErrSSHNotReady)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodGet || wsframe.Check(r, ProtocolSSH) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !take(g.tunnels) {
		busy(w)
		return
	}
	defer func() { <-g.tunnels }()
	up, err := dialLoopback(r.Context(), strconv.Itoa(port))
	if err != nil {
		w.Header().Set(HeaderError, ErrPortClosed)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer func() { _ = up.Close() }()
	ws, err := wsframe.Accept(w, r, ProtocolSSH)
	if err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(up, ws)
		_ = up.Close()
		close(done)
	}()
	_, _ = io.Copy(ws, up)
	_ = ws.Close()
	<-done
}

func (g *Gate) sshPort() (int, bool) {
	if g.sshPortFile == "" {
		return 0, false
	}
	b, err := os.ReadFile(g.root.Path(g.sshPortFile))
	if err != nil {
		return 0, false
	}
	return parsePort(strings.TrimSpace(string(b)))
}

func take(slots chan struct{}) bool {
	select {
	case slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func busy(w http.ResponseWriter) {
	w.Header().Set(HeaderError, ErrBusy)
	w.WriteHeader(http.StatusServiceUnavailable)
}

// dialLoopback tries IPv4 loopback first, then IPv6, where many dev servers listen alone
func dialLoopback(ctx context.Context, port string) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	c, err4 := d.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", port))
	if err4 == nil {
		return c, nil
	}
	c, err6 := d.DialContext(ctx, "tcp6", net.JoinHostPort("::1", port))
	if err6 == nil {
		return c, nil
	}
	return nil, fmt.Errorf("%w: %w", errPortClosed, errors.Join(err4, err6))
}

/* Proxy rewriting */

func rewrite(pr *httputil.ProxyRequest) {
	port, _ := pr.In.Context().Value(portKey{}).(int)
	pr.Out.URL.Scheme = "http"
	pr.Out.URL.Host = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	// ReverseProxy re-encodes a query it cannot parse, and the app must see the visitor's bytes
	pr.Out.URL.RawQuery = pr.In.URL.RawQuery
	in := pr.In.Header
	if host := in.Get(HeaderHost); host != "" {
		pr.Out.Host = host
		pr.Out.Header.Set("X-Forwarded-Host", host)
	}
	pr.Out.Header.Set("X-Forwarded-Proto", "https")
	if ip, err := netip.ParseAddr(in.Get(HeaderClientIP)); err == nil {
		pr.Out.Header.Set("X-Forwarded-For", ip.String())
	}
	for name := range pr.Out.Header {
		l := strings.ToLower(name)
		if strings.HasPrefix(l, "bugnet-") || strings.HasPrefix(l, "e2b-") ||
			l == "x-routing-key" {
			delete(pr.Out.Header, name)
		}
	}
	dropCookie(pr.Out.Header, "_port_auth")
}

// dropCookie removes one cookie from every Cookie line, leaving other lines as they came
func dropCookie(h http.Header, name string) {
	lines := h.Values("Cookie")
	if len(lines) == 0 {
		return
	}
	var kept []string
	for _, line := range lines {
		var pairs []string
		found := false
		for pair := range strings.SplitSeq(line, ";") {
			pair = strings.TrimSpace(pair)
			n, _, _ := strings.Cut(pair, "=")
			if strings.TrimSpace(n) == name {
				found = true
				continue
			}
			if pair != "" {
				pairs = append(pairs, pair)
			}
		}
		switch {
		case !found:
			kept = append(kept, line)
		case len(pairs) > 0:
			kept = append(kept, strings.Join(pairs, "; "))
		}
	}
	h.Del("Cookie")
	for _, line := range kept {
		h.Add("Cookie", line)
	}
}

// modifyResponse keeps provider caches and proxies from storing or rewriting the app's answer
func modifyResponse(res *http.Response) error {
	for name := range res.Header {
		if strings.HasPrefix(strings.ToLower(name), "bugnet-") {
			delete(res.Header, name)
		}
	}
	move(res.Header, "Cache-Control", HeaderCacheControl)
	res.Header.Set("Cache-Control", "private")
	move(res.Header, "Server", HeaderServer)
	res.Header.Set(HeaderResponse, "1")
	return nil
}

func move(h http.Header, from, to string) {
	v := strings.Join(h.Values(from), ", ")
	if v == "" {
		v = "-"
	}
	h.Del(from)
	h.Set(to, v)
}

func proxyError(w http.ResponseWriter, _ *http.Request, err error) {
	w.Header().Set(HeaderResponse, "1")
	if errors.Is(err, errPortClosed) {
		w.Header().Set(HeaderError, ErrPortClosed)
	}
	w.WriteHeader(http.StatusBadGateway)
}

/* Command */

// Run is bugnet-run gate, serving until SIGTERM
func Run(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("gate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "gate.json, /etc/bugnet/gate.json under the root")
	rootDir := flags.String("root", "/", "directory standing for the sandbox's /")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 {
		_, _ = fmt.Fprintln(stderr, "bugnet-run gate: usage: gate --config FILE [--root DIR]")
		return 2
	}
	root, err := sandbox.NewRoot(*rootDir)
	if err != nil {
		return fatal(stderr, err)
	}
	if *configPath == "" {
		*configPath = root.Path(sandbox.GateConfig)
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return fatal(stderr, err)
	}
	g, err := New(cfg, root)
	if err != nil {
		return fatal(stderr, err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fatal(stderr, err)
	}
	pid := os.Getpid()
	if err := sandbox.WritePidFile(root, sandbox.Gate.Name, pid); err != nil {
		_ = ln.Close()
		return fatal(stderr, err)
	}
	defer sandbox.RemovePidFile(root, sandbox.Gate.Name, pid)
	signal.Ignore(syscall.SIGHUP)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := g.Serve(ctx, ln); err != nil {
		return fatal(stderr, err)
	}
	return 0
}

func fatal(stderr io.Writer, err error) int {
	_, _ = fmt.Fprintf(stderr, "bugnet-run gate: %v\n", err)
	return 1
}

/* Probes */

// Healthy checks that a gate holding key answers its health route at addr
func Healthy(ctx context.Context, addr, key string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+PathHealth, nil)
	if err != nil {
		return err
	}
	req.Header.Set(HeaderKey, key)
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	res, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return err
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent || res.Header.Get(HeaderResponse) != "1" {
		return fmt.Errorf("gate health at %s answered %d", addr, res.StatusCode)
	}
	return nil
}

// ProbeAddr returns the loopback address that reaches a gate listening on listen
func ProbeAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return net.JoinHostPort(host, port)
}
