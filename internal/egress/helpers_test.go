package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/bugnet-sh/bugnet-run/internal/sandbox"
	"github.com/bugnet-sh/bugnet-run/internal/wsframe"
)

const testEndpoint = "egress.test.example"

// rootsFile is where tests put the tunnel server's CA, a sandbox path under the test root
const rootsFile = "/etc/bugnet/test-roots.pem"

var (
	testToken  = "bnt_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	otherToken = "bnt_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	binPath    string
)

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	dir, err := os.MkdirTemp("", "bugnet-run-egress-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()
	binPath = filepath.Join(dir, "bugnet-run")
	build := exec.Command("go", "build", "-o", binPath,
		"github.com/bugnet-sh/bugnet-run/cmd/bugnet-run")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build bugnet-run: %v\n%s", err, out)
		return 1
	}
	// One run pays macOS's check of a new binary, which can take seconds, before a test times it
	_ = exec.Command(binPath).Run()
	executable = func() (string, error) { return binPath, nil }
	rootsForTests = rootsFile
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

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Dir(path), 0o755))
	must(t, os.WriteFile(path, []byte(content), 0o644))
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	must(t, err)
	return string(b)
}

func testRoot(t *testing.T) sandbox.Root {
	t.Helper()
	r, err := sandbox.NewRoot(t.TempDir())
	must(t, err)
	return r
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

func gone(pid int) bool {
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}

// syncBuffer is a bytes.Buffer that a logger and a test may share
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

/* Certificates */

type pki struct {
	pem  []byte
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial atomic.Int64

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(t, err)
	cert, err := x509.ParseCertificate(der)
	must(t, err)
	return &pki{pem: certPEM(der), cert: cert, key: key}
}

// leaf returns a server certificate for name signed by the CA
func (p *pki) leaf(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	must(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

/* Tunnel server */

// tunnelServer stands in for the egress proxy, echoing each tunnel's bytes back
type tunnelServer struct {
	port    int
	accepts atomic.Int64
	drop    atomic.Int64
	open    atomic.Int64
	// status, when set, is the proxy's answer instead of the upgrade
	status atomic.Int64
	// hold keeps each new connection open without a TLS answer
	hold atomic.Bool
	// stall leaves each upgrade unanswered until the client hangs up, or for 10 s
	stall atomic.Bool
	mu    sync.Mutex
	reqs  []*http.Request
	srcs  []string
}

func newTunnelServer(t *testing.T, p *pki, name string) *tunnelServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	return serveTunnel(t, p, name, ln)
}

// serveTunnel answers tunnels on ln with a certificate for name
func serveTunnel(t *testing.T, p *pki, name string, ln net.Listener) *tunnelServer {
	t.Helper()
	s := &tunnelServer{}
	srv := httptest.NewUnstartedServer(s)
	_ = srv.Listener.Close()
	srv.Listener = dropListener{Listener: ln, s: s}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{p.leaf(t, name)}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.port = srv.Listener.Addr().(*net.TCPAddr).Port
	return s
}

func (s *tunnelServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.reqs = append(s.reqs, r.Clone(context.Background()))
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	s.srcs = append(s.srcs, host)
	s.mu.Unlock()
	if s.stall.Load() {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
		return
	}
	if code := s.status.Load(); code != 0 {
		w.WriteHeader(int(code))
		return
	}
	if r.URL.Path != TunnelPath || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	c, err := wsframe.Accept(w, r, ProtocolTunnel)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.open.Add(1)
	defer s.open.Add(-1)
	_, _ = io.Copy(c, c)
	_ = c.Close()
}

func (s *tunnelServer) requests() []*http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*http.Request(nil), s.reqs...)
}

// sources returns the client address of each upgrade request
func (s *tunnelServer) sources() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.srcs...)
}

// dropListener closes the first drop connections before any TLS, and keeps them silent under hold
type dropListener struct {
	net.Listener
	s *tunnelServer
}

func (l dropListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.s.accepts.Add(1)
		if n := l.s.drop.Load(); n > 0 && l.s.drop.CompareAndSwap(n, n-1) {
			_ = c.Close()
			continue
		}
		if l.s.hold.Load() {
			go func() { _, _ = io.Copy(io.Discard, c); _ = c.Close() }()
			continue
		}
		return c, nil
	}
}

// sharedPort listens on one port of 127.0.0.1 and of a second loopback address
func sharedPort(t *testing.T) (first, second net.Listener) {
	t.Helper()
	for range 20 {
		first, err := net.Listen("tcp", "127.0.0.1:0")
		must(t, err)
		port := strconv.Itoa(first.Addr().(*net.TCPAddr).Port)
		for _, ip := range []string{"::1", "127.0.0.2"} {
			if second, err := net.Listen("tcp", net.JoinHostPort(ip, port)); err == nil {
				return first, second
			}
		}
		_ = first.Close()
	}
	t.Skip("no second loopback address has the port 127.0.0.1 got free")
	return nil, nil
}

/* Forwarder in this process */

func testConfig(s *tunnelServer) Config {
	return Config{
		Endpoint: testEndpoint, IPs: []string{"127.0.0.1"}, Port: s.port,
		Listen: "127.0.0.1:0", TokenFile: sandbox.EgressToken, Hosts: []string{"huggingface.co"},
		RootsFile: rootsFile,
	}
}

// writeForwarderFiles puts egress.json, the token and the test roots under root
func writeForwarderFiles(t *testing.T, root sandbox.Root, p *pki, cfg Config, token string) {
	t.Helper()
	b, err := json.Marshal(cfg)
	must(t, err)
	writeFile(t, root.Path(sandbox.EgressConfig), string(b)+"\n")
	writeFile(t, root.Path(sandbox.EgressToken), token+"\n")
	writeFile(t, root.Path(rootsFile), string(p.pem))
}

type running struct {
	f    *Forwarder
	addr string
	root sandbox.Root
	logs *syncBuffer
}

func startForwarder(t *testing.T, p *pki, cfg Config, token string,
	tune ...func(*Forwarder)) *running {
	t.Helper()
	root := testRoot(t)
	writeForwarderFiles(t, root, p, cfg, token)
	logs := &syncBuffer{}
	f, err := NewForwarder(root, root.Path(sandbox.EgressConfig), log.New(logs, "", 0))
	must(t, err)
	for _, fn := range tune {
		fn(f)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return &running{f: f, addr: ln.Addr().String(), root: root, logs: logs}
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	must(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// roundTrip sends msg through c and returns what came back
func roundTrip(t *testing.T, c net.Conn, msg string) string {
	t.Helper()
	must(t, c.SetDeadline(time.Now().Add(10*time.Second)))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	_, err := io.WriteString(c, msg)
	must(t, err)
	got := make([]byte, len(msg))
	_, err = io.ReadFull(c, got)
	must(t, err)
	return string(got)
}

// closedSoon reports whether the peer closes c within d of sending msg
func closedSoon(t *testing.T, c net.Conn, msg string, d time.Duration) bool {
	t.Helper()
	must(t, c.SetDeadline(time.Now().Add(d)))
	_, _ = io.WriteString(c, msg)
	_, err := bufio.NewReader(c).ReadByte()
	var ne net.Error
	timedOut := errors.As(err, &ne) && ne.Timeout()
	return err != nil && !timedOut
}
