package gate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bugnet-sh/bugnet-run/internal/sandbox"
	"github.com/bugnet-sh/bugnet-run/internal/wsframe"
)

var (
	testKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	// otherKey is a valid key of the same length that is not the gate's
	otherKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
)

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
	must(t, os.WriteFile(path, []byte(content), 0o600))
}

type testGate struct {
	addr string
	port int
	root sandbox.Root
	gate *Gate
}

// startGate serves a gate on a free loopback port with the production deny list, tuned first
func startGate(t *testing.T, tune ...func(*Gate)) *testGate {
	t.Helper()
	root, err := sandbox.NewRoot(t.TempDir())
	must(t, err)
	writeFile(t, root.Path(sandbox.GateKeyFile), testKey+"\n")
	g, err := New(Config{
		Listen: "127.0.0.1:0", KeyFile: sandbox.GateKeyFile, Deny: []int{29417, 22, 2022, 49983},
		SSHPortFile: sandbox.SSHPortFile,
	}, root)
	must(t, err)
	for _, f := range tune {
		f(g)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		must(t, <-done)
	})
	return &testGate{addr: ln.Addr().String(), port: ln.Addr().(*net.TCPAddr).Port, root: root,
		gate: g}
}

type response struct {
	StatusCode int
	Header     http.Header
	Body       string
}

var plainClient = &http.Client{Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}

func gateGet(t *testing.T, g *testGate, path string, h http.Header) response {
	t.Helper()
	return gateDo(t, plainClient, g, path, h)
}

func gateDo(t *testing.T, c *http.Client, g *testGate, path string, h http.Header) response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+g.addr+path, nil)
	must(t, err)
	req.Header = h.Clone()
	res, err := c.Do(req)
	must(t, err)
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	must(t, err)
	return response{StatusCode: res.StatusCode, Header: res.Header, Body: string(b)}
}

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

// app is the gate key and port headers the edges send for app traffic, plus kv
func app(port int, kv ...string) http.Header {
	h := hdr(kv...)
	h.Set(HeaderKey, testKey)
	h.Set(HeaderPort, strconv.Itoa(port))
	return h
}

func keyed(kv ...string) http.Header {
	h := hdr(kv...)
	h.Set(HeaderKey, testKey)
	return h
}

func serve(t *testing.T, h http.Handler) int {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().(*net.TCPAddr).Port
}

// listenOnly serves 200 with body name on addr alone and returns its port
func listenOnly(t *testing.T, addr, name string) int {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	must(t, err)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter,
		_ *http.Request) {
		_, _ = io.WriteString(w, name)
	}))
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return ln.Addr().(*net.TCPAddr).Port
}

// appWith serves 200 with the response headers kv and returns its port
func appWith(t *testing.T, kv ...string) int {
	t.Helper()
	return serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i+1 < len(kv); i += 2 {
			w.Header().Set(kv[i], kv[i+1])
		}
		_, _ = io.WriteString(w, "ok")
	}))
}

// freePort returns a loopback port nothing listens on, on IPv4 or IPv6
func freePort(t *testing.T) int {
	t.Helper()
	for range 20 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		must(t, err)
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		if c, err := net.Dial("tcp", net.JoinHostPort("::1", strconv.Itoa(port))); err == nil {
			_ = c.Close()
			continue
		}
		return port
	}
	t.Fatal("no free port")
	return 0
}

type recorder struct {
	port   int
	mu     sync.Mutex
	host   string
	uri    string
	header http.Header
}

// appRecorder serves 200 and keeps what the last request carried
func appRecorder(t *testing.T) *recorder {
	t.Helper()
	r := &recorder{}
	r.port = serve(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.host, r.uri, r.header = req.Host, req.RequestURI, req.Header.Clone()
		r.mu.Unlock()
		_, _ = io.WriteString(w, "seen")
	}))
	return r
}

func (r *recorder) get(name string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.header.Values(name), ", ")
}

func (r *recorder) values(name string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.header.Values(name)
}

func (r *recorder) anyHeaderWithPrefix(prefixes ...string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name := range r.header {
		for _, p := range prefixes {
			if strings.HasPrefix(strings.ToLower(name), strings.ToLower(p)) {
				return true
			}
		}
	}
	return false
}

// upgrade sends a WebSocket upgrade for protocol and returns the answer and the connection
func upgrade(t *testing.T, g *testGate, path string, h http.Header,
	protocol string) (*http.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", g.addr)
	must(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	req, err := http.NewRequest(http.MethodGet, "http://"+g.addr+path, nil)
	must(t, err)
	req.Header = h.Clone()
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(key))
	req.Header.Set("Sec-WebSocket-Protocol", protocol)
	must(t, req.Write(conn))
	br := bufio.NewReader(conn)
	must(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	res, err := http.ReadResponse(br, req)
	must(t, err)
	must(t, conn.SetReadDeadline(time.Time{}))
	if res.StatusCode == http.StatusSwitchingProtocols {
		eq(t, res.Header.Get("Sec-Websocket-Accept"),
			wsframe.AcceptKey(req.Header.Get("Sec-WebSocket-Key")))
	} else {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}
	return res, conn, br
}

// wsRecorder accepts WebSocket upgrades for protocol and keeps what the last one carried
func wsRecorder(t *testing.T, protocol string) *recorder {
	t.Helper()
	r := &recorder{}
	r.port = serve(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.host, r.uri, r.header = req.Host, req.RequestURI, req.Header.Clone()
		r.mu.Unlock()
		c, err := wsframe.Accept(w, req, protocol)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = c.Close()
	}))
	return r
}

// echoApp answers WebSocket upgrades for protocol and echoes every message
func echoApp(t *testing.T, protocol string) int {
	t.Helper()
	return serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := wsframe.Accept(w, r, protocol)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.Copy(c, c)
	}))
}

type fakeSSHD struct {
	port  int
	conns chan net.Conn
}

// sshdAt listens like sshd would and writes its port where the gate looks for it
func sshdAt(t *testing.T, g *testGate) *fakeSSHD {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	f := &fakeSSHD{port: ln.Addr().(*net.TCPAddr).Port, conns: make(chan net.Conn, 64)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.conns <- c
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		for {
			select {
			case c := <-f.conns:
				_ = c.Close()
			default:
				return
			}
		}
	})
	writeFile(t, g.root.Path(sandbox.SSHPortFile), strconv.Itoa(f.port)+"\n")
	return f
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %v", timeout)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
