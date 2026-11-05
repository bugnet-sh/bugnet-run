package gate

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oynozan/bugnet-run/internal/sandbox"
	"github.com/oynozan/bugnet-run/internal/wsframe"
)

func TestWireNames(t *testing.T) {
	t.Parallel()
	eq(t, []string{HeaderKey, HeaderPort, HeaderHost, HeaderClientIP}, []string{
		"Bugnet-Gate", "Bugnet-Port", "Bugnet-Host", "Bugnet-Client-Ip",
	})
	eq(t, []string{HeaderResponse, HeaderError, HeaderVersion, HeaderCacheControl, HeaderServer},
		[]string{"Bugnet-Gate-Response", "Bugnet-Gate-Error", "Bugnet-Gate-Version",
			"Bugnet-Cache-Control", "Bugnet-Server"})
	eq(t, []string{ErrPortClosed, ErrBusy, ErrSSHNotReady}, []string{
		"port_closed", "busy", "ssh_not_ready",
	})
	eq(t, []string{PathHealth, PathPort, PathSSH, ProtocolSSH}, []string{
		"/__bugnet/health", "/__bugnet/port/", "/__bugnet/ssh", "bugnet-ssh.v1",
	})
	eq(t, DefaultPort, 29417)
	eq(t, []int{MaxInFlight, MaxTunnels}, []int{256, 16})
}

func TestGateMissingOrWrongKeyIs404(t *testing.T) {
	t.Parallel()
	g := startGate(t)
	port := appWith(t)
	for _, key := range []string{"", "wrong", testKey[:42], testKey + "x"} {
		h := hdr(HeaderPort, strconv.Itoa(port))
		if key != "" {
			h.Set(HeaderKey, key)
		}
		for _, path := range []string{"/", PathHealth} {
			r := gateGet(t, g, path, h)
			eq(t, r.StatusCode, 404)
			eq(t, r.Body, "")
			eq(t, r.Header.Get(HeaderResponse), "1")
			eq(t, r.Header.Get(HeaderError), "")
		}
	}
	eq(t, gateGet(t, g, "/", app(port)).StatusCode, 200)
}

func TestGateDenyList(t *testing.T) {
	t.Parallel()
	g := startGate(t)
	for _, port := range []string{"29417", "22", "2022", "49983", strconv.Itoa(g.port), "0",
		"65536", "-1", "80x", ""} {
		r := gateGet(t, g, "/", keyed(HeaderPort, port))
		eq(t, r.StatusCode, 400)
		eq(t, r.Header.Get(HeaderResponse), "1")
	}
}

func TestGateDialsIPv4ThenIPv6(t *testing.T) {
	t.Parallel()
	g := startGate(t)
	port := listenOnly(t, "[::1]:0", "v6")
	r := gateGet(t, g, "/", app(port))
	eq(t, r.StatusCode, 200)
	eq(t, r.Body, "v6")

	both := listenOnly(t, "127.0.0.1:0", "v4")
	ln, err := net.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(both)))
	if err != nil {
		t.Skipf("IPv6 loopback port %d is taken: %v", both, err)
	}
	_ = ln.Close()
	listenOnly(t, net.JoinHostPort("::1", strconv.Itoa(both)), "v6")
	eq(t, gateGet(t, g, "/", app(both)).Body, "v4")
}

func TestGateClosedPort(t *testing.T) {
	t.Parallel()
	g := startGate(t)
	r := gateGet(t, g, "/", app(freePort(t)))
	eq(t, r.StatusCode, 502)
	eq(t, r.Header.Get(HeaderError), "port_closed")
	eq(t, r.Header.Get(HeaderResponse), "1")
}

func TestGateRewritesRequestHeaders(t *testing.T) {
	t.Parallel()
	g := startGate(t)
	seen := appRecorder(t)
	gateGet(t, g, "/x", app(seen.port, "Bugnet-Host", "abc.preview.example",
		"Bugnet-Client-Ip", "198.51.100.7", "E2b-X", "1", "e2b-traffic-access-token", "t",
		"X-Routing-Key", "k", "Cookie", "_port_auth=1; app=2", "Bugnet-Token", "bnp_x",
		"X-Forwarded-For", "203.0.113.9", "Authorization", "Bearer app", "Origin", "https://o"))
	eq(t, seen.host, "abc.preview.example")
	eq(t, seen.get("X-Forwarded-Host"), "abc.preview.example")
	eq(t, seen.get("X-Forwarded-Proto"), "https")
	eq(t, seen.get("X-Forwarded-For"), "198.51.100.7")
	eq(t, seen.get("Cookie"), "app=2")
	eq(t, seen.anyHeaderWithPrefix("Bugnet-", "E2b-"), false)
	eq(t, seen.get("e2b-traffic-access-token")+seen.get("X-Routing-Key"), "")
	eq(t, seen.get("Authorization"), "Bearer app")
	eq(t, seen.get("Origin"), "https://o")

	gateGet(t, g, "/y", app(seen.port, "Cookie", "_port_auth=1", "Bugnet-Client-Ip", "nonsense"))
	eq(t, seen.get("Cookie"), "")
	eq(t, seen.get("X-Forwarded-For"), "")
}

func TestGateKeepsPathAndQueryByteForByte(t *testing.T) {
	t.Parallel()
	g := startGate(t)
	seen := appRecorder(t)
	for _, uri := range []string{"/app?page=2&q=a%20b&t=1", "/a%2Fb/%7e?x=%zz&&y",
		"/s?a=1;b=2&b=1&a=0", "/"} {
		gateGet(t, g, uri, app(seen.port))
		eq(t, seen.uri, uri)
	}
}

func TestGateMovesCacheControlAndServer(t *testing.T) {
	t.Parallel()
	g := startGate(t)
	r := gateGet(t, g, "/", app(appWith(t, "Cache-Control", "max-age=60", "Server", "vite")))
	eq(t, r.Header.Get("Cache-Control"), "private")
	eq(t, r.Header.Get(HeaderCacheControl), "max-age=60")
	eq(t, r.Header.Get(HeaderServer), "vite")
	eq(t, r.Header.Get("Server"), "")
	r = gateGet(t, g, "/", app(appWith(t)))
	eq(t, r.Header.Get(HeaderCacheControl)+r.Header.Get(HeaderServer), "--")
	eq(t, r.Header.Get("Cache-Control"), "private")
}

func TestGateDropsBugnetHeadersTheAppSets(t *testing.T) {
	t.Parallel()
	g := startGate(t)
	r := gateGet(t, g, "/", app(appWith(t, "Bugnet-Gate-Error", "busy",
		"Bugnet-Gate-Response", "0", "Bugnet-Cache-Control", "public")))
	eq(t, r.StatusCode, 200)
	eq(t, r.Header.Values(HeaderResponse), []string{"1"})
	eq(t, r.Header.Get(HeaderError), "")
	eq(t, r.Header.Get(HeaderCacheControl), "-")
}

func TestGateMarksTheAnswerAfterEarlyHints(t *testing.T) {
	t.Parallel()
	g := startGate(t)
	port := serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", "</app.js>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		_, _ = io.WriteString(w, "after hints")
	}))
	r := gateGet(t, g, "/", app(port))
	eq(t, r.StatusCode, 200)
	eq(t, r.Body, "after hints")
	eq(t, r.Header.Values(HeaderResponse), []string{"1"})
	eq(t, r.Header.Get("Cache-Control"), "private")
}

func TestGateEveryResponseIsMarked(t *testing.T) {
	t.Parallel()
	g := startGate(t)
	statuses := map[int]response{
		404: gateGet(t, g, "/", hdr()),
		400: gateGet(t, g, "/", app(22)),
		502: gateGet(t, g, "/", app(freePort(t))),
		503: gateGet(t, g, PathSSH, keyed()),
		204: gateGet(t, g, PathHealth, keyed()),
		200: gateGet(t, g, "/", app(appWith(t))),
	}
	for status, r := range statuses {
		eq(t, r.StatusCode, status)
		eq(t, r.Header.Values(HeaderResponse), []string{"1"})
	}

	res, conn, br := upgrade(t, g, "/socket", app(echoApp(t, "chat")), "chat")
	eq(t, res.StatusCode, 101)
	eq(t, res.Header.Values(HeaderResponse), []string{"1"})
	eq(t, res.Header.Get("Sec-Websocket-Protocol"), "chat")
	ws := wsframe.NewConn(conn, br, true)
	_, err := ws.Write([]byte("ping through the gate"))
	must(t, err)
	got := make([]byte, len("ping through the gate"))
	_, err = io.ReadFull(ws, got)
	must(t, err)
	eq(t, string(got), "ping through the gate")

	sshdAt(t, g)
	res, _, _ = upgrade(t, g, PathSSH, keyed(), ProtocolSSH)
	eq(t, res.StatusCode, 101)
	eq(t, res.Header.Values(HeaderResponse), []string{"1"})
}

func TestGateControlRoutes(t *testing.T) {
	t.Parallel()
	g := startGate(t)
	r := gateGet(t, g, PathHealth, keyed())
	eq(t, r.StatusCode, 204)
	eq(t, r.Header.Get(HeaderVersion), Version)

	open := appWith(t)
	eq(t, gateGet(t, g, PathPort+strconv.Itoa(open), keyed()).StatusCode, 204)
	eq(t, gateGet(t, g, PathPort+strconv.Itoa(listenOnly(t, "[::1]:0", "")), keyed()).StatusCode,
		204)
	eq(t, gateGet(t, g, PathPort+strconv.Itoa(freePort(t)), keyed()).StatusCode, 404)
	for _, path := range []string{PathPort + "x", PathPort + "0", PathPort, "/", "/__bugnet/",
		PathHealth + "/x", "/__bugnet/other"} {
		eq(t, gateGet(t, g, path, keyed()).StatusCode, 404)
	}

	req, err := http.NewRequest(http.MethodPost, "http://"+g.addr+PathHealth, nil)
	must(t, err)
	req.Header = keyed()
	res, err := plainClient.Do(req)
	must(t, err)
	_ = res.Body.Close()
	eq(t, res.StatusCode, 404)
}

func TestGateSSHPathCopiesBytes(t *testing.T) {
	t.Parallel()
	g := startGate(t)
	res, _, _ := upgrade(t, g, PathSSH, keyed(), ProtocolSSH)
	eq(t, res.StatusCode, 503)
	eq(t, res.Header.Get(HeaderError), "ssh_not_ready")

	sshd := sshdAt(t, g)
	res, _, _ = upgrade(t, g, PathSSH, keyed(), "bugnet-ssh.v2")
	eq(t, res.StatusCode, 400)

	res, conn, br := upgrade(t, g, PathSSH, keyed(), ProtocolSSH)
	eq(t, res.StatusCode, 101)
	eq(t, res.Header.Get("Sec-Websocket-Protocol"), ProtocolSSH)
	ws := wsframe.NewConn(conn, br, true)
	up := <-sshd.conns

	up2in := make([]byte, 1<<20+256)
	_, _ = rand.Read(up2in)
	go func() { _, _ = ws.Write(up2in) }()
	got := make([]byte, len(up2in))
	_, err := io.ReadFull(up, got)
	must(t, err)
	eq(t, bytes.Equal(got, up2in), true)

	greeting := []byte("SSH-2.0-OpenSSH_9.6\r\n" + string(bytes.Repeat([]byte{0, 255}, 70000)))
	go func() { _, _ = up.Write(greeting) }()
	got = make([]byte, len(greeting))
	_, err = io.ReadFull(ws, got)
	must(t, err)
	eq(t, bytes.Equal(got, greeting), true)

	_ = up.Close()
	_, err = io.ReadAll(ws)
	must(t, err)

	writeFile(t, g.root.Path(sandbox.SSHPortFile), strconv.Itoa(freePort(t))+"\n")
	res, _, _ = upgrade(t, g, PathSSH, keyed(), ProtocolSSH)
	eq(t, res.StatusCode, 502)
	eq(t, res.Header.Get(HeaderError), "port_closed")

	writeFile(t, g.root.Path(sandbox.SSHPortFile), "twenty-two\n")
	res, _, _ = upgrade(t, g, PathSSH, keyed(), ProtocolSSH)
	eq(t, res.StatusCode, 503)
	eq(t, res.Header.Get(HeaderError), "ssh_not_ready")
}

func TestGateSSHClientCloseReachesSSHD(t *testing.T) {
	t.Parallel()
	g := startGate(t)
	sshd := sshdAt(t, g)
	res, conn, br := upgrade(t, g, PathSSH, keyed(), ProtocolSSH)
	eq(t, res.StatusCode, 101)
	up := <-sshd.conns
	must(t, wsframe.NewConn(conn, br, true).Close())
	must(t, up.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err := io.ReadAll(up)
	eq(t, errors.Is(err, nil) || isReset(err), true)
}

func isReset(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && !op.Timeout()
}

func TestGateLimits(t *testing.T) {
	t.Parallel()
	g := startGate(t)
	release := make(chan struct{})
	var once sync.Once
	var inApp atomic.Int32
	port := serve(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		inApp.Add(1)
		<-release
	}))
	t.Cleanup(func() { once.Do(func() { close(release) }) })

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}
	var wg sync.WaitGroup
	codes := make(chan int, MaxInFlight)
	for range MaxInFlight {
		wg.Go(func() {
			req, _ := http.NewRequest(http.MethodGet, "http://"+g.addr+"/", nil)
			req.Header = app(port)
			res, err := client.Do(req)
			if err != nil {
				codes <- 0
				return
			}
			_ = res.Body.Close()
			codes <- res.StatusCode
		})
	}
	waitFor(t, 20*time.Second, func() bool { return inApp.Load() == MaxInFlight })
	r := gateGet(t, g, "/", app(port))
	eq(t, r.StatusCode, 503)
	eq(t, r.Header.Get(HeaderError), "busy")
	eq(t, r.Header.Get(HeaderResponse), "1")
	eq(t, gateGet(t, g, PathHealth, keyed()).StatusCode, 503)
	eq(t, gateGet(t, g, "/", hdr()).StatusCode, 404)

	once.Do(func() { close(release) })
	wg.Wait()
	close(codes)
	for code := range codes {
		eq(t, code, 200)
	}
	eq(t, gateGet(t, g, PathHealth, keyed()).StatusCode, 204)

	sshd := sshdAt(t, g)
	var tunnels, ups []net.Conn
	t.Cleanup(func() {
		for _, up := range ups {
			_ = up.Close()
		}
	})
	for i := range MaxTunnels {
		res, conn, _ := upgrade(t, g, PathSSH, keyed(), ProtocolSSH)
		if res.StatusCode != 101 {
			t.Fatalf("tunnel %d got %d", i+1, res.StatusCode)
		}
		ups = append(ups, <-sshd.conns)
		tunnels = append(tunnels, conn)
	}
	res, _, _ := upgrade(t, g, PathSSH, keyed(), ProtocolSSH)
	eq(t, res.StatusCode, 503)
	eq(t, res.Header.Get(HeaderError), "busy")
	eq(t, gateGet(t, g, PathHealth, keyed()).StatusCode, 204)

	_ = tunnels[0].Close()
	waitFor(t, 5*time.Second, func() bool {
		res, _, _ := upgrade(t, g, PathSSH, keyed(), ProtocolSSH)
		return res.StatusCode == 101
	})
}

func TestNewRefusesABadKeyFile(t *testing.T) {
	t.Parallel()
	for _, content := range []string{"", "\n", "short", testKey[:42] + "*"} {
		root, err := sandbox.NewRoot(t.TempDir())
		must(t, err)
		writeFile(t, root.Path(sandbox.GateKeyFile), content)
		_, err = New(Config{Listen: ":29417", KeyFile: sandbox.GateKeyFile}, root)
		if err == nil {
			t.Fatalf("key file %q accepted", content)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/gate.json"
	writeFile(t, path, `{"listen": ":29417", "key_file": "/etc/bugnet/gate.key", `+
		`"deny": [29417, 22], "ssh_port_file": "/etc/bugnet/ssh/port"}`)
	cfg, err := LoadConfig(path)
	must(t, err)
	eq(t, cfg, Config{Listen: ":29417", KeyFile: "/etc/bugnet/gate.key", Deny: []int{29417, 22},
		SSHPortFile: "/etc/bugnet/ssh/port"})

	for _, bad := range []string{`{"listen": ":29417"}`, `{"listen": "", "key_file": "/k"}`,
		`{"listen": ":0", "key_file": "/k"}`, `{"listen": ":29417", "key_file": "/k", "x": 1}`,
		`{"listen": ":29417", "key_file": "/k", "deny": [70000]}`, `not json`} {
		writeFile(t, path, bad)
		if _, err := LoadConfig(path); err == nil {
			t.Errorf("config %s loaded", bad)
		}
	}
}

func TestHealthyChecksKeyAndMark(t *testing.T) {
	t.Parallel()
	g := startGate(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	must(t, Healthy(ctx, g.addr, testKey))
	if err := Healthy(ctx, g.addr, "wrong"); err == nil {
		t.Fatal("a wrong key passed")
	}
	plain := serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	if err := Healthy(ctx, fmt.Sprintf("127.0.0.1:%d", plain), testKey); err == nil {
		t.Fatal("an unmarked 204 passed")
	}
	eq(t, ProbeAddr(":29417"), "127.0.0.1:29417")
	eq(t, ProbeAddr("0.0.0.0:1"), "127.0.0.1:1")
	eq(t, ProbeAddr("[::]:2"), "[::1]:2")
	eq(t, ProbeAddr("127.0.0.1:3"), "127.0.0.1:3")
}
