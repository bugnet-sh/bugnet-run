package egress

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oynozan/bugnet-run/internal/sandbox"
)

func loadConfig(t *testing.T, root sandbox.Root, change func(*Config)) error {
	t.Helper()
	cfg := Config{
		Endpoint: "egress.bugnet.sh", IPs: []string{"203.0.113.7", "2001:db8::7"}, Port: 443,
		Listen: "127.77.0.1:443", TokenFile: sandbox.EgressToken,
		Hosts: []string{"huggingface.co", "api.github.com"},
	}
	change(&cfg)
	b, err := json.Marshal(cfg)
	must(t, err)
	path := t.TempDir() + "/egress.json"
	writeFile(t, path, string(b))
	_, err = LoadConfig(path, root)
	return err
}

func TestWireNames(t *testing.T) {
	t.Parallel()
	eq(t, []string{ListenIP, TunnelPath, ProtocolTunnel}, []string{
		"127.77.0.1", "/v1/tunnel", "bugnet-tunnel.v1",
	})
	eq(t, MaxConns, 64)
	eq(t, []time.Duration{firstRetry, listenWait, handshakeTimeout}, []time.Duration{
		time.Second, 5 * time.Second, 10 * time.Second,
	})
	eq(t, []string{ErrBadSpec, ErrPort443Taken, ErrTokenMissing, ErrApplyFailed}, []string{
		"bad_spec", "port_443_taken", "token_missing", "apply_failed",
	})
}

func TestForwardRefusesLoopbackListen(t *testing.T) {
	t.Parallel()
	for _, a := range []string{"127.0.0.1:443", "[::1]:443", "0.0.0.0:443", ":443",
		"127.77.0.2:443", "127.77.0.1:0", "127.0.0.1:0", "[::]:443", "127.77.0.1"} {
		err := loadConfig(t, sandbox.System, func(c *Config) { c.Listen = a })
		if err == nil || !strings.HasSuffix(err.Error(), ": listen is not 127.77.0.1 with a port") {
			t.Errorf("listen %q in a sandbox gave %v, want a refusal that quotes nothing", a, err)
		}
	}
	must(t, loadConfig(t, sandbox.System, func(*Config) {}))

	root := testRoot(t)
	for _, a := range []string{"127.0.0.1:0", "127.0.0.1:8443", "127.77.0.1:443"} {
		must(t, loadConfig(t, root, func(c *Config) { c.Listen = a }))
	}
	for _, a := range []string{"[::1]:443", "0.0.0.0:0", ":0"} {
		if loadConfig(t, root, func(c *Config) { c.Listen = a }) == nil {
			t.Errorf("listen %q was accepted under a test root", a)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	for name, change := range map[string]func(*Config){
		"endpoint":       func(c *Config) { c.Endpoint = "egress bugnet.sh" },
		"no endpoint":    func(c *Config) { c.Endpoint = "" },
		"no ips":         func(c *Config) { c.IPs = nil },
		"bad ip":         func(c *Config) { c.IPs = []string{"203.0.113.300"} },
		"zone":           func(c *Config) { c.IPs = []string{"fe80::1%eth0"} },
		"port 0":         func(c *Config) { c.Port = 0 },
		"port 65536":     func(c *Config) { c.Port = 65536 },
		"no token file":  func(c *Config) { c.TokenFile = "" },
		"upper host":     func(c *Config) { c.Hosts = []string{"HuggingFace.co"} },
		"host space":     func(c *Config) { c.Hosts = []string{"a.example b.example"} },
		"host newline":   func(c *Config) { c.Hosts = []string{"a.example\n1.2.3.4 b.example"} },
		"host dot":       func(c *Config) { c.Hosts = []string{"a.example."} },
		"one label":      func(c *Config) { c.Hosts = []string{"localhost"} },
		"duplicate host": func(c *Config) { c.Hosts = []string{"a.example", "a.example"} },
		"ip host":        func(c *Config) { c.Hosts = []string{"1.2.3.4"} },
	} {
		if loadConfig(t, root, change) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if loadConfig(t, sandbox.System, func(c *Config) { c.RootsFile = "/tmp/roots.pem" }) == nil {
		t.Error("roots_file was accepted in a sandbox")
	}
	must(t, loadConfig(t, root, func(c *Config) { c.RootsFile = rootsFile; c.Hosts = nil }))

	path := t.TempDir() + "/egress.json"
	writeFile(t, path, `{"endpoint":"egress.bugnet.sh","ips":["203.0.113.7"],"port":443,`+
		`"listen":"127.77.0.1:443","token_file":"/etc/bugnet/egress.token","hosts":[],`+
		`"roots_file":"","extra":1}`)
	if _, err := LoadConfig(path, sandbox.System); err == nil {
		t.Error("an unknown field was accepted")
	}
}

func TestForwardSendsTunnelUpgrade(t *testing.T) {
	t.Parallel()
	p := newPKI(t)
	s := newTunnelServer(t, p, testEndpoint)
	fw := startForwarder(t, p, testConfig(s), testToken)
	eq(t, roundTrip(t, dial(t, fw.addr), "client hello"), "client hello")

	reqs := s.requests()
	eq(t, len(reqs), 1)
	r := reqs[0]
	eq(t, r.Method, "GET")
	eq(t, r.URL.Path, "/v1/tunnel")
	eq(t, r.Host, testEndpoint)
	eq(t, r.Header.Get("Authorization"), "Bearer "+testToken)
	eq(t, r.Header.Get("Sec-Websocket-Protocol"), "bugnet-tunnel.v1")
	eq(t, strings.ToLower(r.Header.Get("Upgrade")), "websocket")
	eq(t, r.TLS.ServerName, testEndpoint)
	eq(t, r.TLS.NegotiatedProtocol, "http/1.1")
}

func TestForwardRefusesWrongCertificateName(t *testing.T) {
	t.Parallel()
	p := newPKI(t)
	s := newTunnelServer(t, p, "other.example")
	fw := startForwarder(t, p, testConfig(s), testToken)
	eq(t, closedSoon(t, dial(t, fw.addr), "client hello", 900*time.Millisecond), true)
	eq(t, len(s.requests()), 0)
	eq(t, s.accepts.Load(), int64(1))

	untrusted := newPKI(t)
	s = newTunnelServer(t, untrusted, testEndpoint)
	fw = startForwarder(t, p, testConfig(s), testToken)
	eq(t, closedSoon(t, dial(t, fw.addr), "client hello", 900*time.Millisecond), true)
	eq(t, len(s.requests()), 0)
}

func TestForwardReloadKeepsOpenConnections(t *testing.T) {
	t.Parallel()
	p := newPKI(t)
	first, second := newTunnelServer(t, p, testEndpoint), newTunnelServer(t, p, testEndpoint)
	fw := startForwarder(t, p, testConfig(first), testToken)
	open := dial(t, fw.addr)
	eq(t, roundTrip(t, open, "before"), "before")

	writeForwarderFiles(t, fw.root, p, testConfig(second), otherToken)
	must(t, fw.f.Reload())
	eq(t, roundTrip(t, open, "after the reload"), "after the reload")
	eq(t, roundTrip(t, dial(t, fw.addr), "new"), "new")
	eq(t, len(first.requests()), 1)
	reqs := second.requests()
	eq(t, len(reqs), 1)
	eq(t, reqs[0].Header.Get("Authorization"), "Bearer "+otherToken)

	writeFile(t, fw.root.Path(sandbox.EgressConfig), "{")
	eq(t, fw.f.Reload() != nil, true)
	writeForwarderFiles(t, fw.root, p, testConfig(first), "bnt_short")
	eq(t, fw.f.Reload() != nil, true)
	eq(t, roundTrip(t, dial(t, fw.addr), "kept"), "kept")
	eq(t, len(second.requests()), 2)
	eq(t, roundTrip(t, open, "still"), "still")
}

func TestForwardRetriesFirstDialOnce(t *testing.T) {
	t.Parallel()
	p := newPKI(t)
	s := newTunnelServer(t, p, testEndpoint)
	s.drop.Store(1)
	fw := startForwarder(t, p, testConfig(s), testToken)
	began := time.Now()
	eq(t, roundTrip(t, dial(t, fw.addr), "late"), "late")
	if took := time.Since(began); took < firstRetry {
		t.Fatalf("the retry came after %v, want %v", took, firstRetry)
	}
	eq(t, s.accepts.Load(), int64(2))

	s.drop.Store(2)
	began = time.Now()
	eq(t, closedSoon(t, dial(t, fw.addr), "again", 900*time.Millisecond), true)
	if took := time.Since(began); took >= firstRetry {
		t.Fatalf("a later dial waited %v, as if retried", took)
	}
	eq(t, s.accepts.Load(), int64(3))
}

func TestForwardTriesTheNextPinnedIP(t *testing.T) {
	t.Parallel()
	p := newPKI(t)
	s := newTunnelServer(t, p, testEndpoint)
	cfg := testConfig(s)
	cfg.IPs = []string{"::1", "127.0.0.1"}
	fw := startForwarder(t, p, cfg, testToken)
	eq(t, roundTrip(t, dial(t, fw.addr), "second ip"), "second ip")
}

func TestForwardStopsAtTheProxysAnswer(t *testing.T) {
	t.Parallel()
	p := newPKI(t)
	for _, code := range []int64{401, 403, 429} {
		s := newTunnelServer(t, p, testEndpoint)
		s.status.Store(code)
		fw := startForwarder(t, p, testConfig(s), testToken)
		began := time.Now()
		eq(t, closedSoon(t, dial(t, fw.addr), "refused", 900*time.Millisecond), true)
		if took := time.Since(began); took >= firstRetry {
			t.Fatalf("a %d came back after %v, as if the first dial was retried", code, took)
		}
		eq(t, s.accepts.Load(), int64(1))
		eq(t, len(s.requests()), 1)
	}

	first, second := sharedPort(t)
	refusing := serveTunnel(t, p, testEndpoint, first)
	next := serveTunnel(t, p, testEndpoint, second)
	refusing.status.Store(401)
	cfg := testConfig(refusing)
	cfg.IPs = []string{"127.0.0.1", second.Addr().(*net.TCPAddr).IP.String()}
	fw := startForwarder(t, p, cfg, testToken)
	eq(t, closedSoon(t, dial(t, fw.addr), "refused", 900*time.Millisecond), true)
	eq(t, refusing.accepts.Load(), int64(1))
	eq(t, next.accepts.Load(), int64(0))
}

func TestForwardWaitsForTheClientToSpeak(t *testing.T) {
	t.Parallel()
	p := newPKI(t)
	s := newTunnelServer(t, p, testEndpoint)
	fw := startForwarder(t, p, testConfig(s), testToken)
	eq(t, fw.f.speakWithin, handshakeTimeout)
	eq(t, fw.f.handshakeWithin, handshakeTimeout)
	_ = dial(t, fw.addr).Close()
	waitFor(t, 5*time.Second, func() bool { return fw.f.accepted.Load() == 1 })
	eq(t, roundTrip(t, dial(t, fw.addr), "speaks"), "speaks")
	eq(t, s.accepts.Load(), int64(1))
}

func TestForwardFreesTheSlotsOfSilentClients(t *testing.T) {
	t.Parallel()
	p := newPKI(t)
	s := newTunnelServer(t, p, testEndpoint)
	fw := startForwarder(t, p, testConfig(s), testToken,
		func(f *Forwarder) { f.speakWithin = 100 * time.Millisecond })
	silent := make([]net.Conn, MaxConns)
	for i := range silent {
		silent[i] = dial(t, fw.addr)
	}
	eq(t, roundTrip(t, dial(t, fw.addr), "after them"), "after them")
	must(t, silent[0].SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err := silent[0].Read(make([]byte, 1))
	var ne net.Error
	if err == nil || errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("a silent client was not closed: %v", err)
	}
	eq(t, s.accepts.Load(), int64(1))

	slow := dial(t, fw.addr)
	eq(t, roundTrip(t, slow, "first"), "first")
	time.Sleep(300 * time.Millisecond)
	eq(t, roundTrip(t, slow, "pause"), "pause")
}

func TestForwardGivesUpOnAStalledProxy(t *testing.T) {
	t.Parallel()
	p := newPKI(t)
	for _, stage := range []string{"tls", "upgrade"} {
		s := newTunnelServer(t, p, testEndpoint)
		stall := &s.stall
		if stage == "tls" {
			stall = &s.hold
		}
		stall.Store(true)
		// Past the first dial, whose retry TestForwardRetriesFirstDialOnce covers
		fw := startForwarder(t, p, testConfig(s), testToken, func(f *Forwarder) {
			f.handshakeWithin = 100 * time.Millisecond
			f.dialed.Store(true)
		})
		if !closedSoon(t, dial(t, fw.addr), "x", 900*time.Millisecond) {
			t.Fatalf("a proxy stalled at its %s answer held the client", stage)
		}
		eq(t, fw.f.failed.Load(), int64(1))

		for range MaxConns {
			_, err := io.WriteString(dial(t, fw.addr), "x")
			must(t, err)
		}
		waitFor(t, 5*time.Second, func() bool { return fw.f.failed.Load() == MaxConns+1 })
		eq(t, s.accepts.Load(), int64(MaxConns+1))
		stall.Store(false)
		eq(t, roundTrip(t, dial(t, fw.addr), stage), stage)
		eq(t, s.accepts.Load(), int64(MaxConns+2))
	}
}

func TestForwardCaps64Connections(t *testing.T) {
	t.Parallel()
	p := newPKI(t)
	s := newTunnelServer(t, p, testEndpoint)
	fw := startForwarder(t, p, testConfig(s), testToken)
	conns := make([]net.Conn, MaxConns)
	for i := range conns {
		conns[i] = dial(t, fw.addr)
		eq(t, roundTrip(t, conns[i], "x"), "x")
	}
	eq(t, s.open.Load(), int64(MaxConns))

	extra := dial(t, fw.addr)
	_, err := io.WriteString(extra, "y")
	must(t, err)
	must(t, extra.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("a 65th connection got through")
	}
	eq(t, s.open.Load(), int64(MaxConns))

	_ = conns[0].Close()
	must(t, extra.SetReadDeadline(time.Now().Add(5*time.Second)))
	got := make([]byte, 1)
	_, err = io.ReadFull(extra, got)
	must(t, err)
	eq(t, string(got), "y")
}

func TestForwardLogsCountsOnly(t *testing.T) {
	t.Parallel()
	p := newPKI(t)
	s := newTunnelServer(t, p, testEndpoint)
	fw := startForwarder(t, p, testConfig(s), testToken,
		func(f *Forwarder) { f.every = 20 * time.Millisecond })
	eq(t, roundTrip(t, dial(t, fw.addr), "x"), "x")
	s.drop.Store(1)
	eq(t, closedSoon(t, dial(t, fw.addr), "y", 900*time.Millisecond), true)
	waitFor(t, 5*time.Second, func() bool {
		return strings.Contains(fw.logs.String(), "connections 2, open 1, failed 1")
	})
	logs := fw.logs.String()
	for _, secret := range []string{testEndpoint, "127.0.0.1", strconv.Itoa(s.port),
		"huggingface.co", testToken, "bnt_"} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs hold %q: %s", secret, logs)
		}
	}
}

func TestForwardCommand(t *testing.T) {
	t.Parallel()
	p := newPKI(t)
	first, second := newTunnelServer(t, p, testEndpoint), newTunnelServer(t, p, testEndpoint)
	root := testRoot(t)
	writeForwarderFiles(t, root, p, testConfig(first), testToken)
	cmd := exec.Command(binPath, "forward", "--config", root.Path(sandbox.EgressConfig),
		"--root", root.Dir())
	stderr := &syncBuffer{}
	cmd.Stderr = stderr
	must(t, cmd.Start())
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	pidFile := root.Path(sandbox.RunDir + "/forward.pid")
	waitFor(t, 5*time.Second, func() bool { return exists(pidFile) })
	pid, err := sandbox.ReadPidFile(root, "forward")
	must(t, err)
	eq(t, pid, cmd.Process.Pid)
	addr := strings.TrimSpace(readFile(t, root.Path(addrFile)))
	open := dial(t, addr)
	eq(t, roundTrip(t, open, "one"), "one")

	writeForwarderFiles(t, root, p, testConfig(second), otherToken)
	must(t, syscall.Kill(cmd.Process.Pid, syscall.SIGHUP))
	waitFor(t, 5*time.Second, func() bool { return strings.Contains(stderr.String(), "reloaded") })
	eq(t, roundTrip(t, open, "two"), "two")
	eq(t, roundTrip(t, dial(t, addr), "three"), "three")
	eq(t, second.requests()[0].Header.Get("Authorization"), "Bearer "+otherToken)

	must(t, syscall.Kill(cmd.Process.Pid, syscall.SIGTERM))
	select {
	case err := <-exited:
		must(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the forwarder outlived SIGTERM")
	}
	eq(t, exists(pidFile), false)
	eq(t, exists(root.Path(addrFile)), false)
	out := stderr.String()
	eq(t, strings.Contains(out, "listening, 1 hosts"), true)
	eq(t, strings.Contains(out, testEndpoint) || strings.Contains(out, "huggingface.co"), false)
}

func TestForwardCommandFailures(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"forward", "--nope"}, {"forward", "extra"}} {
		cmd := exec.Command(binPath, args...)
		if err := cmd.Run(); cmd.ProcessState.ExitCode() != 2 {
			t.Errorf("bugnet-run %v: %v, want exit 2", args, err)
		}
	}
	root := testRoot(t)
	cmd := exec.Command(binPath, "forward", "--root", root.Dir())
	if err := cmd.Run(); cmd.ProcessState.ExitCode() != 1 {
		t.Errorf("forward without a config: %v, want exit 1", err)
	}

	p := newPKI(t)
	held, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	t.Cleanup(func() { _ = held.Close() })
	cfg := testConfig(&tunnelServer{port: 443})
	cfg.Listen = held.Addr().String()
	writeForwarderFiles(t, root, p, cfg, testToken)
	taken := exec.Command(binPath, "forward", "--root", root.Dir())
	out, err := taken.CombinedOutput()
	if err == nil || taken.ProcessState.ExitCode() != 1 ||
		!strings.Contains(string(out), "address already in use") {
		t.Errorf("forward on a held port: %v %q, want exit 1 for a taken address", err, out)
	}
	eq(t, exists(root.Path(sandbox.RunDir+"/forward.pid")), false)
	if _, err := os.Stat(root.Path(addrFile)); !os.IsNotExist(err) {
		t.Errorf("a forwarder that never listened left %s", addrFile)
	}
}
