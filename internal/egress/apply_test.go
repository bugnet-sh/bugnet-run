package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oynozan/bugnet-run/internal/sandbox"
)

var (
	hfPlaceholder  = "bnsec_" + strings.Repeat("a", 26)
	ghPlaceholder  = "bnsec_" + strings.Repeat("b", 26)
	npmPlaceholder = "bnsec_" + strings.Repeat("c", 26)
)

func spec(hosts ...string) Spec {
	return Spec{
		V: 1, Token: testToken, Endpoint: "egress.bugnet.sh",
		IPs: []string{"203.0.113.7", "2001:db8::7"}, Port: 443, Listen: "127.77.0.1:443",
		Hosts: hosts, Env: []EnvVar{{Name: "HF_TOKEN", Value: hfPlaceholder}}, Home: "/home/boxd",
	}
}

func TestApplyMapsHostsOnlyAfterForwarderListens(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	fwd := newFakeForwarder(t, root)
	out, events := applyWith(t, root, fwd, spec("huggingface.co", "api.github.com"))
	eq(t, out, `{"forward":"listening","hosts":2,"secrets":1}`)
	eq(t, events, []string{"token", "config", "forwarder", "listening", "hosts", "env", "presets"})
	eq(t, fwd.calls, []string{"start 127.77.0.1:443", "wait 127.77.0.1:443"})
	eq(t, fwd.blockAt, map[string]string{"start": "", "wait": ""})
	eq(t, managedBlock(t, root.Path(sandbox.HostsFile)),
		"127.77.0.1 huggingface.co api.github.com\n")
}

func TestApplyHostsBlock(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	writeFile(t, root.Path(sandbox.HostsFile), "127.0.0.1 localhost\n::1 localhost\n")
	applyFake(t, root, spec("huggingface.co", "api.github.com"))
	eq(t, managedBlock(t, root.Path(sandbox.HostsFile)),
		"127.77.0.1 huggingface.co api.github.com\n")
	eq(t, readFile(t, root.Path(sandbox.HostsFile)), "127.0.0.1 localhost\n::1 localhost\n"+
		"# bugnet begin\n127.77.0.1 huggingface.co api.github.com\n# bugnet end\n")

	applyFake(t, root, spec())
	eq(t, readFile(t, root.Path(sandbox.HostsFile)), "127.0.0.1 localhost\n::1 localhost\n")
}

func TestApplyLeavesAMissingHostsFileAlone(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	applyFake(t, root, spec())
	eq(t, exists(root.Path(sandbox.HostsFile)), false)
	applyFake(t, root, spec("huggingface.co"))
	eq(t, managedBlock(t, root.Path(sandbox.HostsFile)), "127.77.0.1 huggingface.co\n")
}

func TestApplyHostLinesStayShortForMusl(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	var hosts []string
	for i := range 32 {
		hosts = append(hosts, fmt.Sprintf("%s.%02d.example", strings.Repeat("h", 48), i))
	}
	applyFake(t, root, spec(hosts...))
	var mapped []string
	for line := range strings.Lines(managedBlock(t, root.Path(sandbox.HostsFile))) {
		if len(line) > 511 {
			t.Errorf("a hosts line is %d bytes", len(line))
		}
		fields := strings.Fields(line)
		eq(t, fields[0], "127.77.0.1")
		mapped = append(mapped, fields[1:]...)
	}
	eq(t, mapped, hosts)
}

func TestApplyPort443Taken(t *testing.T) {
	t.Parallel()
	listenErr := &net.OpError{Op: "listen", Net: "tcp",
		Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
	for _, at := range []string{"start", "wait"} {
		root := testRoot(t)
		fwd := newFakeForwarder(t, root)
		if at == "start" {
			fwd.startErr = listenErr
		} else {
			fwd.waitErr = listenErr
		}
		out, _ := applyWith(t, root, fwd, spec("huggingface.co"))
		eq(t, out, `{"error":"port_443_taken"}`)
		eq(t, managedBlock(t, root.Path(sandbox.HostsFile)), "")
	}
	root := testRoot(t)
	fwd := newFakeForwarder(t, root)
	fwd.waitErr = errors.New("the forwarder did not listen within 5 s")
	out, _ := applyWith(t, root, fwd, spec("huggingface.co"))
	eq(t, out, `{"error":"apply_failed"}`)
}

func TestApplyPort443TakenForReal(t *testing.T) {
	t.Parallel()
	held, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	t.Cleanup(func() { _ = held.Close() })
	root := realRoot(t, newPKI(t))
	s := realSpec(&tunnelServer{port: 443})
	s.Listen = held.Addr().String()
	began := time.Now()
	out, _, code := runApply(t, root, s)
	if took := time.Since(began); took >= listenWait {
		t.Errorf("a taken port was found after %v, as if apply waited for the forwarder", took)
	}
	eq(t, out, `{"error":"port_443_taken"}`)
	eq(t, code, 1)
	eq(t, managedBlock(t, root.Path(sandbox.HostsFile)), "")
	_, err = sandbox.ReadPidFile(root, "forward")
	eq(t, err != nil, true)
}

func TestApplyWaitFindsAPortTakenAfterTheProbe(t *testing.T) {
	t.Parallel()
	held, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	t.Cleanup(func() { _ = held.Close() })
	fwd := supervised{sup: sandbox.Supervisor{Root: testRoot(t)}, wait: 50 * time.Millisecond}
	eq(t, reasonOf(classify(fwd.Wait(context.Background(), held.Addr().String()))),
		ErrPort443Taken)
	must(t, held.Close())
	eq(t, reasonOf(classify(fwd.Wait(context.Background(), held.Addr().String()))),
		ErrApplyFailed)
}

func TestApplyGitAndNpmPresets(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	home := root.Path("/home/boxd")
	writeFile(t, home+"/.npmrc", "registry=https://registry.example/\n")
	writeFile(t, root.Path(sandbox.GitConfig), "[user]\n\tname = someone\n")
	s := spec("github.com", "registry.npmjs.org")
	s.GitPlaceholder, s.NPMPlaceholder = ghPlaceholder, npmPlaceholder
	applyFake(t, root, s)

	creds := root.Path(sandbox.GitCredentials)
	login := "username=x-access-token\npassword=" + ghPlaceholder + "\n"
	eq(t, readFile(t, creds), login)
	eq(t, mode(t, creds), os.FileMode(0o644))
	eq(t, readFile(t, root.Path(sandbox.GitConfig)), "[user]\n\tname = someone\n# bugnet begin\n"+
		"[credential \"https://github.com\"]\n\thelper = \"!f() { test \\\"$1\\\" = get && cat "+
		creds+"; }; f\"\n# bugnet end\n")
	eq(t, readFile(t, home+"/.npmrc"), "registry=https://registry.example/\n# bugnet begin\n"+
		"//registry.npmjs.org/:_authToken="+npmPlaceholder+"\n# bugnet end\n")
	if _, err := exec.LookPath("git"); err == nil {
		eq(t, gitLogin(t, root), []string{"x-access-token", ghPlaceholder})
		// git hands back each login it used or that failed, where a non-root user cannot write
		dir := filepath.Dir(creds)
		must(t, os.Chmod(dir, 0o555))
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		used := "protocol=https\nhost=github.com\nusername=x-access-token\npassword="
		eq(t, gitCredential(t, root, "approve", used+npmPlaceholder+"\n\n"), "")
		eq(t, gitCredential(t, root, "reject", used+ghPlaceholder+"\n\n"), "")
		eq(t, readFile(t, creds), login)
		must(t, os.Chmod(dir, 0o755))
	}

	applyFake(t, root, spec("huggingface.co"))
	eq(t, exists(creds), false)
	eq(t, readFile(t, root.Path(sandbox.GitConfig)), "[user]\n\tname = someone\n")
	eq(t, readFile(t, home+"/.npmrc"), "registry=https://registry.example/\n")
}

func TestApplyCreatesNpmrcForTheUserAlone(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	must(t, os.MkdirAll(root.Path("/home/boxd"), 0o755))
	s := spec("registry.npmjs.org")
	s.NPMPlaceholder = npmPlaceholder
	applyFake(t, root, s)
	npmrc := root.Path("/home/boxd/.npmrc")
	eq(t, mode(t, npmrc), os.FileMode(0o600))
	eq(t, managedBlock(t, npmrc), "//registry.npmjs.org/:_authToken="+npmPlaceholder+"\n")

	applyFake(t, root, spec())
	eq(t, readFile(t, npmrc), "")
	other := testRoot(t)
	must(t, os.MkdirAll(other.Path("/home/boxd"), 0o755))
	applyFake(t, other, spec())
	eq(t, exists(other.Path("/home/boxd/.npmrc")), false)
	eq(t, exists(other.Path(sandbox.GitConfig)), false)
}

func TestApplyNeverWritesThroughALinkedNpmrc(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	target := root.Path("/etc/target")
	writeFile(t, target, "kept\n")
	must(t, os.MkdirAll(root.Path("/home/boxd"), 0o755))
	must(t, os.Symlink(target, root.Path("/home/boxd/.npmrc")))
	s := spec("registry.npmjs.org")
	s.NPMPlaceholder = npmPlaceholder
	out, _ := applyWith(t, root, newFakeForwarder(t, root), s)
	eq(t, out, `{"forward":"listening","hosts":1,"secrets":1}`)
	eq(t, readFile(t, target), "kept\n")
	link, err := os.Readlink(root.Path("/home/boxd/.npmrc"))
	must(t, err)
	eq(t, link, target)
}

func TestApplyNeedsTheHomeForNpm(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	s := spec("registry.npmjs.org")
	s.NPMPlaceholder = npmPlaceholder
	out, _ := applyWith(t, root, newFakeForwarder(t, root), s)
	eq(t, out, `{"error":"apply_failed"}`)
}

func TestApplyRewritesSetEnvAndHUPsSshd(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	writeFile(t, root.Path(sandbox.EnvFile), "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\n")
	writeFile(t, root.Path(sandbox.SSHDConfig),
		"Port 22\nSetEnv OLD=1\nUsePAM no\nSetEnv DUP=2\n")
	sshd := fakeSSHD(t, root)
	applyFake(t, root, spec("huggingface.co"))
	eq(t, readFile(t, root.Path(sandbox.SSHDConfig)), "Port 22\nSetEnv "+
		"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt HF_TOKEN="+hfPlaceholder+"\nUsePAM no\n")
	eq(t, hungUp(t, sshd), true)

	sshd = fakeSSHD(t, root)
	applyFake(t, root, spec("huggingface.co"))
	eq(t, hungUp(t, sshd), false)

	plain := testRoot(t)
	applyFake(t, plain, spec("huggingface.co"))
	eq(t, exists(plain.Path(sandbox.SSHDConfig)), false)
}

func TestApplyWritesSecretsEnvAndProfile(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	writeFile(t, root.Path(sandbox.EnvFile), "NODE_USE_SYSTEM_CA=1\n")
	s := spec("huggingface.co", "api.openai.com")
	s.Env = append(s.Env, EnvVar{Name: "OPENAI_API_KEY", Value: ghPlaceholder})
	applyFake(t, root, s)
	eq(t, readFile(t, root.Path(sandbox.SecretsEnvFile)),
		"HF_TOKEN="+hfPlaceholder+"\nOPENAI_API_KEY="+ghPlaceholder+"\n")
	eq(t, mode(t, root.Path(sandbox.SecretsEnvFile)), os.FileMode(0o644))
	profile := readFile(t, root.Path(sandbox.ProfileFile))
	for _, line := range []string{"export NODE_USE_SYSTEM_CA='1'\n",
		"export HF_TOKEN='" + hfPlaceholder + "'\n",
		"export OPENAI_API_KEY='" + ghPlaceholder + "'\n"} {
		eq(t, strings.Contains(profile, line), true)
	}
	eq(t, readFile(t, root.Path(sandbox.EgressToken)), testToken+"\n")
	eq(t, mode(t, root.Path(sandbox.EgressToken)), os.FileMode(0o600))
	var cfg map[string]any
	must(t, json.Unmarshal([]byte(readFile(t, root.Path(sandbox.EgressConfig))), &cfg))
	eq(t, cfg, map[string]any{
		"endpoint": "egress.bugnet.sh", "ips": []any{"203.0.113.7", "2001:db8::7"},
		"port": 443.0, "listen": "127.77.0.1:443", "token_file": "/etc/bugnet/egress.token",
		"hosts": []any{"huggingface.co", "api.openai.com"}, "roots_file": rootsFile,
	})
	eq(t, mode(t, root.Path(sandbox.EgressConfig)), os.FileMode(0o644))
}

func TestApplyIsIdempotent(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	fwd := newFakeForwarder(t, root)
	s := spec("huggingface.co")
	s.GitPlaceholder = ghPlaceholder
	applyWith(t, root, fwd, s)
	files := snapshot(t, root)
	fwd.calls = nil
	out, _ := applyWith(t, root, fwd, s)
	eq(t, out, `{"forward":"listening","hosts":1,"secrets":1}`)
	eq(t, fwd.calls, []string{"wait 127.77.0.1:443"})
	eq(t, snapshot(t, root), files)

	s.Token = ""
	applyWith(t, root, fwd, s)
	eq(t, fwd.calls, []string{"wait 127.77.0.1:443", "wait 127.77.0.1:443"})
	eq(t, snapshot(t, root), files)
}

func TestApplyReloadsOrRestarts(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	fwd := newFakeForwarder(t, root)
	applyWith(t, root, fwd, spec("huggingface.co"))
	for _, c := range []struct {
		change func(*Spec)
		call   string
	}{
		{func(s *Spec) { s.Token = otherToken }, "reload"},
		{func(s *Spec) { s.Hosts = append(s.Hosts, "api.github.com") }, "reload"},
		{func(s *Spec) { s.Listen = "127.0.0.1:0" }, "restart"},
	} {
		s := spec("huggingface.co")
		c.change(&s)
		fwd.calls = nil
		applyWith(t, root, fwd, s)
		eq(t, fwd.calls, []string{c.call, "wait " + s.Listen})
	}
}

func TestApplyTokenMissing(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	s := spec("huggingface.co")
	s.Token = ""
	out, events := applyWith(t, root, newFakeForwarder(t, root), s)
	eq(t, out, `{"error":"token_missing"}`)
	eq(t, events, []string(nil))
	eq(t, exists(root.Path(sandbox.EgressConfig)), false)

	writeFile(t, root.Path(sandbox.EgressToken), "bnt_short\n")
	out, _ = applyWith(t, root, newFakeForwarder(t, root), s)
	eq(t, out, `{"error":"token_missing"}`)
}

func TestApplyBadSpec(t *testing.T) {
	t.Parallel()
	good, err := json.Marshal(spec("huggingface.co"))
	must(t, err)
	cases := map[string]json.RawMessage{
		"not json":   json.RawMessage(`{`),
		"unknown":    json.RawMessage(strings.Replace(string(good), `{"v":1`, `{"x":1,"v":1`, 1)),
		"trailing":   json.RawMessage(string(good) + `{}`),
		"version 2":  json.RawMessage(strings.Replace(string(good), `"v":1`, `"v":2`, 1)),
		"no hosts":   json.RawMessage(`{"v":1}`),
		"empty file": json.RawMessage(``),
	}
	for name, change := range map[string]func(*Spec){
		"short token":        func(s *Spec) { s.Token = "bnt_short" },
		"token prefix":       func(s *Spec) { s.Token = "bnx_" + testToken[4:] },
		"endpoint":           func(s *Spec) { s.Endpoint = "egress.bugnet.sh/x" },
		"no ips":             func(s *Spec) { s.IPs = nil },
		"port":               func(s *Spec) { s.Port = 0 },
		"listen":             func(s *Spec) { s.Listen = "0.0.0.0:443" },
		"host":               func(s *Spec) { s.Hosts = []string{"Huggingface.co"} },
		"host line break":    func(s *Spec) { s.Hosts = []string{"a.example\n1.2.3.4 b.example"} },
		"env name":           func(s *Spec) { s.Env[0].Name = "9X" },
		"env value":          func(s *Spec) { s.Env[0].Value = "hf_real" },
		"env repeat":         func(s *Spec) { s.Env = append(s.Env, s.Env[0]) },
		"git placeholder":    func(s *Spec) { s.GitPlaceholder = "ghp_real" },
		"npm placeholder":    func(s *Spec) { s.NPMPlaceholder = "bnsec_UPPER" },
		"npm without home":   func(s *Spec) { s.NPMPlaceholder, s.Home = npmPlaceholder, "" },
		"relative home":      func(s *Spec) { s.Home = "home/boxd" },
		"home line break":    func(s *Spec) { s.Home = "/home/boxd\n" },
		"home not clean":     func(s *Spec) { s.Home = "/home/../etc" },
		"placeholder breaks": func(s *Spec) { s.Env[0].Value = hfPlaceholder + "\nX=1" },
	} {
		s := spec("huggingface.co")
		change(&s)
		b, err := json.Marshal(s)
		must(t, err)
		cases[name] = b
	}
	// Whole refused values only, since the token message itself names bnt_
	refused := map[string][]string{
		"short token": {"bnt_short"}, "token prefix": {"bnx_" + testToken[4:]},
		"endpoint": {"egress.bugnet.sh/x"}, "listen": {"0.0.0.0"}, "host": {"Huggingface.co"},
		"host line break": {"a.example", "b.example", "1.2.3.4"}, "env value": {"hf_real"},
		"git placeholder": {"ghp_real"}, "npm placeholder": {"bnsec_UPPER"},
		"relative home": {"home/boxd"}, "home line break": {"/home/boxd"},
		"home not clean": {"/home/../etc"}, "placeholder breaks": {"X=1"},
	}
	for name, raw := range cases {
		root := testRoot(t)
		out, stderr, code := runApply(t, root, raw)
		if out != `{"error":"bad_spec"}` || code != 1 {
			t.Errorf("%s: printed %s and exited %d", name, out, code)
		}
		for _, v := range refused[name] {
			if strings.Contains(stderr, v) {
				t.Errorf("%s: stderr quotes %q: %s", name, v, stderr)
			}
		}
		if exists(root.Path(sandbox.EgressConfig)) || exists(root.Path(sandbox.EgressToken)) {
			t.Errorf("%s: a bad spec wrote files", name)
		}
	}
	for _, args := range [][]string{{}, {"--spec"}, {"--nope"}, {"--root", "relative"},
		{"--spec", "/nonexistent/egress-spec.json"}, {"extra"}} {
		var out, errOut bytes.Buffer
		code := Apply(args, &out, &errOut)
		if strings.TrimSpace(out.String()) != `{"error":"bad_spec"}` || code != 1 {
			t.Errorf("apply %v: printed %q and exited %d", args, out.String(), code)
		}
	}
}

func TestApplyDeletesTheSpecWhateverElseIsWrong(t *testing.T) {
	t.Parallel()
	good, err := json.Marshal(spec("huggingface.co"))
	must(t, err)
	for _, rest := range [][]string{{"--nope"}, {"extra"}, {"--root", "relative"}} {
		path := filepath.Join(t.TempDir(), "egress-spec.json")
		must(t, os.WriteFile(path, good, 0o600))
		var out, errOut bytes.Buffer
		code := Apply(append([]string{"--spec", path}, rest...), &out, &errOut)
		if strings.TrimSpace(out.String()) != `{"error":"bad_spec"}` || code != 1 {
			t.Errorf("apply --spec %v: printed %q and exited %d", rest, out.String(), code)
		}
		if exists(path) {
			t.Errorf("apply --spec %v left its spec file behind", rest)
		}
	}
}

func TestApplyStartsTheForwarderForReal(t *testing.T) {
	t.Parallel()
	p := newPKI(t)
	s := newTunnelServer(t, p, testEndpoint)
	root := realRoot(t, p)
	out, _, code := runApply(t, root, realSpec(s))
	eq(t, out, `{"forward":"listening","hosts":1,"secrets":1}`)
	eq(t, code, 0)
	pid, err := sandbox.ReadPidFile(root, "forward")
	must(t, err)
	addr := strings.TrimSpace(readFile(t, root.Path(addrFile)))
	open := dial(t, addr)
	eq(t, roundTrip(t, open, "through apply"), "through apply")
	eq(t, managedBlock(t, root.Path(sandbox.HostsFile)), "127.0.0.1 huggingface.co\n")
	files := snapshot(t, root)

	out, _, _ = runApply(t, root, realSpec(s))
	eq(t, out, `{"forward":"listening","hosts":1,"secrets":1}`)
	eq(t, snapshot(t, root), files)
	again, err := sandbox.ReadPidFile(root, "forward")
	must(t, err)
	eq(t, again, pid)

	rotated := realSpec(s)
	rotated.Token = otherToken
	out, _, _ = runApply(t, root, rotated)
	eq(t, out, `{"forward":"listening","hosts":1,"secrets":1}`)
	again, err = sandbox.ReadPidFile(root, "forward")
	must(t, err)
	eq(t, again, pid)
	waitFor(t, 5*time.Second, func() bool {
		_ = roundTrip(t, dial(t, addr), "new")
		reqs := s.requests()
		return reqs[len(reqs)-1].Header.Get("Authorization") == "Bearer "+otherToken
	})
	eq(t, roundTrip(t, open, "kept open"), "kept open")
}

func TestApplyUnderSystemd(t *testing.T) {
	p := newPKI(t)
	s := newTunnelServer(t, p, testEndpoint)
	root := realRoot(t, p)
	must(t, os.MkdirAll(root.Path(sandbox.SystemdDir), 0o755))
	calls := fakeSystemctl(t, root)
	out, _, code := runApply(t, root, realSpec(s))
	eq(t, out, `{"forward":"listening","hosts":1,"secrets":1}`)
	eq(t, code, 0)
	unit := readFile(t, root.Path(sandbox.UnitDir+"/bugnet-forward.service"))
	eq(t, strings.Contains(unit, "\nExecStart="+binPath+" forward --config "+
		root.Path(sandbox.EgressConfig)+" --root "+root.Dir()+"\n"), true)
	eq(t, calls(), []string{"daemon-reload", "enable --quiet bugnet-forward.service",
		"reset-failed bugnet-forward.service", "start bugnet-forward.service"})
	addr := strings.TrimSpace(readFile(t, root.Path(addrFile)))
	eq(t, roundTrip(t, dial(t, addr), "systemd"), "systemd")
}

/* Apply helpers */

// fakeForwarder stands in for the forwarder process and records what /etc/hosts held at each call
type fakeForwarder struct {
	t        *testing.T
	root     sandbox.Root
	running  bool
	startErr error
	waitErr  error
	calls    []string
	blockAt  map[string]string
}

func newFakeForwarder(t *testing.T, root sandbox.Root) *fakeForwarder {
	return &fakeForwarder{t: t, root: root, blockAt: map[string]string{}}
}

func (f *fakeForwarder) seen(step string) {
	f.t.Helper()
	if !exists(f.root.Path(sandbox.EgressConfig)) || !exists(f.root.Path(sandbox.EgressToken)) {
		f.t.Errorf("%s ran before egress.json and the token were written", step)
	}
	f.blockAt[step] = managedBlock(f.t, f.root.Path(sandbox.HostsFile))
}

func (f *fakeForwarder) Running() bool { return f.running }

func (f *fakeForwarder) Start(_ context.Context, listen string) error {
	f.calls = append(f.calls, "start "+listen)
	f.seen("start")
	if f.startErr != nil {
		return f.startErr
	}
	f.running = true
	return nil
}

func (f *fakeForwarder) Restart(context.Context) error {
	f.calls = append(f.calls, "restart")
	return nil
}

func (f *fakeForwarder) Reload() error {
	f.calls = append(f.calls, "reload")
	return nil
}

func (f *fakeForwarder) Wait(_ context.Context, listen string) error {
	f.calls = append(f.calls, "wait "+listen)
	f.seen("wait")
	return f.waitErr
}

// applyWith runs apply's steps on s with fwd and returns its line and the steps it took
func applyWith(t *testing.T, root sandbox.Root, fwd forwarder, s Spec) (string, []string) {
	t.Helper()
	var events []string
	a := applier{
		root: root, sup: sandbox.Supervisor{Root: root}, fwd: fwd,
		trace: func(step string) { events = append(events, step) },
	}
	res, err := a.apply(context.Background(), s)
	var out, errOut bytes.Buffer
	report(&out, &errOut, res, err)
	if strings.Contains(errOut.String(), "bnsec_") || strings.Contains(errOut.String(), "bnt_") {
		t.Errorf("apply's error quotes a token: %s", errOut.String())
	}
	return strings.TrimSpace(out.String()), events
}

func applyFake(t *testing.T, root sandbox.Root, s Spec) {
	t.Helper()
	fwd := newFakeForwarder(t, root)
	fwd.running = exists(root.Path(sandbox.EgressConfig))
	if out, _ := applyWith(t, root, fwd, s); strings.Contains(out, "error") {
		t.Fatalf("apply printed %s", out)
	}
}

// reasonOf returns the error value apply would print for err
func reasonOf(err error) string {
	var f *failure
	if !errors.As(err, &f) {
		return ""
	}
	return f.reason
}

func managedBlock(t *testing.T, path string) string {
	t.Helper()
	b, err := sandbox.Block(path)
	must(t, err)
	return b
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	must(t, err)
	return info.Mode().Perm()
}

// gitLogin asks git which username and password the system config's helper gives github.com
func gitLogin(t *testing.T, root sandbox.Root) []string {
	t.Helper()
	out := gitCredential(t, root, "fill", "protocol=https\nhost=github.com\n\n")
	fields := map[string]string{}
	for line := range strings.Lines(out) {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			fields[k] = v
		}
	}
	return []string{fields["username"], fields["password"]}
}

// gitCredential runs git credential with only the system config under root, returning its output
func gitCredential(t *testing.T, root sandbox.Root, action, input string) string {
	t.Helper()
	cmd := exec.Command("git", "credential", action)
	cmd.Env = []string{"GIT_CONFIG_SYSTEM=" + root.Path(sandbox.GitConfig),
		"GIT_CONFIG_GLOBAL=/dev/null", "HOME=" + t.TempDir(), "GIT_TERMINAL_PROMPT=0",
		"PATH=" + os.Getenv("PATH")}
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git credential %s: %v: %s", action, err, out)
	}
	return string(out)
}

// fakeSSHD starts a process named sshd and records it in our sshd's pid file
func fakeSSHD(t *testing.T, root sandbox.Root) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("bash", "-c", "exec -a sshd sleep 30")
	must(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	must(t, sandbox.WritePidFile(root, "sshd", cmd.Process.Pid))
	return cmd
}

// hungUp reports whether cmd ended by SIGHUP within a second, killing it otherwise
func hungUp(t *testing.T, cmd *exec.Cmd) bool {
	t.Helper()
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		_ = cmd.Process.Kill()
		<-done
		return false
	}
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && ws.Signal() == syscall.SIGHUP
}

// snapshot reads every file apply writes, with its mode
func snapshot(t *testing.T, root sandbox.Root) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, dir := range []string{sandbox.EtcDir, "/etc", "/etc/profile.d", sandbox.RunDir,
		"/home/boxd"} {
		entries, err := os.ReadDir(root.Path(dir))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		must(t, err)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(root.Path(dir), e.Name())
			out[dir+"/"+e.Name()] = mode(t, path).String() + " " + readFile(t, path)
		}
	}
	return out
}

// realRoot is a test root holding the tunnel server's CA, whose forwarder stops at the end
func realRoot(t *testing.T, p *pki) sandbox.Root {
	t.Helper()
	root := testRoot(t)
	writeFile(t, root.Path(rootsFile), string(p.pem))
	t.Cleanup(func() {
		pid, err := sandbox.ReadPidFile(root, "forward")
		if err != nil {
			return
		}
		_ = syscall.Kill(pid, syscall.SIGTERM)
		waitFor(t, 5*time.Second, func() bool { return gone(pid) })
	})
	return root
}

func realSpec(s *tunnelServer) Spec {
	sp := spec("huggingface.co")
	sp.Endpoint, sp.IPs, sp.Port, sp.Listen = testEndpoint, []string{"127.0.0.1"}, s.port,
		"127.0.0.1:0"
	return sp
}

// runApply runs apply on spec, a Spec or raw JSON, and returns its line, its stderr and its status
func runApply(t *testing.T, root sandbox.Root, spec any) (string, string, int) {
	t.Helper()
	b, ok := spec.(json.RawMessage)
	if !ok {
		var err error
		b, err = json.Marshal(spec)
		must(t, err)
	}
	path := filepath.Join(t.TempDir(), "egress-spec.json")
	must(t, os.WriteFile(path, b, 0o600))
	var out, errOut bytes.Buffer
	code := Apply([]string{"--spec", path, "--root", root.Dir()}, &out, &errOut)
	if strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("apply printed %q, want one line, stderr %q", out.String(), errOut.String())
	}
	if exists(path) {
		t.Fatal("apply left its spec file behind")
	}
	for _, v := range []string{"bnsec_", testToken, otherToken} {
		if strings.Contains(errOut.String(), v) {
			t.Errorf("apply's stderr quotes %q: %s", v, errOut.String())
		}
	}
	return strings.TrimSpace(out.String()), errOut.String(), code
}

// fakeSystemctl runs a unit's ExecStart for start, as systemd would, and records every call
func fakeSystemctl(t *testing.T, root sandbox.Root) func() []string {
	t.Helper()
	var calls []string
	systemctl = func(_ context.Context, args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		if len(args) != 2 || args[0] != "start" {
			return nil
		}
		unit, err := os.ReadFile(root.Path(sandbox.UnitDir + "/" + args[1]))
		if err != nil {
			return err
		}
		for line := range strings.Lines(string(unit)) {
			if exe, ok := strings.CutPrefix(strings.TrimSpace(line), "ExecStart="); ok {
				argv := strings.Fields(exe)
				cmd := exec.Command(argv[0], argv[1:]...)
				cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
				if err := cmd.Start(); err != nil {
					return err
				}
				go func() { _ = cmd.Wait() }()
				return nil
			}
		}
		return errors.New("unit has no ExecStart")
	}
	t.Cleanup(func() { systemctl = nil })
	return func() []string { return calls }
}
