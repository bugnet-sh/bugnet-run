package setup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oynozan/bugnet-run/internal/sandbox"
)

func TestSetupStartsTheGate(t *testing.T) {
	f := newFixture(t)
	out, code := f.run(t, f.spec())
	eq(t, out, `{"gate":"listening","ca":"skipped","init":"setsid"}`)
	eq(t, code, 0)
	must(t, f.healthy(testKey))

	eq(t, readFile(t, f.root.Path(sandbox.GateKeyFile)), testKey+"\n")
	var cfg map[string]any
	must(t, json.Unmarshal([]byte(readFile(t, f.root.Path(sandbox.GateConfig))), &cfg))
	eq(t, cfg, map[string]any{
		"listen": f.spec().GateListen, "key_file": "/etc/bugnet/gate.key",
		"deny":          []any{29417.0, 22.0, 2022.0, 49983.0},
		"ssh_port_file": "/etc/bugnet/ssh/port",
	})
	for path, mode := range map[string]os.FileMode{
		sandbox.EtcDir: 0o755 | os.ModeDir, sandbox.RunDir: 0o755 | os.ModeDir,
		sandbox.GateKeyFile: 0o600, sandbox.GateConfig: 0o644, sandbox.EnvFile: 0o644,
		sandbox.ProfileFile: 0o644,
	} {
		info, err := os.Stat(f.root.Path(path))
		must(t, err)
		eq(t, info.Mode()&(os.ModeDir|os.ModePerm), mode)
	}
}

func TestSetupIsIdempotent(t *testing.T) {
	f := newFixture(t)
	tool := fakeUpdateCA(t)
	s := f.spec()
	s.CAPEM, s.CAVersion = testCA(t, "Bugnet dev CA"), 1
	s.CASHA256 = sha(s.CAPEM)

	first, code := f.run(t, s)
	eq(t, first, `{"gate":"listening","ca":"installed","init":"setsid"}`)
	eq(t, code, 0)
	files, pid := snapshot(t, f.root), f.gatePid(t)

	again, code := f.run(t, s)
	eq(t, again, first)
	eq(t, code, 0)
	eq(t, snapshot(t, f.root), files)
	eq(t, f.gatePid(t), pid)
	eq(t, alive(pid), true)
	eq(t, tool.count(), 1)
	must(t, f.healthy(testKey))
}

func TestSetupNewKeyRestartsTheGate(t *testing.T) {
	f := newFixture(t)
	_, code := f.run(t, f.spec())
	eq(t, code, 0)
	pid := f.gatePid(t)

	s := f.spec()
	s.GateKey = otherKey
	out, code := f.run(t, s)
	eq(t, out, `{"gate":"listening","ca":"skipped","init":"setsid"}`)
	eq(t, code, 0)
	waitGone(t, pid)
	must(t, f.healthy(otherKey))
	eq(t, f.healthy(testKey) != nil, true)
}

func TestSetupRepairRerunsOnlyGate(t *testing.T) {
	f := newFixture(t)
	tool := fakeUpdateCA(t)
	s := f.spec()
	s.CAPEM, s.CAVersion = testCA(t, "Bugnet dev CA"), 1
	_, code := f.run(t, s)
	eq(t, code, 0)

	writeFile(t, f.root.Path(sandbox.EnvFile), "HAND=1\n")
	must(t, os.Remove(f.root.Path(sandbox.CABundle)))
	pid := f.gatePid(t)
	f.kill(t, pid, syscall.SIGKILL)

	out, code := f.run(t, s, "--repair")
	eq(t, out, `{"gate":"listening","init":"setsid"}`)
	eq(t, code, 0)
	eq(t, f.gatePid(t) != pid, true)
	must(t, f.healthy(testKey))
	eq(t, readFile(t, f.root.Path(sandbox.EnvFile)), "HAND=1\n")
	eq(t, exists(f.root.Path(sandbox.CABundle)), false)
	eq(t, tool.count(), 1)

	pid = f.gatePid(t)
	f.kill(t, pid, syscall.SIGKILL)
	out, code = f.run(t, nil, "--repair")
	eq(t, out, `{"gate":"listening","init":"setsid"}`)
	eq(t, code, 0)
	must(t, f.healthy(testKey))

	healthy := f.gatePid(t)
	out, code = f.run(t, nil, "--repair")
	eq(t, out, `{"gate":"listening","init":"setsid"}`)
	eq(t, code, 0)
	eq(t, f.gatePid(t), healthy)
}

func TestSetupRepairWithoutAnySetupIsBadSpec(t *testing.T) {
	f := newFixture(t)
	out, code := f.run(t, nil, "--repair")
	eq(t, out, `{"error":"bad_spec"}`)
	eq(t, code, 1)
	out, code = f.run(t, nil)
	eq(t, out, `{"error":"bad_spec"}`)
	eq(t, code, 1)
}

func TestSetupBakedCAMismatch(t *testing.T) {
	f := newFixture(t)
	baked := testCA(t, "baked")
	writeFile(t, f.root.Path(sandbox.CADir+"/bugnet-egress-v1.crt"), baked)
	s := f.spec()
	s.CASHA256, s.CAVersion = sha("another CA"), 1
	out, code := f.run(t, s)
	eq(t, out, `{"error":"ca_mismatch"}`)
	eq(t, code, 1)
	_, err := sandbox.ReadPidFile(f.root, "gate")
	eq(t, err != nil, true)

	s.CASHA256 = strings.ToUpper(sha(baked))
	out, code = f.run(t, s)
	eq(t, out, `{"gate":"listening","ca":"checked","init":"setsid"}`)
	eq(t, code, 0)
	eq(t, strings.Contains(readFile(t, f.root.Path(sandbox.EnvFile)),
		"NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/bugnet-egress-v1.crt\n"), true)

	s.CAVersion = 2
	out, _ = f.run(t, s)
	eq(t, out, `{"error":"ca_mismatch"}`)
}

func TestSetupPEMMustMatchItsHash(t *testing.T) {
	f := newFixture(t)
	fakeUpdateCA(t)
	s := f.spec()
	s.CAPEM, s.CASHA256, s.CAVersion = testCA(t, "a"), sha("b"), 1
	out, code := f.run(t, s)
	eq(t, out, `{"error":"ca_mismatch"}`)
	eq(t, code, 1)
	eq(t, exists(f.root.Path(sandbox.CADir+"/bugnet-egress-v1.crt")), false)
}

func TestSetupSkipsCAWithoutOne(t *testing.T) {
	f := newFixture(t)
	tool := fakeUpdateCA(t)
	out, code := f.run(t, f.spec())
	eq(t, out, `{"gate":"listening","ca":"skipped","init":"setsid"}`)
	eq(t, code, 0)
	eq(t, tool.count(), 0)
	matches, err := filepath.Glob(f.root.Path(sandbox.CADir + "/*"))
	must(t, err)
	eq(t, len(matches), 0)
	eq(t, readFile(t, f.root.Path(sandbox.EnvFile)),
		"__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS=.preview.example\n")

	s := f.spec()
	s.PreviewDomain = ""
	_, code = f.run(t, s)
	eq(t, code, 0)
	eq(t, readFile(t, f.root.Path(sandbox.EnvFile)), "")
}

func TestSetupWritesEnvAndProfile(t *testing.T) {
	f := newFixture(t)
	fakeUpdateCA(t)
	s := f.spec()
	s.CAPEM, s.CAVersion = testCA(t, "Bugnet dev CA"), 3
	_, code := f.run(t, s)
	eq(t, code, 0)
	bundle := "/etc/ssl/certs/ca-certificates.crt"
	want := "SSL_CERT_FILE=" + bundle + "\nREQUESTS_CA_BUNDLE=" + bundle + "\nCURL_CA_BUNDLE=" +
		bundle + "\nPIP_CERT=" + bundle + "\nGIT_SSL_CAINFO=" + bundle + "\nAWS_CA_BUNDLE=" +
		bundle + "\nNODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/bugnet-egress-v3.crt\n" +
		"NODE_USE_SYSTEM_CA=1\nDENO_TLS_CA_STORE=system\n" +
		"__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS=.preview.example\n"
	eq(t, readFile(t, f.root.Path(sandbox.EnvFile)), want)
	profile := readFile(t, f.root.Path(sandbox.ProfileFile))
	eq(t, strings.Contains(profile, "export SSL_CERT_FILE='"+bundle+"'\n"), true)
	eq(t, strings.Contains(profile, "export __VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS="+
		"'.preview.example'\n"), true)
	eq(t, readFile(t, f.root.Path(sandbox.CADir+"/bugnet-egress-v3.crt")), s.CAPEM)
}

func TestSetupCARotationAppends(t *testing.T) {
	f := newFixture(t)
	tool := fakeUpdateCA(t)
	s := f.spec()
	v1 := testCA(t, "Bugnet CA 1")
	s.CAPEM, s.CAVersion = v1, 1
	out, _ := f.run(t, s)
	eq(t, out, `{"gate":"listening","ca":"installed","init":"setsid"}`)
	eq(t, tool.count(), 1)

	v2 := strings.TrimSuffix(testCA(t, "Bugnet CA 2"), "\n")
	s.CAPEM, s.CAVersion = v2, 2
	out, code := f.run(t, s)
	eq(t, out, `{"gate":"listening","ca":"appended","init":"setsid"}`)
	eq(t, code, 0)
	eq(t, tool.count(), 1)
	bundle := readFile(t, f.root.Path(sandbox.CABundle))
	eq(t, bundle, "# system roots\n"+v1+v2+"\n")
	eq(t, readFile(t, f.root.Path(sandbox.CADir+"/bugnet-egress-v2.crt")), v2)
	eq(t, strings.Contains(readFile(t, f.root.Path(sandbox.EnvFile)), "bugnet-egress-v2.crt"), true)

	out, _ = f.run(t, s)
	eq(t, out, `{"gate":"listening","ca":"appended","init":"setsid"}`)
	eq(t, readFile(t, f.root.Path(sandbox.CABundle)), bundle)
	eq(t, tool.count(), 1)
}

func TestSetupInstallsWithoutTheTool(t *testing.T) {
	f := newFixture(t)
	writeFile(t, f.root.Path(sandbox.CABundle), "# system roots")
	s := f.spec()
	s.CAPEM, s.CAVersion = testCA(t, "Bugnet CA"), 1
	out, code := f.run(t, s)
	eq(t, out, `{"gate":"listening","ca":"installed","init":"setsid"}`)
	eq(t, code, 0)
	eq(t, readFile(t, f.root.Path(sandbox.CABundle)), "# system roots\n"+s.CAPEM)
}

func TestSetupBadSpec(t *testing.T) {
	f := newFixture(t)
	bad := map[string]func(*Spec){
		"version":       func(s *Spec) { s.V = 2 },
		"short key":     func(s *Spec) { s.GateKey = testKey[:42] },
		"key alphabet":  func(s *Spec) { s.GateKey = testKey[:42] + "+" },
		"no listen":     func(s *Spec) { s.GateListen = "" },
		"listen port 0": func(s *Spec) { s.GateListen = ":0" },
		"deny port":     func(s *Spec) { s.DenyPorts = []int{70000} },
		"pem":           func(s *Spec) { s.CAPEM, s.CAVersion = "not a certificate", 1 },
		"sha":           func(s *Spec) { s.CASHA256, s.CAVersion = "abc", 1 },
		"ca version":    func(s *Spec) { s.CASHA256 = sha("x") },
		"domain":        func(s *Spec) { s.PreviewDomain = "a b\nX=1" },
		"dot domain":    func(s *Spec) { s.PreviewDomain = ".preview.example" },
	}
	for name, change := range bad {
		s := f.spec()
		change(&s)
		out, code := f.run(t, s)
		if out != `{"error":"bad_spec"}` || code != 1 {
			t.Errorf("%s: printed %s and exited %d", name, out, code)
		}
	}
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"v": 1, "gate_key": "` + testKey + `", "gate_listen": ":29417", "x": 1}`),
		json.RawMessage(`not json`),
	} {
		out, code := f.run(t, raw)
		eq(t, out, `{"error":"bad_spec"}`)
		eq(t, code, 1)
	}
	eq(t, exists(f.root.Path(sandbox.GateKeyFile)), false)
}

func TestSetupGateFailed(t *testing.T) {
	f := newFixture(t)
	ln, err := net.Listen("tcp", f.spec().GateListen)
	must(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	out, code := f.run(t, f.spec())
	eq(t, out, `{"error":"gate_failed"}`)
	eq(t, code, 1)
}

func TestSetupWriteFailureIsGateFailed(t *testing.T) {
	t.Parallel()
	for _, blocker := range []string{sandbox.EtcDir, sandbox.GateKeyFile, sandbox.EnvFile} {
		f := newFixture(t)
		if blocker == sandbox.EtcDir {
			writeFile(t, f.root.Path(blocker), "a file where a directory belongs\n")
		} else {
			must(t, os.MkdirAll(f.root.Path(blocker), 0o755))
		}
		out, code := f.run(t, f.spec())
		eq(t, out, `{"error":"gate_failed"}`)
		eq(t, code, 1)
	}
}

func TestSetupUnderSystemd(t *testing.T) {
	f := newFixture(t)
	must(t, os.MkdirAll(f.root.Path(sandbox.SystemdDir), 0o755))
	fake := fakeSystemctl(t, f)
	out, code := f.run(t, f.spec())
	eq(t, out, `{"gate":"listening","ca":"skipped","init":"systemd"}`)
	eq(t, code, 0)
	eq(t, fake.take(), []string{
		"daemon-reload", "enable --quiet bugnet-gate.service", "reset-failed bugnet-gate.service",
		"restart bugnet-gate.service",
	})
	unit := readFile(t, f.root.Path(sandbox.UnitDir+"/bugnet-gate.service"))
	for _, line := range []string{
		"ExecStart=" + f.root.Path(sandbox.RunnerPath) + " gate --config " +
			f.root.Path(sandbox.GateConfig) + " --root " + f.root.Dir(),
		"Restart=always", "RuntimeDirectory=bugnet", "RuntimeDirectoryPreserve=yes",
		"WantedBy=multi-user.target",
	} {
		if !bytes.Contains([]byte(unit), []byte(line+"\n")) {
			t.Errorf("unit lacks %q:\n%s", line, unit)
		}
	}
	must(t, f.healthy(testKey))
	pid := f.gatePid(t)

	out, _ = f.run(t, f.spec())
	eq(t, out, `{"gate":"listening","ca":"skipped","init":"systemd"}`)
	eq(t, fake.take(), []string(nil))
	eq(t, f.gatePid(t), pid)
}

func TestSetupCopiesTheRunnerBeforeAnyUnit(t *testing.T) {
	slowStart(t)
	f := freshFixture(t)
	must(t, os.MkdirAll(f.root.Path(sandbox.SystemdDir), 0o755))
	fake := fakeSystemctl(t, f)
	out, code := f.run(t, f.spec())
	eq(t, out, `{"gate":"listening","ca":"skipped","init":"systemd"}`)
	eq(t, code, 0)
	eq(t, len(fake.take()), 4)
	runner := f.root.Path(sandbox.RunnerPath)
	info, err := os.Stat(runner)
	must(t, err)
	eq(t, info.Mode().Perm(), os.FileMode(0o755))
	built, err := os.Stat(binPath)
	must(t, err)
	eq(t, os.SameFile(info, built), false)
	eq(t, sameContent(t, runner, binPath), true)
	unit := readFile(t, f.root.Path(sandbox.UnitDir+"/bugnet-gate.service"))
	eq(t, strings.Contains(unit, "\nExecStart="+runner+" gate "), true)
	eq(t, strings.HasPrefix(command(t, f.gatePid(t)), runner+" gate --config "), true)

	// A second setup with the same binary leaves the copy as it was
	must(t, f.healthy(testKey))
	out, code = f.run(t, f.spec())
	eq(t, out, `{"gate":"listening","ca":"skipped","init":"systemd"}`)
	eq(t, code, 0)
	again, err := os.Stat(runner)
	must(t, err)
	eq(t, os.SameFile(again, info) && again.ModTime().Equal(info.ModTime()), true)
	eq(t, leftovers(t, filepath.Dir(runner)), []string{"bugnet-run"})
}

func TestSetupReplacesAnOlderRunner(t *testing.T) {
	slowStart(t)
	f := freshFixture(t)
	runner := f.root.Path(sandbox.RunnerPath)
	writeFile(t, runner, "#!/bin/sh\nexit 1\n")
	must(t, os.Chmod(runner, 0o755))
	// The gate an older setup started still runs from the older file, which a rename keeps
	held := filepath.Join(t.TempDir(), "held")
	must(t, os.Link(runner, held))

	out, code := f.run(t, f.spec())
	eq(t, out, `{"gate":"listening","ca":"skipped","init":"setsid"}`)
	eq(t, code, 0)
	eq(t, sameContent(t, runner, binPath), true)
	eq(t, readFile(t, held), "#!/bin/sh\nexit 1\n")
	eq(t, leftovers(t, filepath.Dir(runner)), []string{"bugnet-run"})
	eq(t, strings.HasPrefix(command(t, f.gatePid(t)), runner+" gate --config "), true)
}

func sameContent(t *testing.T, a, b string) bool {
	t.Helper()
	x, err := os.ReadFile(a)
	must(t, err)
	y, err := os.ReadFile(b)
	must(t, err)
	return bytes.Equal(x, y)
}

func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	must(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestSetupWaitsForTheSandboxLock(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	must(t, os.MkdirAll(f.root.Path(sandbox.EtcDir), 0o755))
	unlock, err := sandbox.Lock(f.root)
	must(t, err)
	locked := true
	t.Cleanup(func() {
		if locked {
			unlock()
		}
	})
	args := []string{"--spec", f.specFile(t, f.spec()), "--root", f.root.Dir()}
	done := make(chan string, 1)
	go func() {
		var out, errOut bytes.Buffer
		code := Run(args, &out, &errOut)
		done <- fmt.Sprintf("%d %s", code, strings.TrimSpace(out.String()))
	}()

	select {
	case got := <-done:
		t.Fatalf("setup finished as %q while respawn held the sandbox lock", got)
	case <-time.After(300 * time.Millisecond):
	}
	eq(t, exists(f.root.Path(sandbox.GateKeyFile)), false)
	locked = false
	unlock()
	select {
	case got := <-done:
		eq(t, got, `0 {"gate":"listening","ca":"skipped","init":"setsid"}`)
	case <-time.After(15 * time.Second):
		t.Fatal("setup did not finish once the lock was free")
	}
}

// samplerPid waits for the sampler setup started to record itself
func (f *fixture) samplerPid(t *testing.T) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		pid, err := sandbox.ReadPidFile(f.root, "sample")
		if err == nil && alive(pid) {
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("no sampler runs: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSetupStartsTheSampler(t *testing.T) {
	f := newFixture(t)
	s := f.spec()
	s.Sample = true
	out, code := f.run(t, s)
	eq(t, out, `{"gate":"listening","ca":"skipped","init":"setsid"}`)
	eq(t, code, 0)
	eq(t, readFile(t, f.root.Path(sandbox.SampleConfig)), "{\"v\":1}\n")
	info, err := os.Stat(f.root.Path(sandbox.SampleConfig))
	must(t, err)
	eq(t, info.Mode().Perm(), os.FileMode(0o644))
	pid := f.samplerPid(t)

	_, code = f.run(t, s)
	eq(t, code, 0)
	eq(t, f.samplerPid(t), pid)

	// A later spec without sample leaves the running sampler and its config alone
	s.Sample = false
	_, code = f.run(t, s)
	eq(t, code, 0)
	eq(t, f.samplerPid(t), pid)
	eq(t, readFile(t, f.root.Path(sandbox.SampleConfig)), "{\"v\":1}\n")

	// A repair touches only the gate
	_, code = f.run(t, nil, "--repair")
	eq(t, code, 0)
	eq(t, f.samplerPid(t), pid)
}

// A respawn right after setup finds no pid file yet and starts a second sampler, which must yield
func TestSetupThenRespawnRunsOneSampler(t *testing.T) {
	f := newFixture(t)
	t.Cleanup(func() {
		for _, pid := range f.samplers(t) {
			f.kill(t, pid, syscall.SIGTERM)
		}
	})
	s := f.spec()
	s.Sample = true
	_, code := f.run(t, s)
	eq(t, code, 0)
	must(t, sandbox.Supervisor{Root: f.root}.Start(t.Context(), sandbox.Sample))
	pid := f.samplerPid(t)
	deadline := time.Now().Add(3 * time.Second)
	for running := f.samplers(t); len(running) != 1; running = f.samplers(t) {
		if time.Now().After(deadline) {
			t.Fatalf("samplers %v run, want only %d", running, pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
	eq(t, f.samplers(t), []int{pid})
}

// samplers lists the sampler processes of this fixture's root, which only this test starts
func (f *fixture) samplers(t *testing.T) []int {
	t.Helper()
	out, err := exec.Command("ps", "-A", "-o", "pid=", "-o", "command=").Output()
	must(t, err)
	mark := " sample --config " + f.root.Path(sandbox.SampleConfig) + " "
	var pids []int
	for line := range strings.Lines(string(out)) {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.Contains(line+" ", mark) {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		must(t, err)
		pids = append(pids, pid)
	}
	return pids
}

func TestSetupWithoutSampleStartsNone(t *testing.T) {
	f := newFixture(t)
	_, code := f.run(t, f.spec())
	eq(t, code, 0)
	eq(t, exists(f.root.Path(sandbox.SampleConfig)), false)
	_, err := sandbox.ReadPidFile(f.root, "sample")
	eq(t, err != nil, true)
}

func TestSetupSamplerUnderSystemd(t *testing.T) {
	f := newFixture(t)
	must(t, os.MkdirAll(f.root.Path(sandbox.SystemdDir), 0o755))
	fake := fakeSystemctl(t, f)
	s := f.spec()
	s.Sample = true
	_, code := f.run(t, s)
	eq(t, code, 0)
	eq(t, fake.take(), []string{
		"daemon-reload", "enable --quiet bugnet-gate.service", "reset-failed bugnet-gate.service",
		"restart bugnet-gate.service", "daemon-reload", "enable --quiet bugnet-sample.service",
		"reset-failed bugnet-sample.service", "start bugnet-sample.service",
	})
	unit := readFile(t, f.root.Path(sandbox.UnitDir+"/bugnet-sample.service"))
	want := "ExecStart=" + f.root.Path(sandbox.RunnerPath) + " sample --config " +
		f.root.Path(sandbox.SampleConfig) + " --root " + f.root.Dir() + "\n"
	eq(t, strings.Contains(unit, want), true)
	f.samplerPid(t)
}

func TestSetupSamplerFailureNeverFailsSetup(t *testing.T) {
	f := newFixture(t)
	// A directory where the config goes cannot be written over
	must(t, os.MkdirAll(f.root.Path(sandbox.SampleConfig), 0o755))
	s := f.spec()
	s.Sample = true
	out, code := f.run(t, s)
	eq(t, out, `{"gate":"listening","ca":"skipped","init":"setsid"}`)
	eq(t, code, 0)
}
