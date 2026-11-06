package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestInitDetectsSystemd(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	s := Supervisor{Root: r}
	eq(t, s.Init(), InitSetsid)
	must(t, os.MkdirAll(r.Path(SystemdDir), 0o755))
	eq(t, s.Init(), InitSystemd)
}

func TestUnitText(t *testing.T) {
	t.Parallel()
	s := Supervisor{Root: System}
	eq(t, s.unit(Gate), "[Unit]\nDescription=Bugnet gate\nAfter=network.target\n"+
		"StartLimitIntervalSec=60\nStartLimitBurst=10\n\n[Service]\n"+
		"ExecStart=/usr/local/lib/bugnet/bugnet-run gate --config /etc/bugnet/gate.json\n"+
		"Restart=always\nRestartSec=1\nRuntimeDirectory=bugnet\nRuntimeDirectoryPreserve=yes\n\n"+
		"[Install]\nWantedBy=multi-user.target\n")

	sshd := s.unit(SSHD)
	for _, line := range []string{
		"ExecStart=/usr/sbin/sshd -D -e -f /etc/bugnet/ssh/sshd_config",
		"RuntimeDirectory=bugnet sshd", "RuntimeDirectoryPreserve=yes", "Restart=always",
		"KillMode=process",
	} {
		eq(t, slices.Contains(strings.Split(sshd, "\n"), line), true)
	}

	eq(t, strings.Contains(s.unit(Sample), "Description=Bugnet sampler\n"), true)
	eq(t, strings.Contains(s.unit(Sample), "ExecStart=/usr/local/lib/bugnet/bugnet-run sample "+
		"--config /etc/bugnet/sample.json\n"), true)

	local := Supervisor{Root: Root{dir: "/s/bn fs"}}
	eq(t, strings.Contains(local.unit(Forward), "ExecStart=\"/s/bn fs/usr/local/lib/bugnet/"+
		"bugnet-run\" forward --config \"/s/bn fs/etc/bugnet/egress.json\" --root \"/s/bn fs\"\n"),
		true)
}

func TestUnitsNameTheRunnersOwnPath(t *testing.T) {
	t.Parallel()
	local := Supervisor{Root: Root{dir: "/s/fs"}}
	var runners []string
	for _, svc := range Services {
		if svc.Name == SSHD.Name {
			continue
		}
		runners = append(runners, svc.Name)
		for _, c := range []struct {
			s    Supervisor
			exec string
		}{
			{Supervisor{Root: System}, "ExecStart=/usr/local/lib/bugnet/bugnet-run " + svc.Name +
				" --config " + svc.Config + "\n"},
			{local, "ExecStart=/s/fs/usr/local/lib/bugnet/bugnet-run " + svc.Name + " --config " +
				"/s/fs" + svc.Config + " --root /s/fs\n"},
		} {
			eq(t, svc.argv(c.s.Root)[0], c.s.Root.Path(RunnerPath))
			if unit := c.s.unit(svc); !strings.Contains(unit, c.exec) {
				t.Errorf("unit of %s lacks %q:\n%s", svc.Name, c.exec, unit)
			}
		}
	}
	eq(t, runners, []string{"gate", "forward", "sample"})
}

func TestSystemdQuote(t *testing.T) {
	t.Parallel()
	eq(t, systemdQuote("/usr/sbin/sshd"), "/usr/sbin/sshd")
	eq(t, systemdQuote("a b"), `"a b"`)
	eq(t, systemdQuote(`say "hi" \ 100%`), `"say \"hi\" \\ 100%%"`)
	eq(t, systemdQuote("$HOME"), `"$$HOME"`)
	eq(t, systemdQuote(""), `""`)
}

func TestRunningReadsThePidFile(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	s := Supervisor{Root: r}
	svc := Service{Name: "sleeper", marker: "sleep"}
	eq(t, s.Running(svc), false)

	writeFile(t, r.Path(RunDir+"/sleeper.pid"), "garbage\n")
	eq(t, s.Running(svc), false)

	dead := exec.Command("true")
	must(t, dead.Run())
	must(t, WritePidFile(r, "sleeper", dead.Process.Pid))
	eq(t, s.Running(svc), false)

	live := exec.Command("sleep", "30")
	must(t, live.Start())
	t.Cleanup(func() { _ = live.Process.Kill(); _ = live.Wait() })
	must(t, WritePidFile(r, "sleeper", live.Process.Pid))
	eq(t, s.Running(svc), true)
	eq(t, readFile(t, r.Path(RunDir+"/sleeper.pid")), strconv.Itoa(live.Process.Pid)+"\n")

	RemovePidFile(r, "sleeper", live.Process.Pid+1)
	eq(t, s.Running(svc), true)
	RemovePidFile(r, "sleeper", live.Process.Pid)
	eq(t, s.Running(svc), false)
}

func TestAliveChecksTheCommandLine(t *testing.T) {
	procDir = t.TempDir()
	t.Cleanup(func() { procDir = "/proc" })
	live := exec.Command("sleep", "30")
	must(t, live.Start())
	t.Cleanup(func() { _ = live.Process.Kill(); _ = live.Wait() })
	pid := live.Process.Pid
	cmdline := filepath.Join(procDir, strconv.Itoa(pid), "cmdline")

	eq(t, alive(pid, Gate.marker, ""), true)
	writeFile(t, cmdline, "/usr/local/lib/bugnet/bugnet-run\x00gate\x00--config\x00"+
		"/etc/bugnet/gate.json\x00")
	eq(t, alive(pid, Gate.marker, ""), true)
	eq(t, alive(pid, Forward.marker, ""), false)
	writeFile(t, cmdline, "/usr/sbin/sshd\x00-D\x00-e\x00-f\x00/etc/bugnet/ssh/sshd_config\x00")
	eq(t, alive(pid, SSHD.marker, ""), true)
	eq(t, alive(pid, Gate.marker, ""), false)

	r := testRoot(t)
	writeFile(t, r.Path(GateConfig), "{}")
	must(t, WritePidFile(r, "gate", pid))
	for _, other := range []string{"sleep\x0030\x00", "/srv/gatekeeper\x00--gate=1\x00", ""} {
		writeFile(t, cmdline, other)
		eq(t, names(Supervisor{Root: r}.Dead()), []string{"gate"})
	}
}

// A pid another local root's service once held never counts as this root's service
func TestAliveChecksTheRoot(t *testing.T) {
	procDir = t.TempDir()
	t.Cleanup(func() { procDir = "/proc" })
	live := exec.Command("sleep", "30")
	must(t, live.Start())
	t.Cleanup(func() { _ = live.Process.Kill(); _ = live.Wait() })
	pid := live.Process.Pid
	cmdline := filepath.Join(procDir, strconv.Itoa(pid), "cmdline")

	mine, other := testRoot(t), testRoot(t)
	nested, err := NewRoot(mine.Dir() + "2")
	must(t, err)
	gateOf := func(r Root) string {
		return strings.Join(append(Gate.argv(r), ""), "\x00")
	}
	for _, r := range []Root{mine, other, nested} {
		must(t, WritePidFile(r, "gate", pid))
	}
	running := func(r Root) bool {
		if r.IsSystem() {
			return alive(pid, Gate.marker, r.Path(Gate.Config))
		}
		return Supervisor{Root: r}.Running(Gate)
	}

	writeFile(t, cmdline, gateOf(mine))
	eq(t, []bool{running(mine), running(other), running(nested), running(System)},
		[]bool{true, false, false, false})
	writeFile(t, cmdline, gateOf(other))
	eq(t, []bool{running(mine), running(other)}, []bool{false, true})
	writeFile(t, cmdline, gateOf(System))
	eq(t, []bool{running(mine), running(System)}, []bool{false, true})

	// sshd's listener rewrites its command line as one string joined by spaces
	writeFile(t, mine.Path(SSHDConfig), "Port 22\n")
	must(t, WritePidFile(mine, "sshd", pid))
	must(t, WritePidFile(other, "sshd", pid))
	writeFile(t, cmdline, "sshd: /usr/sbin/sshd -D -e -f "+mine.Path(SSHDConfig)+
		" [listener] 0 of 10-100 startups\x00")
	eq(t, Supervisor{Root: mine}.Running(SSHD), true)
	eq(t, Supervisor{Root: other}.Running(SSHD), false)
	sent, err := Supervisor{Root: other}.Signal(SSHD, syscall.SIGHUP)
	must(t, err)
	eq(t, sent, false)
	eq(t, names(Supervisor{Root: other}.Dead()), []string(nil))
	writeFile(t, other.Path(SSHDConfig), "Port 22\n")
	eq(t, names(Supervisor{Root: other}.Dead()), []string{"sshd"})
}

func TestDeadListsConfiguredServicesWithoutProcess(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	s := Supervisor{Root: r}
	eq(t, names(s.Dead()), []string(nil))
	writeFile(t, r.Path(GateConfig), "{}")
	eq(t, names(s.Dead()), []string{"gate"})
	writeFile(t, r.Path(SSHDConfig), "Port 22\n")
	eq(t, names(s.Dead()), []string{"gate", "sshd"})
	writeFile(t, r.Path(EgressConfig), "{}")
	eq(t, names(s.Dead()), []string{"gate", "forward", "sshd"})
	writeFile(t, r.Path(SampleConfig), `{"v":1}`)
	eq(t, names(s.Dead()), []string{"gate", "forward", "sshd", "sample"})
}

type fakeSystemctl struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeSystemctl) run(_ context.Context, args ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, strings.Join(args, " "))
	return nil
}

func (f *fakeSystemctl) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	calls := f.calls
	f.calls = nil
	return calls
}

func TestSystemdStartAndRestart(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	must(t, os.MkdirAll(r.Path(SystemdDir), 0o755))
	fake := &fakeSystemctl{}
	s := Supervisor{Root: r, Systemctl: fake.run}
	ctx := context.Background()

	must(t, s.Start(ctx, Gate))
	eq(t, fake.take(), []string{
		"daemon-reload", "enable --quiet bugnet-gate.service", "reset-failed bugnet-gate.service",
		"start bugnet-gate.service",
	})
	eq(t, readFile(t, r.Path(UnitDir+"/bugnet-gate.service")), s.unit(Gate))

	must(t, s.Start(ctx, Gate))
	eq(t, fake.take(), []string{"reset-failed bugnet-gate.service", "start bugnet-gate.service"})

	must(t, s.Restart(ctx, Gate))
	eq(t, fake.take(), []string{"reset-failed bugnet-gate.service", "restart bugnet-gate.service"})
}

func TestSetsidStartRunsInItsOwnSession(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	s := Supervisor{Root: r}
	svc := Service{Name: "sleeper", marker: "sleep", argv: func(Root) []string {
		return []string{"sleep", "30"}
	}}
	pid, err := s.spawn(svc)
	must(t, err)
	// Stop ended the pid, which the system may hand to another process by the cleanup
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	pgid, err := syscall.Getpgid(pid)
	must(t, err)
	eq(t, pgid, pid)
	must(t, WritePidFile(r, "sleeper", pid))

	must(t, s.Start(context.Background(), svc))
	eq(t, readFile(t, r.Path(RunDir+"/sleeper.pid")), strconv.Itoa(pid)+"\n")

	must(t, s.Stop(svc))
	stopped = true
	waitGone(t, pid)
}

func waitGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("pid %d still runs", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func names(svcs []Service) []string {
	var out []string
	for _, s := range svcs {
		out = append(out, s.Name)
	}
	return out
}

func TestSignalReachesOnlyARunningService(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	s := Supervisor{Root: r}
	svc := Service{Name: "sleeper", marker: "sleep"}
	sent, err := s.Signal(svc, syscall.SIGHUP)
	must(t, err)
	eq(t, sent, false)

	live := exec.Command("sleep", "30")
	must(t, live.Start())
	t.Cleanup(func() { _ = live.Process.Kill() })
	must(t, WritePidFile(r, "sleeper", live.Process.Pid))
	sent, err = s.Signal(svc, syscall.SIGHUP)
	must(t, err)
	eq(t, sent, true)
	err = live.Wait()
	ws, ok := live.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGHUP {
		t.Fatalf("sleep ended with %v, want SIGHUP", err)
	}
	sent, err = s.Signal(svc, syscall.SIGHUP)
	must(t, err)
	eq(t, sent, false)
}

func TestSSHDRunsTheRecordedPath(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	s := Supervisor{Root: r}
	cfg := r.Path(SSHDConfig)
	eq(t, SSHD.argv(r), []string{"/usr/sbin/sshd", "-D", "-e", "-f", cfg})

	writeFile(t, r.Path(SSHDPathFile), "/opt/homebrew/sbin/sshd\n")
	eq(t, SSHD.argv(r), []string{"/opt/homebrew/sbin/sshd", "-D", "-e", "-f", cfg})
	eq(t, strings.Contains(s.unit(SSHD), "ExecStart=/opt/homebrew/sbin/sshd -D -e -f "+cfg+"\n"),
		true)

	for _, bad := range []string{"sshd\n", "\n", "/usr/sbin/../sbin/sshd\n", "/a\n/b\n"} {
		writeFile(t, r.Path(SSHDPathFile), bad)
		eq(t, SSHD.argv(r)[0], "/usr/sbin/sshd")
	}
}

func TestSSHDPrepareMakesBothRunDirs(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	must(t, SSHD.prepare(r))
	for _, dir := range []string{SSHDRunDir, RunDir} {
		info, err := os.Stat(r.Path(dir))
		must(t, err)
		eq(t, info.IsDir(), true)
		eq(t, info.Mode().Perm(), os.FileMode(0o755))
	}
}

func TestSignalPidFileChecksTheCommandLine(t *testing.T) {
	procDir = t.TempDir()
	t.Cleanup(func() { procDir = "/proc" })
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd.pid")
	sent, err := SignalPidFile(path, "sshd", syscall.SIGTERM)
	must(t, err)
	eq(t, sent, false)

	live := exec.Command("sleep", "30")
	must(t, live.Start())
	t.Cleanup(func() { _ = live.Process.Kill(); _ = live.Wait() })
	pid := live.Process.Pid
	writeFile(t, path, strconv.Itoa(pid)+"\n")
	writeFile(t, filepath.Join(procDir, strconv.Itoa(pid), "cmdline"), "sleep\x0030\x00")
	sent, err = SignalPidFile(path, "sshd", syscall.SIGTERM)
	must(t, err)
	eq(t, sent, false)

	writeFile(t, filepath.Join(procDir, strconv.Itoa(pid), "cmdline"),
		"sshd: /usr/sbin/sshd [listener]\x00")
	sent, err = SignalPidFile(path, "sshd", syscall.SIGTERM)
	must(t, err)
	eq(t, sent, true)
	_ = live.Wait()
	ws, ok := live.ProcessState.Sys().(syscall.WaitStatus)
	eq(t, ok && ws.Signaled() && ws.Signal() == syscall.SIGTERM, true)
}

func TestClaimServiceLetsOneProcessHoldIt(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	release, ok, err := ClaimService(r, "sample")
	must(t, err)
	eq(t, ok, true)
	info, err := os.Stat(r.Path(RunDir + "/sample.lock"))
	must(t, err)
	eq(t, info.Mode().Perm(), os.FileMode(0o600))

	// A lock belongs to an open file, so a second open here stands for a second process
	_, ok, err = ClaimService(r, "sample")
	must(t, err)
	eq(t, ok, false)
	gate, ok, err := ClaimService(r, "gate")
	must(t, err)
	eq(t, ok, true)
	gate()

	release()
	// A child that another test forks holds a copy of the lock until its exec, so retry briefly
	deadline := time.Now().Add(time.Second)
	release, ok, err = ClaimService(r, "sample")
	for err == nil && !ok && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		release, ok, err = ClaimService(r, "sample")
	}
	must(t, err)
	eq(t, ok, true)
	release()

	target := filepath.Join(t.TempDir(), "target")
	writeFile(t, target, "")
	must(t, os.Symlink(target, r.Path(RunDir+"/forward.lock")))
	_, ok, err = ClaimService(r, "forward")
	eq(t, err != nil, true)
	eq(t, ok, false)
}
