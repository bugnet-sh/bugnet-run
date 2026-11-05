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
	s := Supervisor{Root: r, Exe: "/tmp/bugnet/bin/bugnet-run"}
	eq(t, s.Init(), InitSetsid)
	must(t, os.MkdirAll(r.Path(SystemdDir), 0o755))
	eq(t, s.Init(), InitSystemd)
}

func TestUnitText(t *testing.T) {
	t.Parallel()
	s := Supervisor{Root: System, Exe: "/tmp/bugnet/bin/bugnet-run"}
	eq(t, s.unit(Gate), "[Unit]\nDescription=Bugnet gate\nAfter=network.target\n"+
		"StartLimitIntervalSec=60\nStartLimitBurst=10\n\n[Service]\n"+
		"ExecStart=/tmp/bugnet/bin/bugnet-run gate --config /etc/bugnet/gate.json\n"+
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

	local := Supervisor{Root: Root{dir: "/s/fs"}, Exe: "/opt/bn run/bugnet-run"}
	eq(t, strings.Contains(local.unit(Forward), "ExecStart=\"/opt/bn run/bugnet-run\" forward "+
		"--config /s/fs/etc/bugnet/egress.json --root /s/fs\n"), true)
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

	eq(t, alive(pid, Gate.marker), true)
	writeFile(t, cmdline, "/tmp/bugnet/bin/bugnet-run\x00gate\x00--config\x00/etc/gate.json\x00")
	eq(t, alive(pid, Gate.marker), true)
	eq(t, alive(pid, Forward.marker), false)
	writeFile(t, cmdline, "/usr/sbin/sshd\x00-D\x00-e\x00-f\x00/etc/bugnet/ssh/sshd_config\x00")
	eq(t, alive(pid, SSHD.marker), true)
	eq(t, alive(pid, Gate.marker), false)

	r := testRoot(t)
	writeFile(t, r.Path(GateConfig), "{}")
	must(t, WritePidFile(r, "gate", pid))
	for _, other := range []string{"sleep\x0030\x00", "/srv/gatekeeper\x00--gate=1\x00", ""} {
		writeFile(t, cmdline, other)
		eq(t, names(Supervisor{Root: r}.Dead()), []string{"gate"})
	}
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
	s := Supervisor{Root: r, Exe: "/tmp/bugnet/bin/bugnet-run", Systemctl: fake.run}
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
	svc := Service{Name: "sleeper", marker: "sleep", argv: func(Root, string) []string {
		return []string{"sleep", "30"}
	}}
	pid, err := s.spawn(svc)
	must(t, err)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	pgid, err := syscall.Getpgid(pid)
	must(t, err)
	eq(t, pgid, pid)
	must(t, WritePidFile(r, "sleeper", pid))

	must(t, s.Start(context.Background(), svc))
	eq(t, readFile(t, r.Path(RunDir+"/sleeper.pid")), strconv.Itoa(pid)+"\n")

	must(t, s.Stop(svc))
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
