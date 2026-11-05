package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Init names how a sandbox keeps Bugnet processes running
type Init string

// The two ways a sandbox supervises Bugnet processes
const (
	InitSystemd Init = "systemd"
	InitSetsid  Init = "setsid"
)

const (
	stopGrace        = 3 * time.Second
	systemctlTimeout = 30 * time.Second
)

// Service is a long-running Bugnet process that setup and respawn keep running
type Service struct {
	// Name names the service's pid file and its unit
	Name string
	// Config is the sandbox path whose presence means the service should run
	Config      string
	description string
	runtimeDirs string
	killProcess bool
	// marker appears in the process's command line, so a reused pid is never taken for it
	marker  string
	prepare func(Root) error
	argv    func(r Root, exe string) []string
}

// Gate is the bugnet-run gate in front of the sandbox's ports
var Gate = Service{
	Name: "gate", Config: GateConfig, description: "Bugnet gate", runtimeDirs: "bugnet",
	marker: "\x00gate\x00", argv: runnerArgv("gate", GateConfig),
}

// Forward is the bugnet-run forwarder that tunnels secret hosts
var Forward = Service{
	Name: "forward", Config: EgressConfig, description: "Bugnet forwarder", runtimeDirs: "bugnet",
	marker: "\x00forward\x00", argv: runnerArgv("forward", EgressConfig),
}

// SSHD is the sandbox's own sshd behind the gate's SSH path
var SSHD = Service{
	Name: "sshd", Config: SSHDConfig, description: "Bugnet sshd", runtimeDirs: "bugnet sshd",
	killProcess: true, marker: "sshd", prepare: makeSSHDRunDir,
	argv: func(r Root, _ string) []string {
		return []string{"/usr/sbin/sshd", "-D", "-e", "-f", r.Path(SSHDConfig)}
	},
}

// Services lists every service respawn brings back, in start order
var Services = []Service{Gate, Forward, SSHD}

func runnerArgv(sub, config string) func(Root, string) []string {
	return func(r Root, exe string) []string {
		return append([]string{exe, sub, "--config", r.Path(config)}, r.Args()...)
	}
}

// makeSSHDRunDir creates sshd's privilege separation directory, which a boot empties
func makeSSHDRunDir(r Root) error {
	dir := r.Path(SSHDRunDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.Chmod(dir, 0o755)
}

// Supervisor runs services under systemd where the sandbox boots it, else each in its own session
type Supervisor struct {
	Root Root
	// Exe is the bugnet-run binary the gate and the forwarder run from
	Exe string
	// Systemctl runs systemctl, nil meaning the real one
	Systemctl func(ctx context.Context, args ...string) error
}

// Init reports whether the sandbox boots systemd
func (s Supervisor) Init() Init {
	if exists(s.Root.Path(SystemdDir)) {
		return InitSystemd
	}
	return InitSetsid
}

// Running reports whether the process the service's pid file names is alive and is that service
func (s Supervisor) Running(svc Service) bool {
	pid, err := ReadPidFile(s.Root, svc.Name)
	return err == nil && alive(pid, svc.marker)
}

// Dead lists the services whose config exists and whose process is gone
func (s Supervisor) Dead() []Service {
	var dead []Service
	for _, svc := range Services {
		if exists(s.Root.Path(svc.Config)) && !s.Running(svc) {
			dead = append(dead, svc)
		}
	}
	return dead
}

// Start makes sure the service runs, leaving a running one alone
func (s Supervisor) Start(ctx context.Context, svc Service) error {
	if svc.prepare != nil {
		if err := svc.prepare(s.Root); err != nil {
			return err
		}
	}
	if s.Init() == InitSystemd {
		return s.systemd(ctx, svc, "start")
	}
	if s.Running(svc) {
		return nil
	}
	_, err := s.spawn(svc)
	return err
}

// Restart stops the service if it runs and starts it again
func (s Supervisor) Restart(ctx context.Context, svc Service) error {
	if svc.prepare != nil {
		if err := svc.prepare(s.Root); err != nil {
			return err
		}
	}
	if s.Init() == InitSystemd {
		return s.systemd(ctx, svc, "restart")
	}
	if err := s.Stop(svc); err != nil {
		return err
	}
	_, err := s.spawn(svc)
	return err
}

// Stop ends the process the service's pid file names, with SIGKILL after a grace period
func (s Supervisor) Stop(svc Service) error {
	pid, err := ReadPidFile(s.Root, svc.Name)
	if err != nil || !alive(pid, svc.marker) {
		return nil
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	if waitDead(pid, svc.marker, stopGrace) {
		return nil
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	if !waitDead(pid, svc.marker, time.Second) {
		return fmt.Errorf("%s pid %d survived SIGKILL", svc.Name, pid)
	}
	return nil
}

func waitDead(pid int, marker string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for alive(pid, marker) {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}

// Install writes and enables the service's unit when it changed, and does nothing without systemd
func (s Supervisor) Install(ctx context.Context, svc Service) error {
	if s.Init() != InitSystemd {
		return nil
	}
	unit := unitName(svc)
	changed, err := WriteFile(s.Root.Path(UnitDir+"/"+unit), []byte(s.unit(svc)), 0o644)
	if err != nil || !changed {
		return err
	}
	if err := s.systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	return s.systemctl(ctx, "enable", "--quiet", unit)
}

func (s Supervisor) systemd(ctx context.Context, svc Service, verb string) error {
	if err := s.Install(ctx, svc); err != nil {
		return err
	}
	// A unit that restarted too often stays failed until this, whatever Restart says
	_ = s.systemctl(ctx, "reset-failed", unitName(svc))
	return s.systemctl(ctx, verb, unitName(svc))
}

func unitName(svc Service) string {
	return "bugnet-" + svc.Name + ".service"
}

func (s Supervisor) unit(svc Service) string {
	argv := svc.argv(s.Root, s.Exe)
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = systemdQuote(a)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Unit]\nDescription=%s\nAfter=network.target\nStartLimitIntervalSec=0\n\n",
		svc.description)
	fmt.Fprintf(&b, "[Service]\nExecStart=%s\nRestart=always\nRestartSec=1\n",
		strings.Join(quoted, " "))
	if svc.killProcess {
		b.WriteString("KillMode=process\n")
	}
	fmt.Fprintf(&b, "RuntimeDirectory=%s\nRuntimeDirectoryPreserve=yes\n\n", svc.runtimeDirs)
	b.WriteString("[Install]\nWantedBy=multi-user.target\n")
	return b.String()
}

// systemdQuote quotes one ExecStart word so systemd neither splits nor expands it
func systemdQuote(s string) string {
	plain := s != ""
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.ContainsRune("/._-:=+,@", c):
		default:
			plain = false
		}
	}
	if plain {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$")
	return `"` + r.Replace(s) + `"`
}

func (s Supervisor) systemctl(ctx context.Context, args ...string) error {
	if s.Systemctl != nil {
		return s.Systemctl(ctx, args...)
	}
	ctx, cancel := context.WithTimeout(ctx, systemctlTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err,
			bytes.TrimSpace(out))
	}
	return nil
}

// spawn starts the service in its own session with stdio on /dev/null
func (s Supervisor) spawn(svc Service) (int, error) {
	argv := svc.argv(s.Root, s.Exe)
	CloseInherited()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	go func() { _ = cmd.Wait() }()
	return cmd.Process.Pid, nil
}

// CloseInherited marks descriptors above stderr close-on-exec so no child inherits them
func CloseInherited() {
	for _, dir := range []string{"/dev/fd", "/proc/self/fd"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if fd, err := strconv.Atoi(e.Name()); err == nil && fd > 2 {
				syscall.CloseOnExec(fd)
			}
		}
		return
	}
}

/* Pid files */

func pidPath(r Root, name string) string {
	return filepath.Join(r.Path(RunDir), name+".pid")
}

// WritePidFile records pid as the process of the named service
func WritePidFile(r Root, name string, pid int) error {
	_, err := WriteFile(pidPath(r, name), []byte(strconv.Itoa(pid)+"\n"), 0o644)
	return err
}

// RemovePidFile deletes the named service's pid file while it still names pid
func RemovePidFile(r Root, name string, pid int) {
	if got, err := ReadPidFile(r, name); err == nil && got == pid {
		_ = os.Remove(pidPath(r, name))
	}
}

// ReadPidFile returns the pid the named service recorded
func ReadPidFile(r Root, name string) (int, error) {
	b, err := os.ReadFile(pidPath(r, name))
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	pid, err := strconv.ParseInt(s, 10, 32)
	if err != nil || pid <= 1 || strings.TrimLeft(s, "0123456789") != "" {
		return 0, fmt.Errorf("pid file of %s holds %q", name, s)
	}
	return int(pid), nil
}

// procDir is where process command lines are read, a variable so tests can fake them
var procDir = "/proc"

// alive trusts kill alone where /proc is missing or hides the process, as for another user's
func alive(pid int, marker string) bool {
	if err := syscall.Kill(pid, 0); err != nil && !errors.Is(err, syscall.EPERM) {
		return false
	}
	cmdline, err := os.ReadFile(filepath.Join(procDir, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return true
	}
	return strings.Contains("\x00"+string(cmdline), marker)
}
