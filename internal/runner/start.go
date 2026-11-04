package runner

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/oynozan/bugnet-run/frame"
)

// commandSpec is what start parses and hands on to supervise
type commandSpec struct {
	job  jobFlags
	cwd  string
	env  envFlag
	argv []string
}

func parseCommand(name string, args []string) (commandSpec, string, error) {
	var spec commandSpec
	flags := newFlags(name)
	spec.job.register(flags)
	flags.StringVar(&spec.cwd, "cwd", "", "working directory of the command")
	flags.Var(&spec.env, "env", "K=V added to the command's environment, repeatable")
	if err := flags.Parse(args); err != nil {
		return spec, "", err
	}
	spec.argv = flags.Args()
	if len(spec.argv) == 0 {
		return spec, "", errors.New("missing command")
	}
	dir, err := spec.job.path()
	return spec, dir, err
}

func start(args []string, stdout, stderr io.Writer) int {
	spec, dir, err := parseCommand("start", args)
	if err != nil {
		return badArgs(stdout, stderr, err)
	}
	if err := os.MkdirAll(spec.job.dir, 0o700); err != nil {
		return failed(stderr, err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fail(stdout, stderr, frame.ReasonJobExists, exitJobExists, nil)
		}
		return failed(stderr, err)
	}
	if err := spawnSupervisor(spec); err != nil {
		_ = os.RemoveAll(dir)
		return fail(stdout, stderr, frame.ReasonSpawnFailed, exitSpawnFailed, err)
	}
	return followJob(stdout, stderr, dir, 0, 0)
}

// spawnSupervisor starts supervise in its own session with stdio on /dev/null
func spawnSupervisor(spec commandSpec) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"supervise", "--job", spec.job.id, "--dir", spec.job.dir, "--cwd", spec.cwd}
	for _, kv := range spec.env {
		args = append(args, "--env", kv)
	}
	args = append(append(args, "--"), spec.argv...)

	markInheritedCloseOnExec()
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// markInheritedCloseOnExec keeps descriptors start inherited from its caller out of the supervisor
func markInheritedCloseOnExec() {
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
