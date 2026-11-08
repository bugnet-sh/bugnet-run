package runner

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/bugnet-sh/bugnet-run/frame"
	"github.com/bugnet-sh/bugnet-run/internal/sandbox"
)

type commandSpec struct {
	job  jobFlags
	cwd  string
	root string
	env  envFlag
	argv []string
}

func parseCommand(name string, args []string) (commandSpec, string, error) {
	var spec commandSpec
	flags := newFlags(name)
	spec.job.register(flags)
	flags.StringVar(&spec.cwd, "cwd", "", "working directory of the command")
	flags.StringVar(&spec.root, "root", "/", "directory standing for the sandbox's /")
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
	if err == nil && spec.cwd != "" {
		spec.cwd, err = workDir(spec.cwd)
	}
	var root sandbox.Root
	if err == nil {
		root, err = sandbox.NewRoot(spec.root)
	}
	if err != nil {
		return badArgs(stdout, stderr, err)
	}
	respawnBeforeJob(root)
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
	return followJob(stdout, stderr, dir, 0, 0, 0)
}

// workDir resolves cwd so the supervisor enters the same directory start checked
func workDir(cwd string) (string, error) {
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("cwd %s is not a directory", abs)
	}
	return abs, nil
}

// spawnSupervisor starts supervise in its own session with stdio on /dev/null
func spawnSupervisor(spec commandSpec) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"supervise", "--job", spec.job.id, "--dir", spec.job.dir, "--cwd", spec.cwd}
	if spec.root != "" && spec.root != "/" {
		args = append(args, "--root", spec.root)
	}
	for _, kv := range spec.env {
		args = append(args, "--env", kv)
	}
	args = append(append(args, "--"), spec.argv...)

	sandbox.CloseInherited()
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
