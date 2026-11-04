package runner

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Shell conventions for a command that could not be started
const (
	codeCannotRun = 126
	codeNotFound  = 127
)

// supervise writes the exit file after the command, and spid so followers notice if it dies first
func supervise(args []string) int {
	spec, dir, err := parseCommand("supervise", args)
	if err != nil {
		return exitBadArgs
	}
	if dir, err = filepath.Abs(dir); err != nil {
		return exitFailed
	}
	code := []byte(strconv.Itoa(runCommand(dir, spec)) + "\n")
	if err := writeAtomic(filepath.Join(dir, exitFile), code); err != nil {
		return exitFailed
	}
	return exitOK
}

// runCommand returns the command's exit code, or 128 plus the signal that ended it
func runCommand(dir string, spec commandSpec) int {
	outF, err := openAppend(filepath.Join(dir, outFile))
	if err != nil {
		return codeCannotRun
	}
	defer func() { _ = outF.Close() }()
	errF, err := openAppend(filepath.Join(dir, errFile))
	if err != nil {
		return codeCannotRun
	}
	defer func() { _ = errF.Close() }()
	if err := writePid(filepath.Join(dir, spidFile), os.Getpid()); err != nil {
		_, _ = fmt.Fprintf(errF, "bugnet-run: %v\n", err)
	}

	cmd, err := prepare(spec)
	if err == nil {
		cmd.Stdout, cmd.Stderr = outF, errF
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		err = cmd.Start()
	}
	if err != nil {
		_, _ = fmt.Fprintf(errF, "bugnet-run: %v\n", err)
		// Only a failed lookup is 127, since a vanished cwd is ENOENT as well
		var lookup *exec.Error
		if errors.As(err, &lookup) &&
			(errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist)) {
			return codeNotFound
		}
		return codeCannotRun
	}

	if err := writePid(filepath.Join(dir, pidFile), cmd.Process.Pid); err != nil {
		_, _ = fmt.Fprintf(errF, "bugnet-run: %v\n", err)
	}
	err = cmd.Wait()
	if cmd.ProcessState == nil {
		_, _ = fmt.Fprintf(errF, "bugnet-run: %v\n", err)
		return exitFailed
	}
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return cmd.ProcessState.ExitCode()
}

// prepare applies cwd and env to the supervisor itself so PATH lookups see the command's view
func prepare(spec commandSpec) (*exec.Cmd, error) {
	if spec.cwd != "" {
		cwd, err := filepath.Abs(spec.cwd)
		if err != nil {
			return nil, err
		}
		if err := os.Chdir(cwd); err != nil {
			return nil, err
		}
		if err := os.Setenv("PWD", cwd); err != nil {
			return nil, err
		}
	}
	if err := os.Setenv("PYTHONUNBUFFERED", "1"); err != nil {
		return nil, err
	}
	for _, kv := range spec.env {
		k, v, _ := strings.Cut(kv, "=")
		if err := os.Setenv(k, v); err != nil {
			return nil, err
		}
	}
	// Resolve before stdbuf so a missing command reads the same with or without it
	if _, err := exec.LookPath(spec.argv[0]); err != nil {
		return nil, err
	}
	if stdbuf, err := exec.LookPath("stdbuf"); err == nil {
		return exec.Command(stdbuf, append([]string{"-oL", "-eL"}, spec.argv...)...), nil
	}
	return exec.Command(spec.argv[0], spec.argv[1:]...), nil
}

func openAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}
