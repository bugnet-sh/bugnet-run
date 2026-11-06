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

	"github.com/oynozan/bugnet-run/internal/sandbox"
)

// Shell conventions for a command that could not be started
const (
	codeCannotRun = 126
	codeNotFound  = 127
)

// supervise writes stats and exit after the command, and spid so followers notice if it dies first
func supervise(args []string) int {
	spec, dir, err := parseCommand("supervise", args)
	if err != nil {
		return exitBadArgs
	}
	if dir, err = filepath.Abs(dir); err != nil {
		return exitFailed
	}
	code, st := runCommand(dir, spec)
	if st != nil {
		_ = writeStats(dir, *st)
	}
	exit := []byte(strconv.Itoa(code) + "\n")
	if err := writeAtomic(filepath.Join(dir, exitFile), exit); err != nil {
		return exitFailed
	}
	return exitOK
}

// runCommand returns the command's exit code, or 128 plus the signal that ended it, and its peaks
func runCommand(dir string, spec commandSpec) (int, *jobStats) {
	outF, err := openAppend(filepath.Join(dir, outFile))
	if err != nil {
		return codeCannotRun, nil
	}
	defer func() { _ = outF.Close() }()
	errF, err := openAppend(filepath.Join(dir, errFile))
	if err != nil {
		return codeCannotRun, nil
	}
	defer func() { _ = errF.Close() }()
	if err := writePid(filepath.Join(dir, spidFile), os.Getpid()); err != nil {
		_, _ = fmt.Fprintf(errF, "bugnet-run: %v\n", err)
	}

	cmd, err := prepare(spec)
	var job *measured
	if err == nil {
		cmd.Stdout, cmd.Stderr = outF, errF
		job = jobMeter.begin(spec.job.id)
		cmd, err = job.start(cmd)
	}
	if err != nil {
		_, _ = fmt.Fprintf(errF, "bugnet-run: %v\n", err)
		// Only a failed lookup is 127, since a vanished cwd is ENOENT as well
		var lookup *exec.Error
		if errors.As(err, &lookup) &&
			(errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist)) {
			return codeNotFound, nil
		}
		return codeCannotRun, nil
	}

	if err := writePid(filepath.Join(dir, pidFile), cmd.Process.Pid); err != nil {
		_, _ = fmt.Fprintf(errF, "bugnet-run: %v\n", err)
	}
	err = cmd.Wait()
	if cmd.ProcessState == nil {
		_, _ = fmt.Fprintf(errF, "bugnet-run: %v\n", err)
		job.drop()
		return exitFailed, nil
	}
	code := cmd.ProcessState.ExitCode()
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		code = 128 + int(ws.Signal())
	}
	st := job.finish(cmd.ProcessState, code)
	return code, &st
}

// prepare applies cwd and env to the supervisor itself so PATH lookups see the command's view
func prepare(spec commandSpec) (*exec.Cmd, error) {
	root, err := sandbox.NewRoot(spec.root)
	if err != nil {
		return nil, err
	}
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
	if err := setLocale(spec.env); err != nil {
		return nil, err
	}
	// Read at every job start, so a secret added a moment ago reaches the next command
	for _, file := range []string{sandbox.EnvFile, sandbox.SecretsEnvFile} {
		vars, err := sandbox.ReadEnvFile(root.Path(file))
		if err != nil {
			continue
		}
		for _, v := range vars {
			if err := os.Setenv(v.Name, v.Value); err != nil {
				return nil, err
			}
		}
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

// setLocale gives jobs a UTF-8 locale every image has, unless the request names its own
func setLocale(env envFlag) error {
	var lang, lcAll, lcOther bool
	for _, kv := range env {
		switch k, _, _ := strings.Cut(kv, "="); {
		case k == "LANG":
			lang = true
		case k == "LC_ALL":
			lcAll = true
		case strings.HasPrefix(k, "LC_"):
			lcOther = true
		}
	}
	if !lang {
		if err := os.Setenv("LANG", "C.UTF-8"); err != nil {
			return err
		}
	}
	switch {
	case lcAll:
		return nil
	case lang || lcOther:
		// LC_ALL would mask the locale the request names
		return os.Unsetenv("LC_ALL")
	}
	return os.Setenv("LC_ALL", "C.UTF-8")
}

func openAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}
