package runner

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const killGrace = 5 * time.Second

func cancel(args []string, stdout, stderr io.Writer) int {
	dir, status := lookupJob(newFlags("cancel"), args, stdout, stderr)
	if status != exitOK {
		return status
	}
	pgid, err := waitForPid(dir)
	if errors.Is(err, errBadPid) {
		return badArgs(stdout, stderr, err)
	}
	if err != nil {
		return failed(stderr, err)
	}
	if pgid == 0 {
		return exitOK
	}
	if err := stopGroup(pgid); err != nil {
		return failed(stderr, err)
	}
	return exitOK
}

// waitForPid returns the command's process group, or zero once the job ended without starting one
func waitForPid(dir string) (int, error) {
	deadline := time.Now().Add(killGrace)
	for {
		// Checked first since pid, if ever written, precedes the exit file and the supervisor death
		ended := exists(filepath.Join(dir, exitFile)) || supervisorGone(dir)
		b, err := os.ReadFile(filepath.Join(dir, pidFile))
		switch {
		case err == nil:
			return parsePid(b)
		case !errors.Is(err, fs.ErrNotExist):
			return 0, err
		case ended:
			return 0, nil
		case time.Now().After(deadline):
			return 0, fmt.Errorf("job in %s started no command within %v", dir, killGrace)
		}
		time.Sleep(fastPoll)
	}
}

func stopGroup(pgid int) error {
	if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil {
		return ignoreGone(err)
	}
	deadline := time.Now().Add(killGrace)
	for time.Now().Before(deadline) {
		if errors.Is(syscall.Kill(-pgid, 0), syscall.ESRCH) {
			return nil
		}
		time.Sleep(fastPoll)
	}
	return ignoreGone(syscall.Kill(-pgid, syscall.SIGKILL))
}

func ignoreGone(err error) error {
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}
