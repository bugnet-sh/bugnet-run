package runner

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oynozan/bugnet-run/frame"
)

const killGrace = 5 * time.Second

func cancel(args []string, stdout, stderr io.Writer) int {
	var job jobFlags
	flags := newFlags("cancel")
	job.register(flags)
	if err := flags.Parse(args); err != nil {
		return badArgs(stdout, stderr, err)
	}
	if flags.NArg() > 0 {
		return badArgs(stdout, stderr, fmt.Errorf("unexpected argument %q", flags.Arg(0)))
	}
	dir, err := job.path()
	if err != nil {
		return badArgs(stdout, stderr, err)
	}
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return fail(stdout, stderr, frame.ReasonJobNotFound, exitJobNotFound, nil)
	} else if err != nil {
		return failed(stderr, err)
	}
	pgid, running, err := waitForPid(dir)
	if err != nil {
		return failed(stderr, err)
	}
	if running {
		if err := stopGroup(pgid); err != nil {
			return failed(stderr, err)
		}
	}
	return exitOK
}

// waitForPid returns the command's process group, waiting while the supervisor starts it
func waitForPid(dir string) (pgid int, running bool, err error) {
	deadline := time.Now().Add(killGrace)
	for {
		if _, exited, err := readExit(dir); err != nil || exited {
			return 0, false, err
		}
		b, err := os.ReadFile(filepath.Join(dir, pidFile))
		if err == nil {
			pgid, err = strconv.Atoi(strings.TrimSpace(string(b)))
			return pgid, err == nil, err
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return 0, false, err
		}
		if time.Now().After(deadline) {
			return 0, false, fmt.Errorf("job in %s started no command within %v", dir, killGrace)
		}
		time.Sleep(fastPoll)
	}
}

// stopGroup sends SIGTERM to the group and SIGKILL if any member outlives the grace period
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
