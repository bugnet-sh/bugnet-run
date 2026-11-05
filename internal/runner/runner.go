// Package runner implements the bugnet-run subcommands
package runner

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/oynozan/bugnet-run/frame"
	"github.com/oynozan/bugnet-run/internal/egress"
	"github.com/oynozan/bugnet-run/internal/gate"
	"github.com/oynozan/bugnet-run/internal/setup"
)

const defaultDir = "/tmp/bugnet/jobs"

// Exit statuses of bugnet-run itself
const (
	exitOK          = 0
	exitFailed      = 1
	exitBadArgs     = 2
	exitJobExists   = 3
	exitJobNotFound = 4
	exitSpawnFailed = 5
	exitJobLost     = 5
)

// Files inside a job directory
const (
	outFile  = "out"
	errFile  = "err"
	pidFile  = "pid"
	spidFile = "spid"
	exitFile = "exit"
)

// Job states as ls reports them
const (
	stateRunning = "running"
	stateExited  = "exited"
	stateLost    = "lost"
)

// Run executes the subcommand named by args[0] and returns the process exit status
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return badArgs(stdout, stderr, errors.New("missing subcommand"))
	}
	switch name, rest := args[0], args[1:]; name {
	case "start":
		return start(rest, stdout, stderr)
	case "supervise":
		return supervise(rest)
	case "attach":
		return attach(rest, stdout, stderr)
	case "ls":
		return ls(rest, stdout, stderr)
	case "cancel":
		return cancel(rest, stdout, stderr)
	case "setup":
		return setup.Run(rest, stdout, stderr)
	case "gate":
		return gate.Run(rest, stderr)
	case "respawn":
		return respawn(rest, stdout, stderr)
	case "egress":
		if len(rest) > 0 && rest[0] == "apply" {
			return egress.Apply(rest[1:], stdout, stderr)
		}
		return badArgs(stdout, stderr, errors.New("egress takes the subcommand apply"))
	case "forward":
		return egress.Forward(rest, stderr)
	case "ping":
		if err := frame.Encode(stdout, frame.Frame{Kind: frame.KindPong}); err != nil {
			return failed(stderr, err)
		}
		return exitOK
	default:
		return badArgs(stdout, stderr, fmt.Errorf("unknown subcommand %q", name))
	}
}

/* Failures */

func fail(stdout, stderr io.Writer, reason string, status int, detail error) int {
	_ = frame.Encode(stdout, frame.Frame{Kind: frame.KindError, Reason: reason})
	if detail != nil {
		_, _ = fmt.Fprintf(stderr, "bugnet-run: %v\n", detail)
	}
	return status
}

func badArgs(stdout, stderr io.Writer, detail error) int {
	return fail(stdout, stderr, frame.ReasonBadArgs, exitBadArgs, detail)
}

// failed reports an unexpected error on stderr only, keeping stdout a clean frame stream
func failed(stderr io.Writer, err error) int {
	_, _ = fmt.Fprintf(stderr, "bugnet-run: %v\n", err)
	return exitFailed
}

/* Flags */

func newFlags(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags
}

func parseFlags(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	return nil
}

// lookupJob parses flags naming an existing job and returns its directory or the status it reported
func lookupJob(flags *flag.FlagSet, args []string, stdout, stderr io.Writer) (string, int) {
	var job jobFlags
	job.register(flags)
	if err := parseFlags(flags, args); err != nil {
		return "", badArgs(stdout, stderr, err)
	}
	dir, err := job.path()
	if err != nil {
		return "", badArgs(stdout, stderr, err)
	}
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return "", fail(stdout, stderr, frame.ReasonJobNotFound, exitJobNotFound, nil)
	} else if err != nil {
		return "", failed(stderr, err)
	}
	return dir, exitOK
}

type jobFlags struct {
	id  string
	dir string
}

func (j *jobFlags) register(flags *flag.FlagSet) {
	flags.StringVar(&j.id, "job", "", "job id")
	flags.StringVar(&j.dir, "dir", defaultDir, "directory holding one directory per job")
}

// path returns the job directory, accepting only ids that cannot leave the jobs directory
func (j *jobFlags) path() (string, error) {
	if !validID(j.id) {
		return "", fmt.Errorf("invalid job id %q", j.id)
	}
	return filepath.Join(j.dir, j.id), nil
}

func validID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

type envFlag []string

func (e *envFlag) String() string {
	return strings.Join(*e, " ")
}

func (e *envFlag) Set(kv string) error {
	if k, _, ok := strings.Cut(kv, "="); !ok || k == "" {
		return fmt.Errorf("env %q is not K=V", kv)
	}
	*e = append(*e, kv)
	return nil
}

/* Job files */

// jobState checks the supervisor before the exit file so one exiting cleanly meanwhile is not lost
func jobState(dir string) (string, int, error) {
	lost := supervisorGone(dir) || removed(dir)
	code, exited, err := readExit(dir)
	switch {
	case err != nil:
		return "", 0, err
	case exited:
		return stateExited, code, nil
	case lost:
		return stateLost, 0, nil
	}
	return stateRunning, 0, nil
}

// removed reports a job directory deleted under a follower, as when its sandbox is destroyed
func removed(dir string) bool {
	_, err := os.Stat(dir)
	return errors.Is(err, fs.ErrNotExist)
}

// supervisorGone stays false until spid holds a valid pid, since only a known pid can be checked
func supervisorGone(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, spidFile))
	if err != nil {
		return false
	}
	spid, err := parsePid(b)
	return err == nil && errors.Is(syscall.Kill(spid, 0), syscall.ESRCH)
}

func readExit(dir string) (code int, exited bool, err error) {
	b, err := os.ReadFile(filepath.Join(dir, exitFile))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	code, err = strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, false, fmt.Errorf("exit file of %s: %w", dir, err)
	}
	return code, true, nil
}

var errBadPid = errors.New("invalid pid")

// parsePid accepts only plain decimals above 1 that fit a pid, so kill never sees 0 or -1
func parsePid(b []byte) (int, error) {
	s := strings.TrimSpace(string(b))
	if s == "" || strings.TrimLeft(s, "0123456789") != "" {
		return 0, fmt.Errorf("%w %q", errBadPid, s)
	}
	pid, err := strconv.ParseInt(s, 10, 32)
	if err != nil || pid <= 1 {
		return 0, fmt.Errorf("%w %q", errBadPid, s)
	}
	return int(pid), nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// fileSize returns zero for an output file the supervisor has not created yet
func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func writePid(path string, pid int) error {
	return writeAtomic(path, []byte(strconv.Itoa(pid)+"\n"))
}

// writeAtomic renames a finished temp file into place so readers never see a partial write
func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
