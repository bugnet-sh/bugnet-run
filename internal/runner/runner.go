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

	"github.com/oynozan/bugnet-run/frame"
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
)

// Files inside a job directory
const (
	outFile  = "out"
	errFile  = "err"
	pidFile  = "pid"
	exitFile = "exit"
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

// readExit returns the job's exit code once its exit file exists
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

// writeAtomic renames a finished temp file into place so readers never see a partial write
func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
