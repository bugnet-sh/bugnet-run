package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// jobStatus is one line of ls output, Code is set only once the job has exited
type jobStatus struct {
	Job   string `json:"job"`
	State string `json:"state"`
	Code  *int   `json:"code,omitempty"`
	Out   int64  `json:"o"`
	Err   int64  `json:"e"`
}

func ls(args []string, stdout, stderr io.Writer) int {
	var dir string
	flags := newFlags("ls")
	flags.StringVar(&dir, "dir", defaultDir, "directory holding one directory per job")
	if err := flags.Parse(args); err != nil {
		return badArgs(stdout, stderr, err)
	}
	if flags.NArg() > 0 {
		return badArgs(stdout, stderr, fmt.Errorf("unexpected argument %q", flags.Arg(0)))
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return exitOK
	}
	if err != nil {
		return failed(stderr, err)
	}
	enc := json.NewEncoder(stdout)
	for _, e := range entries {
		if !e.IsDir() || !validID(e.Name()) {
			continue
		}
		status, err := statusOf(filepath.Join(dir, e.Name()))
		if err != nil {
			return failed(stderr, err)
		}
		status.Job = e.Name()
		if err := enc.Encode(status); err != nil {
			return failed(stderr, err)
		}
	}
	return exitOK
}

func statusOf(dir string) (jobStatus, error) {
	status := jobStatus{State: "running"}
	code, exited, err := readExit(dir)
	if err != nil {
		return status, err
	}
	if exited {
		status.State, status.Code = "exited", &code
	}
	if status.Out, err = fileSize(filepath.Join(dir, outFile)); err != nil {
		return status, err
	}
	status.Err, err = fileSize(filepath.Join(dir, errFile))
	return status, err
}
