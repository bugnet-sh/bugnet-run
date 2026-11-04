package runner

import (
	"encoding/json"
	"errors"
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
	if err := parseFlags(flags, args); err != nil {
		return badArgs(stdout, stderr, err)
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
	state, code, err := jobState(dir)
	if err != nil {
		return jobStatus{}, err
	}
	status := jobStatus{State: state}
	if state == stateExited {
		status.Code = &code
	}
	if status.Out, err = fileSize(filepath.Join(dir, outFile)); err != nil {
		return status, err
	}
	status.Err, err = fileSize(filepath.Join(dir, errFile))
	return status, err
}
