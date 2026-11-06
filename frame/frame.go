// Package frame defines the line-delimited JSON frames bugnet-run writes and the router reads
package frame

import (
	"encoding/json"
	"io"
)

// Kind names what a frame carries
type Kind string

// Frame kinds
const (
	KindStdout    Kind = "o"
	KindStderr    Kind = "e"
	KindHeartbeat Kind = "h"
	KindExit      Kind = "x"
	KindError     Kind = "err"
	KindPong      Kind = "pong"
	// KindSkip says output goes on at offsets Out and Err, the bytes before them left in the files
	KindSkip Kind = "skip"
)

// Reasons carried by error frames
const (
	ReasonJobExists   = "job_exists"
	ReasonJobNotFound = "job_not_found"
	ReasonBadArgs     = "bad_args"
	ReasonSpawnFailed = "spawn_failed"
	ReasonJobLost     = "job_lost"
)

// Frame is one line of a bugnet-run stream
type Frame struct {
	Kind   Kind   `json:"t"`
	Offset int64  `json:"off,omitempty"`
	Data   []byte `json:"d,omitempty"`
	Code   int    `json:"code,omitempty"`
	Out    int64  `json:"o,omitempty"`
	Err    int64  `json:"e,omitempty"`
	Reason string `json:"reason,omitempty"`
	// OOM reports that the kernel killed a process of the job for want of memory
	OOM bool `json:"oom,omitempty"`
	// PeakMiB is the job's peak memory in MiB, rounded up
	PeakMiB uint32 `json:"pk,omitempty"`
}

// Encode writes f to w as one JSON line in a single Write call
func Encode(w io.Writer, f Frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}
