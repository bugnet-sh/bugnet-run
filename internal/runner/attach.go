package runner

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/oynozan/bugnet-run/frame"
)

const (
	chunkSize        = 16 << 10
	fastPoll         = 5 * time.Millisecond
	slowPoll         = 50 * time.Millisecond
	defaultHeartbeat = 10 * time.Second
)

func attach(args []string, stdout, stderr io.Writer) int {
	var job jobFlags
	var outOff, errOff int64
	flags := newFlags("attach")
	job.register(flags)
	flags.Int64Var(&outOff, "out", 0, "stdout offset to resume from")
	flags.Int64Var(&errOff, "err", 0, "stderr offset to resume from")
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
	if outOff < 0 || errOff < 0 {
		err := fmt.Errorf("negative offset in --out %d --err %d", outOff, errOff)
		return badArgs(stdout, stderr, err)
	}
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return fail(stdout, stderr, frame.ReasonJobNotFound, exitJobNotFound, nil)
	} else if err != nil {
		return failed(stderr, err)
	}
	for _, o := range []struct {
		name string
		off  int64
	}{{outFile, outOff}, {errFile, errOff}} {
		size, err := fileSize(filepath.Join(dir, o.name))
		if err != nil {
			return failed(stderr, err)
		}
		if o.off > size {
			err := fmt.Errorf("%s offset %d beyond its %d bytes", o.name, o.off, size)
			return badArgs(stdout, stderr, err)
		}
	}
	return followJob(stdout, stderr, dir, outOff, errOff)
}

func followJob(stdout, stderr io.Writer, dir string, outOff, errOff int64) int {
	if err := follow(stdout, dir, outOff, errOff, heartbeatInterval()); err != nil {
		return failed(stderr, err)
	}
	return exitOK
}

func heartbeatInterval() time.Duration {
	ms, err := strconv.Atoi(os.Getenv("BUGNET_RUN_HEARTBEAT_MS"))
	if err != nil || ms <= 0 {
		return defaultHeartbeat
	}
	return time.Duration(ms) * time.Millisecond
}

// output tails one append-only output file of a job
type output struct {
	kind frame.Kind
	path string
	off  int64
	file *os.File
}

// read returns the bytes after off, none while the supervisor has not created the file
func (o *output) read(buf []byte) (int, error) {
	if o.file == nil {
		f, err := os.Open(o.path)
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		if err != nil {
			return 0, err
		}
		o.file = f
	}
	n, err := o.file.ReadAt(buf, o.off)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return n, err
}

// follow streams both outputs until the exit file exists and both are drained
func follow(w io.Writer, dir string, outOff, errOff int64, heartbeat time.Duration) error {
	stdout := &output{kind: frame.KindStdout, path: filepath.Join(dir, outFile), off: outOff}
	stderr := &output{kind: frame.KindStderr, path: filepath.Join(dir, errFile), off: errOff}
	outs := []*output{stdout, stderr}
	defer func() {
		for _, o := range outs {
			if o.file != nil {
				_ = o.file.Close()
			}
		}
	}()

	buf := make([]byte, chunkSize)
	delay := fastPoll
	lastFrame := time.Now()
	for {
		// The exit file is checked before draining so output written before it is never missed
		code, exited, err := readExit(dir)
		if err != nil {
			return err
		}
		flowed, err := drain(w, outs, buf)
		if err != nil {
			return err
		}
		if exited {
			return frame.Encode(w, frame.Frame{
				Kind: frame.KindExit, Code: code, Out: stdout.off, Err: stderr.off,
			})
		}
		if flowed {
			lastFrame, delay = time.Now(), fastPoll
		}
		if time.Since(lastFrame) >= heartbeat {
			beat := frame.Frame{Kind: frame.KindHeartbeat, Out: stdout.off, Err: stderr.off}
			if err := frame.Encode(w, beat); err != nil {
				return err
			}
			lastFrame = time.Now()
		}
		time.Sleep(min(delay, time.Until(lastFrame.Add(heartbeat))))
		if !flowed {
			delay = min(delay*2, slowPoll)
		}
	}
}

// drain emits everything available, one chunk per output in turn so neither starves
func drain(w io.Writer, outs []*output, buf []byte) (bool, error) {
	flowed := false
	for {
		moved := false
		for _, o := range outs {
			n, err := o.read(buf)
			if err != nil {
				return flowed, err
			}
			if n == 0 {
				continue
			}
			chunk := frame.Frame{Kind: o.kind, Offset: o.off, Data: buf[:n]}
			if err := frame.Encode(w, chunk); err != nil {
				return flowed, err
			}
			o.off += int64(n)
			moved = true
		}
		if !moved {
			return flowed, nil
		}
		flowed = true
	}
}
