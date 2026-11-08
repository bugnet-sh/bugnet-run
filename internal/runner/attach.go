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

	"github.com/bugnet-sh/bugnet-run/frame"
)

const (
	chunkSize        = 16 << 10
	fastPoll         = 5 * time.Millisecond
	slowPoll         = 50 * time.Millisecond
	defaultHeartbeat = 10 * time.Second
	// tailPoll paces a tail follower, which sends at most its tail per stream each time
	tailPoll = time.Second
)

func attach(args []string, stdout, stderr io.Writer) int {
	var outOff, errOff, tail offsetFlag
	flags := newFlags("attach")
	flags.Var(&outOff, "out", "stdout offset to resume from")
	flags.Var(&errOff, "err", "stderr offset to resume from")
	flags.Var(&tail, "tail", "follow only the newest bytes of each output, skipping the rest")
	dir, status := lookupJob(flags, args, stdout, stderr)
	if status != exitOK {
		return status
	}
	for _, o := range []struct {
		name string
		off  offsetFlag
	}{{outFile, outOff}, {errFile, errOff}} {
		size, err := fileSize(filepath.Join(dir, o.name))
		if err != nil {
			return failed(stderr, err)
		}
		if int64(o.off) > size {
			err := fmt.Errorf("%s offset %d beyond its %d bytes", o.name, o.off, size)
			return badArgs(stdout, stderr, err)
		}
	}
	return followJob(stdout, stderr, dir, int64(outOff), int64(errOff), int64(tail))
}

// offsetFlag refuses negative offsets while parsing, before the job is looked up
type offsetFlag int64

func (o *offsetFlag) String() string {
	return strconv.FormatInt(int64(*o), 10)
}

func (o *offsetFlag) Set(s string) error {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	if n < 0 {
		return fmt.Errorf("negative offset %d", n)
	}
	*o = offsetFlag(n)
	return nil
}

var errJobLost = errors.New("job supervisor died without recording an exit code")

func followJob(stdout, stderr io.Writer, dir string, outOff, errOff, tail int64) int {
	err := follow(stdout, dir, outOff, errOff, heartbeatInterval(), tail)
	if errors.Is(err, errJobLost) {
		return fail(stdout, stderr, frame.ReasonJobLost, exitJobLost, err)
	}
	if err != nil {
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

type output struct {
	kind frame.Kind
	path string
	off  int64
	end  int64
	file *os.File
}

// read returns the next bytes before end, none while the supervisor has not created the file
func (o *output) read(buf []byte) (int, error) {
	if o.off >= o.end {
		return 0, nil
	}
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
	n, err := o.file.ReadAt(buf[:min(int64(len(buf)), o.end-o.off)], o.off)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return n, err
}

// follow streams both outputs until the job exits or is lost, each only its newest tail when set
func follow(
	w io.Writer, dir string, outOff, errOff int64, heartbeat time.Duration, tail int64,
) error {
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
		state, code, err := jobState(dir)
		if err != nil {
			return err
		}
		// Sized after the state check so a pass covers the command yet ends despite later writers
		for _, o := range outs {
			if o.end, err = fileSize(o.path); err != nil {
				return err
			}
		}
		if tail > 0 && skipAhead(outs, tail) {
			skip := frame.Frame{Kind: frame.KindSkip, Out: stdout.off, Err: stderr.off}
			if err := frame.Encode(w, skip); err != nil {
				return err
			}
		}
		flowed, err := drain(w, outs, buf)
		if err != nil {
			return err
		}
		switch state {
		case stateExited:
			st := readStats(dir)
			return frame.Encode(w, frame.Frame{
				Kind: frame.KindExit, Code: code, Out: stdout.off, Err: stderr.off,
				OOM: st.OOM, PeakMiB: st.PeakMiB,
			})
		case stateLost:
			return errJobLost
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
		pause := delay
		if tail > 0 {
			pause = tailPoll
		}
		time.Sleep(min(pause, time.Until(lastFrame.Add(heartbeat))))
		if !flowed {
			delay = min(delay*2, slowPoll)
		}
	}
}

// skipAhead moves every output more than tail bytes behind its end to tail bytes before it
func skipAhead(outs []*output, tail int64) bool {
	moved := false
	for _, o := range outs {
		if o.end-o.off > tail {
			o.off, moved = o.end-tail, true
		}
	}
	return moved
}

// drain emits everything up to each end, one chunk per output in turn so neither starves
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
