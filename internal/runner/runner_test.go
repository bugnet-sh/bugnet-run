package runner_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oynozan/bugnet-run/frame"
)

var binPath string

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	dir, err := os.MkdirTemp("", "bugnet-run-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()
	binPath = filepath.Join(dir, "bugnet-run")
	build := exec.Command("go", "build", "-o", binPath,
		"github.com/oynozan/bugnet-run/cmd/bugnet-run")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build bugnet-run: %v\n%s", err, out)
		return 1
	}
	return m.Run()
}

/* Process helpers */

type proc struct {
	cmd    *exec.Cmd
	frames chan frame.Frame
	stop   chan struct{}
	stderr bytes.Buffer
	decErr error
	waited bool
}

type result struct {
	frames []frame.Frame
	stdout []byte
	stderr []byte
	exit   *frame.Frame
	code   int
}

func launch(t *testing.T, env []string, args ...string) *proc {
	t.Helper()
	p := &proc{frames: make(chan frame.Frame, 64), stop: make(chan struct{})}
	p.cmd = exec.Command(binPath, args...)
	p.cmd.Env = append(os.Environ(), env...)
	p.cmd.Stderr = &p.stderr
	stdout, err := p.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go p.decode(stdout)
	t.Cleanup(func() {
		close(p.stop)
		if !p.waited {
			_ = p.cmd.Process.Kill()
			_ = p.cmd.Wait()
		}
	})
	return p
}

func (p *proc) decode(r io.Reader) {
	defer close(p.frames)
	dec := frame.NewDecoder(r)
	for {
		f, err := dec.Next()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				p.decErr = err
			}
			return
		}
		select {
		case p.frames <- f:
		case <-p.stop:
			return
		}
	}
}

func (p *proc) next(t *testing.T, timeout time.Duration) frame.Frame {
	t.Helper()
	select {
	case f, ok := <-p.frames:
		if !ok {
			t.Fatalf("frame stream ended early, decode error %v", p.decErr)
		}
		return f
	case <-time.After(timeout):
		t.Fatalf("no frame within %v", timeout)
	}
	return frame.Frame{}
}

// nextLine reads stdout frames until a newline and returns the text before it
func (p *proc) nextLine(t *testing.T) string {
	t.Helper()
	var line []byte
	for !bytes.HasSuffix(line, []byte("\n")) {
		f := p.next(t, 5*time.Second)
		if f.Kind != frame.KindStdout {
			continue
		}
		line = append(line, f.Data...)
	}
	return strings.TrimSuffix(string(line), "\n")
}

// collect reads frames to the end, checking that data offsets continue from outOff and errOff
func (p *proc) collect(t *testing.T, outOff, errOff int64) result {
	t.Helper()
	var r result
	deadline := time.After(20 * time.Second)
	for open := true; open; {
		select {
		case f, ok := <-p.frames:
			if !ok {
				open = false
				break
			}
			if r.exit != nil {
				t.Errorf("frame %+v after the exit frame", f)
			}
			r.frames = append(r.frames, f)
			switch f.Kind {
			case frame.KindStdout:
				if f.Offset != outOff {
					t.Errorf("stdout frame at offset %d, want %d", f.Offset, outOff)
				}
				outOff += int64(len(f.Data))
				r.stdout = append(r.stdout, f.Data...)
			case frame.KindStderr:
				if f.Offset != errOff {
					t.Errorf("stderr frame at offset %d, want %d", f.Offset, errOff)
				}
				errOff += int64(len(f.Data))
				r.stderr = append(r.stderr, f.Data...)
			case frame.KindExit:
				if f.Out != outOff || f.Err != errOff {
					t.Errorf("exit frame counts o=%d e=%d, want o=%d e=%d",
						f.Out, f.Err, outOff, errOff)
				}
				r.exit = &f
			}
		case <-deadline:
			t.Fatal("frame stream did not end within 20s")
		}
	}
	if p.decErr != nil {
		t.Fatalf("decode: %v", p.decErr)
	}
	p.waited = true
	if err := p.cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatal(err)
		}
	}
	r.code = p.cmd.ProcessState.ExitCode()
	return r
}

func (r result) mustExit(t *testing.T) frame.Frame {
	t.Helper()
	if r.exit == nil {
		t.Fatalf("no exit frame in %+v", r.frames)
	}
	return *r.exit
}

func (r result) mustFail(t *testing.T, reason string, code int) {
	t.Helper()
	want := []frame.Frame{{Kind: frame.KindError, Reason: reason}}
	if !reflect.DeepEqual(r.frames, want) {
		t.Errorf("frames %+v, want %+v", r.frames, want)
	}
	if r.code != code {
		t.Errorf("exit status %d, want %d", r.code, code)
	}
}

// startJob runs start for id in dir and cancels the job when the test ends
func startJob(t *testing.T, dir, id string, env []string, args ...string) *proc {
	t.Helper()
	p := launch(t, env, append([]string{"start", "--job", id, "--dir", dir}, args...)...)
	t.Cleanup(func() {
		_ = exec.Command(binPath, "cancel", "--job", id, "--dir", dir).Run()
		waitFor(t, 10*time.Second, func() bool { return exists(filepath.Join(dir, id, "exit")) })
	})
	return p
}

// cancelJob runs cancel, expects it to succeed silently and returns how long it took
func cancelJob(t *testing.T, dir, id string) time.Duration {
	t.Helper()
	began := time.Now()
	res := launch(t, nil, "cancel", "--job", id, "--dir", dir).collect(t, 0, 0)
	if res.code != 0 || len(res.frames) != 0 {
		t.Errorf("cancel exited %d with frames %+v, want 0 and none", res.code, res.frames)
	}
	return time.Since(began)
}

func runRaw(t *testing.T, args ...string) []byte {
	t.Helper()
	out, err := exec.Command(binPath, args...).Output()
	if err != nil {
		t.Fatalf("bugnet-run %v: %v", args, err)
	}
	return out
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %v", timeout)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readPid(t *testing.T, dir, id string) int {
	t.Helper()
	path := filepath.Join(dir, id, "pid")
	waitFor(t, 5*time.Second, func() bool { return exists(path) })
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

func gone(pid int) bool {
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}

// openGate unblocks one read of the fifo at path and returns when it did
func openGate(t *testing.T, path string) time.Time {
	t.Helper()
	var f *os.File
	waitFor(t, 5*time.Second, func() bool {
		var err error
		f, err = os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		return err == nil
	})
	defer func() { _ = f.Close() }()
	opened := time.Now()
	if _, err := f.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	return opened
}

func allBytes() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

/* Start */

func TestStartEchoAndExitCode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	res := startJob(t, dir, "echo", nil, "--", "sh", "-c", "echo a; echo b >&2; exit 3").
		collect(t, 0, 0)
	x := res.mustExit(t)
	if string(res.stdout) != "a\n" || string(res.stderr) != "b\n" {
		t.Errorf("stdout %q stderr %q, want %q and %q", res.stdout, res.stderr, "a\n", "b\n")
	}
	if x.Code != 3 || x.Out != 2 || x.Err != 2 {
		t.Errorf("exit frame %+v, want code 3 o=2 e=2", x)
	}
	if res.code != 0 {
		t.Errorf("start exited %d, want 0", res.code)
	}
}

func TestStartRefusesExistingJob(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	startJob(t, dir, "dup", nil, "--", "true").collect(t, 0, 0).mustExit(t)
	launch(t, nil, "start", "--job", "dup", "--dir", dir, "--", "true").collect(t, 0, 0).
		mustFail(t, frame.ReasonJobExists, 3)
}

func TestStartAppliesCwdAndEnv(t *testing.T) {
	t.Parallel()
	dir, work := t.TempDir(), t.TempDir()
	script := `pwd; echo "$BUGNET_TEST $PYTHONUNBUFFERED"`
	res := startJob(t, dir, "env", nil, "--cwd", work, "--env", "BUGNET_TEST=a=b", "--",
		"sh", "-c", script).collect(t, 0, 0)
	res.mustExit(t)
	if want := work + "\na=b 1\n"; string(res.stdout) != want {
		t.Errorf("stdout %q, want %q", res.stdout, want)
	}
}

func TestStartCommandNotFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	res := startJob(t, dir, "missing", nil, "--", "bugnet-no-such-command").collect(t, 0, 0)
	if x := res.mustExit(t); x.Code != 127 {
		t.Errorf("exit code %d, want 127", x.Code)
	}
	if !bytes.Contains(res.stderr, []byte("bugnet-no-such-command")) {
		t.Errorf("stderr %q does not name the command", res.stderr)
	}
}

func TestStartStreamsCarriageReturnAndBinary(t *testing.T) {
	tmp := t.TempDir()
	dir, gate, bin := filepath.Join(tmp, "jobs"), filepath.Join(tmp, "gate"),
		filepath.Join(tmp, "bin")
	if err := syscall.Mkfifo(gate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, allBytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `read x < "$1"; printf '10%%\r'; read x < "$1"; printf '50%%\r100%%\r'; cat "$2"`
	p := startJob(t, dir, "progress", nil, "--", "sh", "-c", script, "sh", gate, bin)

	// Lets the follower back off to its idle poll before the command writes
	time.Sleep(500 * time.Millisecond)
	written := openGate(t, gate)
	first := p.next(t, 5*time.Second)
	if latency := time.Since(written); latency > 200*time.Millisecond {
		t.Errorf("first chunk arrived %v after it was written, want under 200ms", latency)
	}
	if first.Kind != frame.KindStdout || string(first.Data) != "10%\r" {
		t.Fatalf("first frame %+v, want stdout %q", first, "10%\r")
	}

	openGate(t, gate)
	res := p.collect(t, int64(len(first.Data)), 0)
	res.mustExit(t)
	want := append([]byte("50%\r100%\r"), allBytes()...)
	if !bytes.Equal(res.stdout, want) {
		t.Errorf("stdout %q, want %q", res.stdout, want)
	}
}

func TestStartLargeOutput(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	data := make([]byte, 8<<20)
	_, _ = rand.NewChaCha8([32]byte{1}).Read(data)
	src := filepath.Join(tmp, "src")
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}
	res := startJob(t, filepath.Join(tmp, "jobs"), "large", nil, "--", "cat", src).
		collect(t, 0, 0)
	if x := res.mustExit(t); x.Code != 0 || x.Out != int64(len(data)) {
		t.Errorf("exit frame %+v, want code 0 o=%d", x, len(data))
	}
	if sha256.Sum256(res.stdout) != sha256.Sum256(data) {
		t.Errorf("stdout checksum mismatch over %d bytes", len(res.stdout))
	}
	for _, f := range res.frames {
		if len(f.Data) > 16<<10 {
			t.Fatalf("frame at offset %d carries %d bytes", f.Offset, len(f.Data))
		}
	}
}

func TestHeartbeatWhenSilent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	res := startJob(t, dir, "quiet", []string{"BUGNET_RUN_HEARTBEAT_MS=50"}, "--", "sleep", "0.2").
		collect(t, 0, 0)
	res.mustExit(t)
	beats := 0
	for _, f := range res.frames {
		if f.Kind == frame.KindHeartbeat {
			beats++
		}
	}
	if beats < 2 {
		t.Errorf("%d heartbeats, want at least 2", beats)
	}
}

func TestStartLeaksNoDescriptors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	extraR, extraW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = extraR.Close(); _ = outR.Close() }()

	cmd := exec.Command(binPath, "start", "--job", "fds", "--dir", dir, "--", "sleep", "100")
	cmd.Stdout = outW
	cmd.ExtraFiles = []*os.File{extraW}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = extraW.Close()
	_ = outW.Close()
	t.Cleanup(func() {
		_ = exec.Command(binPath, "cancel", "--job", "fds", "--dir", dir).Run()
		waitFor(t, 10*time.Second, func() bool { return exists(filepath.Join(dir, "fds", "exit")) })
	})
	readPid(t, dir, "fds")
	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	for name, r := range map[string]*os.File{"stdout": outR, "fd 3": extraR} {
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(io.Discard, r)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Errorf("%s of start is still held open by the job", name)
		}
	}
}

/* Attach */

func TestAttachFromOffsets(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	startJob(t, dir, "digits", nil, "--", "printf", "0123456789").collect(t, 0, 0).mustExit(t)
	res := launch(t, nil, "attach", "--job", "digits", "--out", "4", "--err", "0", "--dir", dir).
		collect(t, 4, 0)
	res.mustExit(t)
	if string(res.stdout) != "456789" {
		t.Errorf("stdout %q, want %q", res.stdout, "456789")
	}
	if res.code != 0 {
		t.Errorf("attach exited %d, want 0", res.code)
	}
	launch(t, nil, "attach", "--job", "digits", "--out", "11", "--err", "0", "--dir", dir).
		collect(t, 0, 0).mustFail(t, frame.ReasonBadArgs, 2)
}

func TestCommandSurvivesFollowerKill(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	script := "printf a; sleep 0.5; printf b >&2; printf c; exit 7"
	p := startJob(t, dir, "survive", nil, "--", "sh", "-c", script)
	if f := p.next(t, 5*time.Second); f.Kind != frame.KindStdout || string(f.Data) != "a" {
		t.Fatalf("first frame %+v, want stdout %q", f, "a")
	}
	p.waited = true
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
	if exists(filepath.Join(dir, "survive", "exit")) {
		t.Fatal("job finished before the follower was killed")
	}

	res := launch(t, nil, "attach", "--job", "survive", "--out", "0", "--err", "0", "--dir", dir).
		collect(t, 0, 0)
	if x := res.mustExit(t); x.Code != 7 {
		t.Errorf("exit code %d, want 7", x.Code)
	}
	if string(res.stdout) != "ac" || string(res.stderr) != "b" {
		t.Errorf("stdout %q stderr %q, want %q and %q", res.stdout, res.stderr, "ac", "b")
	}
}

func TestUnknownJob(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	launch(t, nil, "attach", "--job", "nope", "--out", "0", "--err", "0", "--dir", dir).
		collect(t, 0, 0).mustFail(t, frame.ReasonJobNotFound, 4)
	launch(t, nil, "cancel", "--job", "nope", "--dir", dir).
		collect(t, 0, 0).mustFail(t, frame.ReasonJobNotFound, 4)
}

/* Cancel */

func TestCancelKillsProcessGroup(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := startJob(t, dir, "group", nil, "--", "sh", "-c", "sleep 100 & echo $!; sleep 100")
	line := p.nextLine(t)
	child, err := strconv.Atoi(line)
	if err != nil {
		t.Fatalf("child pid %q: %v", line, err)
	}
	pgid := readPid(t, dir, "group")

	if elapsed := cancelJob(t, dir, "group"); elapsed >= 5*time.Second {
		t.Errorf("cancel took %v, SIGTERM alone should end the job", elapsed)
	}
	res := p.collect(t, int64(len(line)+1), 0)
	if x := res.mustExit(t); x.Code != 128+int(syscall.SIGTERM) {
		t.Errorf("exit code %d, want %d", x.Code, 128+int(syscall.SIGTERM))
	}
	waitFor(t, 2*time.Second, func() bool { return gone(child) && gone(-pgid) })
}

func TestCancelEscalatesToKill(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := startJob(t, dir, "stubborn", nil, "--", "sh", "-c", `trap "" TERM; echo ready; sleep 100`)
	line := p.nextLine(t)
	pgid := readPid(t, dir, "stubborn")

	if elapsed := cancelJob(t, dir, "stubborn"); elapsed < 5*time.Second {
		t.Errorf("cancel returned after %v, want the 5s grace before SIGKILL", elapsed)
	}
	res := p.collect(t, int64(len(line)+1), 0)
	if x := res.mustExit(t); x.Code != 128+int(syscall.SIGKILL) {
		t.Errorf("exit code %d, want %d", x.Code, 128+int(syscall.SIGKILL))
	}
	waitFor(t, 2*time.Second, func() bool { return gone(-pgid) })
}

/* Ls, ping and arguments */

func TestLsReportsJobs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	startJob(t, dir, "a-done", nil, "--", "sh", "-c", "echo a; echo b >&2; exit 3").
		collect(t, 0, 0).mustExit(t)
	startJob(t, dir, "b-live", nil, "--", "sleep", "100")

	type status struct {
		Job   string `json:"job"`
		State string `json:"state"`
		Code  *int   `json:"code"`
		Out   int64  `json:"o"`
		Err   int64  `json:"e"`
	}
	var got []status
	for line := range strings.Lines(string(runRaw(t, "ls", "--dir", dir))) {
		var s status
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			t.Fatalf("ls line %q: %v", line, err)
		}
		got = append(got, s)
	}
	three := 3
	want := []status{
		{Job: "a-done", State: "exited", Code: &three, Out: 2, Err: 2},
		{Job: "b-live", State: "running"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ls %+v, want %+v", got, want)
	}
}

func TestPing(t *testing.T) {
	t.Parallel()
	res := launch(t, nil, "ping").collect(t, 0, 0)
	if want := []frame.Frame{{Kind: frame.KindPong}}; !reflect.DeepEqual(res.frames, want) {
		t.Errorf("frames %+v, want %+v", res.frames, want)
	}
	if res.code != 0 {
		t.Errorf("ping exited %d, want 0", res.code)
	}
}

func TestBadArgs(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "jobs")
	cases := [][]string{
		{},
		{"bogus"},
		{"start", "--job", "../escape", "--dir", dir, "--", "true"},
		{"start", "--job", "", "--dir", dir, "--", "true"},
		{"start", "--job", "ok", "--dir", dir},
		{"start", "--job", "ok", "--dir", dir, "--env", "NOEQUALS", "--", "true"},
		{"attach", "--job", "ok", "--out", "-1", "--err", "0", "--dir", dir},
		{"cancel", "--dir", dir},
	}
	for _, args := range cases {
		launch(t, nil, args...).collect(t, 0, 0).mustFail(t, frame.ReasonBadArgs, 2)
	}
	if exists(filepath.Join(tmp, "escape")) || exists(filepath.Join(dir, "ok")) {
		t.Error("a rejected start created a job directory")
	}
}
