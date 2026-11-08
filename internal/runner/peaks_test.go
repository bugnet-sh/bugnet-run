package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/bugnet-sh/bugnet-run/frame"
)

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func equal[T comparable](t *testing.T, got, want T) {
	t.Helper()
	if got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// fixtureMeter measures in fixture trees, placing every job in its cgroup without clone3
func fixtureMeter(t *testing.T, cgroup2 bool) meter {
	t.Helper()
	return meter{
		cgroupRoot: t.TempDir(), procDir: t.TempDir(),
		cgroup2: func(string) bool { return cgroup2 },
		place:   func(*syscall.SysProcAttr, int) bool { return true },
	}
}

// ran starts cmd for job and waits for it, returning its state
func ran(t *testing.T, j *measured, cmd *exec.Cmd) *os.ProcessState {
	t.Helper()
	cmd, err := j.start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if cmd.ProcessState == nil {
		t.Fatal("no process state")
	}
	return cmd.ProcessState
}

func TestSupervisePeaksFromCgroup(t *testing.T) {
	t.Parallel()
	m := fixtureMeter(t, true)
	writeTestFile(t, filepath.Join(m.cgroupRoot, "cgroup.subtree_control"), "")
	j := m.begin("job-1")
	dir := filepath.Join(m.cgroupRoot, "bugnet", "jobs", "job-1")
	equal(t, j.dir, dir)
	// One write per controller, which the kernel reads as one request each
	equal(t, readTestFile(t, filepath.Join(m.cgroupRoot, "cgroup.subtree_control")),
		"+memory+cpu+io")

	// The kernel fills these while the job runs
	writeTestFile(t, filepath.Join(dir, "memory.peak"), "734003200\n")
	writeTestFile(t, filepath.Join(dir, "memory.events"),
		"low 0\nhigh 0\nmax 4\noom 1\noom_kill 1\noom_group_kill 0\n")
	writeTestFile(t, filepath.Join(dir, "cpu.stat"),
		"usage_usec 1500\nuser_usec 1000\nsystem_usec 500\n")
	writeTestFile(t, filepath.Join(dir, "io.stat"),
		"8:0 rbytes=4096 wbytes=8192 rios=1 wios=2 dbytes=0 dios=0\n"+
			"259:0 rbytes=1 wbytes=2 rios=1 wios=1 dbytes=0 dios=0\n")
	st := j.finish(ran(t, j, exec.Command("true")), 137)
	equal(t, st, jobStats{
		V: 1, Source: sourceCgroup, PeakMiB: 700, OOM: true, OOMKills: 1, CPUUsec: 1500,
		ReadBytes: 4097, WriteBytes: 8194,
	})
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCgroupOOMCountsEvenWhenTheJobSucceeds(t *testing.T) {
	t.Parallel()
	m := fixtureMeter(t, true)
	j := m.begin("job")
	writeTestFile(t, filepath.Join(j.dir, "memory.events"), "oom_kill 2\n")
	st := j.finish(ran(t, j, exec.Command("true")), 0)
	equal(t, st.OOM, true)
	equal(t, st.OOMKills, uint64(2))
}

func TestCgroupWithoutMemoryFilesFallsBack(t *testing.T) {
	t.Parallel()
	m := fixtureMeter(t, true)
	writeTestFile(t, filepath.Join(m.procDir, "vmstat"), "pgfault 9\noom_kill 3\n")
	j := m.begin("job")
	writeTestFile(t, filepath.Join(m.procDir, "vmstat"), "pgfault 9\noom_kill 4\n")
	st := j.finish(ran(t, j, exec.Command("true")), 137)
	// source names where the peak came from, so a per-process peak never passes for a tree's
	equal(t, st.Source, sourceRusage)
	equal(t, st.OOM, true)
	equal(t, st.OOMKills, uint64(1))
	equal(t, st.PeakMiB > 0, true)
}

// A kernel before 5.19 has memory.events without memory.peak
func TestCgroupEventsWithoutPeak(t *testing.T) {
	t.Parallel()
	m := fixtureMeter(t, true)
	writeTestFile(t, filepath.Join(m.procDir, "vmstat"), "oom_kill 0\n")
	j := m.begin("job")
	writeTestFile(t, filepath.Join(j.dir, "memory.events"), "oom 1\noom_kill 1\n")
	writeTestFile(t, filepath.Join(j.dir, "cpu.stat"), "usage_usec 1500\n")
	st := j.finish(ran(t, j, exec.Command("true")), 0)
	equal(t, st.Source, sourceRusage)
	equal(t, st.PeakMiB > 0, true)
	equal(t, st.OOM, true)
	equal(t, st.OOMKills, uint64(1))
	equal(t, st.CPUUsec, uint64(1500))

	j = m.begin("peak")
	writeTestFile(t, filepath.Join(j.dir, "memory.peak"), "1048576\n")
	st = j.finish(ran(t, j, exec.Command("true")), 0)
	equal(t, st.Source, sourceCgroup)
	equal(t, st.PeakMiB, uint32(1))
}

func TestSuperviseFallbackRusage(t *testing.T) {
	t.Parallel()
	m := fixtureMeter(t, false)
	j := m.begin("job")
	equal(t, j.dir, "")
	// dd touches its whole 50 MiB buffer, so the largest child's peak is at least that
	dd := exec.Command("dd", "if=/dev/zero", "of=/dev/null", "bs=52428800", "count=1")
	st := j.finish(ran(t, j, dd), 0)
	equal(t, st.Source, sourceRusage)
	if st.PeakMiB < 50 || st.PeakMiB > 1024 {
		t.Fatalf("peak %d MiB for a 50 MiB buffer", st.PeakMiB)
	}
	equal(t, st.OOM, false)
	if _, err := os.Stat(filepath.Join(m.cgroupRoot, "bugnet")); !os.IsNotExist(err) {
		t.Fatalf("a mount that is not cgroup2 gained a bugnet cgroup: %v", err)
	}
}

func TestFallbackOOM(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		before, after string
		code          int
		oom           bool
		kills         uint64
	}{
		{"kill during a failed job", "oom_kill 3\n", "oom_kill 4\n", 137, true, 1},
		{"kill of a child, job failed", "oom_kill 0\n", "oom_kill 1\n", 2, true, 1},
		{"kill elsewhere, job succeeded", "oom_kill 0\n", "oom_kill 1\n", 0, false, 1},
		{"no kill, SIGKILL", "oom_kill 5\n", "oom_kill 5\n", 137, false, 0},
		{"no vmstat, SIGKILL is the hint", "", "", 137, true, 0},
		{"no vmstat, other failure", "", "", 1, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := fixtureMeter(t, false)
			vmstat := filepath.Join(m.procDir, "vmstat")
			if tc.before != "" {
				writeTestFile(t, vmstat, tc.before)
			}
			j := m.begin("job")
			if tc.after != "" {
				writeTestFile(t, vmstat, tc.after)
			}
			st := j.finish(ran(t, j, exec.Command("true")), tc.code)
			equal(t, st.OOM, tc.oom)
			equal(t, st.OOMKills, tc.kills)
		})
	}
}

func TestSuperviseRetriesOutsideTheCgroupWhenCloneRefuses(t *testing.T) {
	t.Parallel()
	m := fixtureMeter(t, true)
	// A controlling terminal on a closed descriptor fails the start, as a refused clone3 does
	m.place = func(a *syscall.SysProcAttr, _ int) bool {
		a.Setctty, a.Ctty = true, 1<<20
		return true
	}
	j := m.begin("job")
	dir := j.dir
	first := exec.Command("true")
	cmd, err := j.start(first)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, cmd != first, true)
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	st := j.finish(cmd.ProcessState, 0)
	equal(t, st.Source, sourceRusage)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the refused cgroup %s is still there: %v", dir, err)
	}
}

func TestLeftoverCgroupOfTheSameIDIsReplaced(t *testing.T) {
	t.Parallel()
	m := fixtureMeter(t, true)
	stale := filepath.Join(m.cgroupRoot, "bugnet", "jobs", "job")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	equal(t, m.begin("job").dir, stale)

	// A leftover that still holds a process cannot go, so the job is measured without it
	writeTestFile(t, filepath.Join(stale, "cgroup.procs"), "4242\n")
	equal(t, m.begin("job").dir, "")
}

func TestExitFrameReadsTheJobStats(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	st, err := json.Marshal(jobStats{V: 1, Source: sourceCgroup, PeakMiB: 700, OOM: true})
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		outFile: "", errFile: "", statsFile: string(st), exitFile: "137\n",
	} {
		writeTestFile(t, filepath.Join(dir, name), content)
	}
	var buf bytes.Buffer
	if err := follow(&buf, dir, 0, 0, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	equal(t, buf.String(), `{"t":"x","code":137,"oom":true,"pk":700}`+"\n")

	// A job without a stats file, or with a broken one, still exits with its code
	writeTestFile(t, filepath.Join(dir, statsFile), "{")
	buf.Reset()
	if err := follow(&buf, dir, 0, 0, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	f, err := frame.NewDecoder(&buf).Next()
	if err != nil {
		t.Fatal(err)
	}
	equal(t, f.Code, 137)
	equal(t, f.OOM, false)
	equal(t, f.PeakMiB, uint32(0))
}

func TestCeilMiB(t *testing.T) {
	t.Parallel()
	equal(t, ceilMiB(0), uint32(0))
	equal(t, ceilMiB(1), uint32(1))
	equal(t, ceilMiB(734003200), uint32(700))
	equal(t, ceilMiB(734003201), uint32(701))
	equal(t, ceilMiB(1<<62), uint32(1<<32-1))
}
