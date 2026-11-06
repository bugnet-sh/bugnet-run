package runner_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestExitFrameCarriesTheJobPeak(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	res := startJob(t, dir, "dd", nil, "--",
		"dd", "if=/dev/zero", "of=/dev/null", "bs=52428800", "count=1").collect(t, 0, 0)
	x := res.mustExit(t)
	eq(t, x.Code, 0)
	if x.PeakMiB < 50 || x.PeakMiB > 1024 {
		t.Fatalf("exit frame peak %d MiB for a 50 MiB buffer", x.PeakMiB)
	}
	eq(t, x.OOM, false)

	b, err := os.ReadFile(filepath.Join(dir, "dd", "stats"))
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		V       int    `json:"v"`
		Source  string `json:"source"`
		PeakMiB uint32 `json:"peak_mib"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	eq(t, st.V, 1)
	eq(t, st.PeakMiB, x.PeakMiB)
	if st.Source != "cgroup" && st.Source != "rusage" {
		t.Fatalf("stats source %q", st.Source)
	}
}

func TestCommandThatNeverRanHasNoStats(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	x := startJob(t, dir, "missing", nil, "--", "bugnet-no-such-command").collect(t, 0, 0).
		mustExit(t)
	eq(t, x.Code, 127)
	eq(t, x.PeakMiB, uint32(0))
	if _, err := os.Stat(filepath.Join(dir, "missing", "stats")); !os.IsNotExist(err) {
		t.Fatalf("a command that never ran has a stats file: %v", err)
	}
}
