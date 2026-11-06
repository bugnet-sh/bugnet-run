package sample

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Dir(path), 0o755))
	must(t, os.WriteFile(path, []byte(content), 0o644))
}

// disk is a fake filesystem's device and used bytes
type disk struct{ dev, used uint64 }

type fixture struct {
	s     *sampler
	proc  string
	disks map[string]disk
	start time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{proc: t.TempDir(), disks: map[string]disk{},
		start: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)}
	f.s = newSampler(f.proc, filepath.Join(t.TempDir(), "stats.json"))
	f.s.paths = func() []string { return []string{"/", "/tmp", "/home/user"} }
	f.s.usage = func(path string) (uint64, uint64, bool) {
		d, ok := f.disks[path]
		return d.dev, d.used, ok
	}
	f.s.gpu = func(context.Context) (uint64, bool) { return 0, false }
	return f
}

func meminfo(usedKiB, swapKiB uint64) string {
	return fmt.Sprintf("MemTotal:        8000000 kB\nMemFree:          100 kB\n"+
		"MemAvailable:    %d kB\nSwapTotal:       1000000 kB\nSwapFree:        %d kB\n",
		8000000-usedKiB, 1000000-swapKiB)
}

// cpuStat has two CPUs, user nice system idle iowait irq softirq steal guest guest_nice
func cpuStat(busy, idle uint64) string {
	return fmt.Sprintf("cpu  %d 0 0 %d 0 0 0 0 0 0\ncpu0 0 0 0 0 0 0 0 0 0 0\n"+
		"cpu1 0 0 0 0 0 0 0 0 0 0\nintr 1 2 3\nctxt 4\n", busy, idle)
}

// reading writes one second of fixture files and takes a sample at it
func (f *fixture) reading(t *testing.T, sec int, files map[string]string) {
	t.Helper()
	for name, content := range files {
		writeFile(t, filepath.Join(f.proc, name), content)
	}
	f.s.read(f.start.Add(time.Duration(sec) * time.Second))
}

func TestSampleKeepsMaxima(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.reading(t, 0, map[string]string{"meminfo": meminfo(700<<10, 10<<10)})
	f.reading(t, 1, map[string]string{"meminfo": meminfo(300<<10, 50<<10)})
	st := f.s.stats()
	eq(t, st.MemPeakMiB, uint64(700))
	eq(t, st.SwapPeakMiB, uint64(50))
	eq(t, st.Samples, uint64(2))
	eq(t, st.UpdatedAt, "2026-11-06T12:00:01Z")
	eq(t, st.V, 1)

	// A partial MiB counts as a whole one
	f.reading(t, 2, map[string]string{"meminfo": meminfo(700<<10+1, 0)})
	eq(t, f.s.stats().MemPeakMiB, uint64(701))
}

func TestSampleCPU(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// Two CPUs give 200 jiffies a second, and each step below is one second of them
	busy := []uint64{0, 100, 300, 300, 350}
	for i, b := range busy {
		f.reading(t, i, map[string]string{"stat": cpuStat(b, uint64(i)*200-b)})
	}
	st := f.s.stats()
	eq(t, st.CPUSeconds, uint64(4)) // 350 busy jiffies at 100 a second, rounded
	// The seconds hold 1000, 2000, 0 and 500 millicores, so the 95th percentile is the busiest
	eq(t, st.BusyP95Millicores, uint64(2000))
}

func TestSampleBusyP95IgnoresARareSpike(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	var busy uint64
	for i := range 41 {
		step := uint64(50) // a quarter of both CPUs
		if i == 20 {
			step = 200
		}
		if i > 0 {
			busy += step
		}
		f.reading(t, i, map[string]string{"stat": cpuStat(busy, uint64(i)*200-busy)})
	}
	eq(t, f.s.stats().BusyP95Millicores, uint64(500))
}

func TestSampleDiskAboveItsStart(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// / and /home/user share a device, so their bytes count once
	f.disks = map[string]disk{"/": {1, 1 << 30}, "/home/user": {1, 1 << 30}, "/tmp": {2, 0}}
	f.reading(t, 0, nil)
	f.disks = map[string]disk{"/": {1, 1<<30 + 300<<20}, "/home/user": {1, 1<<30 + 300<<20},
		"/tmp": {2, 100 << 20}}
	f.reading(t, 1, nil)
	f.disks = map[string]disk{"/": {1, 1 << 30}, "/home/user": {1, 1 << 30}, "/tmp": {2, 0}}
	f.reading(t, 2, nil)
	eq(t, f.s.stats().DiskPeakMiB, uint64(400))

	// Deleting files that were there at the start never goes below zero
	g := newFixture(t)
	g.disks = map[string]disk{"/": {1, 1 << 30}}
	g.reading(t, 0, nil)
	g.disks = map[string]disk{"/": {1, 1 << 20}}
	g.reading(t, 1, nil)
	eq(t, g.s.stats().DiskPeakMiB, uint64(0))
}

func TestSampleOOMKillsSinceTheStart(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.reading(t, 0, map[string]string{"vmstat": "pgfault 1\noom_kill 3\n"})
	eq(t, f.s.stats().OOMKills, uint64(0))
	f.reading(t, 1, map[string]string{"vmstat": "pgfault 1\noom_kill 5\n"})
	eq(t, f.s.stats().OOMKills, uint64(2))
}

func TestSampleGPU(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	used := []uint64{3000, 9000, 1000}
	for _, u := range used {
		f.s.gpu = func(context.Context) (uint64, bool) { return u, true }
		f.s.readGPU(context.Background())
	}
	eq(t, f.s.stats().GPUMemPeakMiB, uint64(9000))
	eq(t, parseGPU("1024, 16384\n8000, 16384\n"), uint64(9024))
	eq(t, parseGPU("[N/A], 16384\n"), uint64(0))
}

func TestSampleWithoutProcStillWrites(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.reading(t, 0, nil)
	must(t, f.s.write())
	var st map[string]any
	b, err := os.ReadFile(f.s.out)
	must(t, err)
	must(t, json.Unmarshal(b, &st))
	eq(t, len(st), 10)
	eq(t, st["samples"], any(float64(1)))
}

func TestSampleWritesAtomically(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.reading(t, 0, map[string]string{"meminfo": meminfo(1<<20, 0)})
	must(t, f.s.write())
	// A link to the old file keeps its bytes, so the new file came in by a rename
	old := filepath.Join(t.TempDir(), "old")
	must(t, os.Link(f.s.out, old))
	before, err := os.ReadFile(old)
	must(t, err)
	f.reading(t, 1, map[string]string{"meminfo": meminfo(2<<20, 0)})
	must(t, f.s.write())
	after, err := os.ReadFile(old)
	must(t, err)
	eq(t, string(after), string(before))
	now, err := os.ReadFile(f.s.out)
	must(t, err)
	eq(t, bytes.Contains(now, []byte(`"mem_peak_mib":2048`)), true)
	eq(t, bytes.HasSuffix(now, []byte("}\n")), true)
	info, err := os.Stat(f.s.out)
	must(t, err)
	eq(t, info.Mode().Perm(), os.FileMode(0o644))
	entries, err := os.ReadDir(filepath.Dir(f.s.out))
	must(t, err)
	eq(t, len(entries), 1)
}

func TestSampleNeverMakesItsDirectory(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.s.out = filepath.Join(t.TempDir(), "bugnet", "stats.json")
	f.reading(t, 0, nil)
	err := f.s.write()
	eq(t, errors.Is(err, os.ErrNotExist), true)
	_, err = os.Stat(filepath.Dir(f.s.out))
	eq(t, errors.Is(err, os.ErrNotExist), true)
}

// waitFor polls cond until it holds, failing the test after five seconds
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSampleRunWritesUntilStopped(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	writeFile(t, filepath.Join(f.proc, "meminfo"), meminfo(5<<20, 0))
	var readings atomic.Uint64
	f.s.paths = func() []string {
		readings.Add(1)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		// Only the first write is periodic, so the last file shows the write at the stop
		f.s.run(ctx, pace{read: 10 * time.Millisecond, write: time.Hour, gpu: time.Hour})
		close(done)
	}()
	waitFor(t, "run wrote no stats", func() bool {
		b, err := os.ReadFile(f.s.out)
		return err == nil && strings.Contains(string(b), `"mem_peak_mib":5120,`)
	})
	waitFor(t, "run took no third reading", func() bool { return readings.Load() >= 3 })
	cancel()
	<-done
	var st Stats
	b, err := os.ReadFile(f.s.out)
	must(t, err)
	must(t, json.Unmarshal(b, &st))
	eq(t, st.Samples >= 3, true)
}

// earlier is a stats file an earlier sampler of the same sandbox wrote
const earlier = `{"v":1,"mem_peak_mib":900,"swap_peak_mib":40,"disk_peak_mib":500,` +
	`"cpu_seconds":30,"busy_p95_millicores":1500,"gpu_mem_peak_mib":7000,"oom_kills":2,` +
	`"samples":60,"updated_at":"2026-11-06T11:59:00Z"}` + "\n"

func TestSampleKeepsTheEarlierSamplersPeaks(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	writeFile(t, f.s.out, earlier)
	f.s.resume()
	f.disks = map[string]disk{"/": {1, 5 << 30}}
	f.reading(t, 0, map[string]string{
		"meminfo": meminfo(300<<10, 0), "vmstat": "oom_kill 7\n", "stat": cpuStat(0, 0),
	})
	f.disks = map[string]disk{"/": {1, 5<<30 + 100<<20}}
	// One second of two CPUs, half of it busy
	f.reading(t, 1, map[string]string{"vmstat": "oom_kill 8\n", "stat": cpuStat(100, 100)})
	must(t, f.s.write())
	b, err := os.ReadFile(f.s.out)
	must(t, err)
	var st Stats
	must(t, json.Unmarshal(b, &st))
	eq(t, st, Stats{
		V: 1, MemPeakMiB: 900, SwapPeakMiB: 40, DiskPeakMiB: 500, CPUSeconds: 31,
		BusyP95Millicores: 1500, GPUMemPeakMiB: 7000, OOMKills: 3, Samples: 62,
		UpdatedAt: "2026-11-06T12:00:01Z",
	})

	// Peaks past the earlier ones still count
	f.reading(t, 2, map[string]string{"meminfo": meminfo(1000<<10, 0)})
	eq(t, f.s.stats().MemPeakMiB, uint64(1000))
}

func TestSampleStartsFreshFromAFileItCannotTrust(t *testing.T) {
	t.Parallel()
	for name, write := range map[string]func(t *testing.T, path string){
		"unknown field": func(t *testing.T, path string) {
			writeFile(t, path, strings.Replace(earlier, `"v":1,`, `"v":1,"x":1,`, 1))
		},
		"version": func(t *testing.T, path string) {
			writeFile(t, path, strings.Replace(earlier, `"v":1,`, `"v":2,`, 1))
		},
		"data after": func(t *testing.T, path string) { writeFile(t, path, earlier+"{}") },
		"too large": func(t *testing.T, path string) {
			writeFile(t, path, earlier+strings.Repeat(" ", 8192))
		},
		"past its bounds": func(t *testing.T, path string) {
			writeFile(t, path, strings.Replace(earlier, `"mem_peak_mib":900`,
				`"mem_peak_mib":18446744073709551615`, 1))
		},
		"symlink": func(t *testing.T, path string) {
			target := filepath.Join(t.TempDir(), "elsewhere.json")
			writeFile(t, target, earlier)
			must(t, os.Symlink(target, path))
		},
		// A FIFO with no writer would block a plain read forever
		"fifo": func(t *testing.T, path string) { must(t, syscall.Mkfifo(path, 0o644)) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			write(t, f.s.out)
			done := make(chan struct{})
			go func() {
				f.s.resume()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("resume blocked")
			}
			eq(t, f.s.stats().Samples, uint64(0))
			eq(t, f.s.stats().MemPeakMiB, uint64(0))
		})
	}
}

// served runs serve under a fresh root at a fast pace, with stats as an earlier sampler's file
func served(t *testing.T, stats string) (string, <-chan int, context.CancelFunc) {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "etc", "bugnet", "sample.json"), `{"v":1}`)
	must(t, os.MkdirAll(filepath.Join(root, "tmp", "bugnet"), 0o755))
	if stats != "" {
		writeFile(t, filepath.Join(root, "tmp", "bugnet", "stats.json"), stats)
	}
	proc := t.TempDir()
	writeFile(t, filepath.Join(proc, "meminfo"), meminfo(300<<10, 0))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan int, 1)
	go func() {
		p := pace{read: 10 * time.Millisecond, write: 30 * time.Millisecond, gpu: time.Hour}
		done <- serve(ctx, []string{"--root", root}, io.Discard, proc, p)
	}()
	return root, done, cancel
}

func TestSampleServeCarriesTheEarlierPeaks(t *testing.T) {
	t.Parallel()
	root, done, stop := served(t, earlier)
	out := filepath.Join(root, "tmp", "bugnet", "stats.json")
	var st Stats
	waitFor(t, "serve wrote nothing past the earlier stats", func() bool {
		b, err := os.ReadFile(out)
		return err == nil && json.Unmarshal(b, &st) == nil && st.Samples > 61
	})
	eq(t, st.MemPeakMiB, uint64(900))
	eq(t, st.CPUSeconds >= 30, true)
	stop()
	eq(t, <-done, 0)
}

// Setup and respawn can both start a sampler before the first writes its pid file
func TestSampleExitsWhileAnotherRuns(t *testing.T) {
	t.Parallel()
	root, first, stop := served(t, "")
	pidFile := filepath.Join(root, "run", "bugnet", "sample.pid")
	waitFor(t, "the first sampler wrote no pid file", func() bool {
		_, err := os.Stat(pidFile)
		return err == nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var errOut bytes.Buffer
	p := pace{read: 10 * time.Millisecond, write: 30 * time.Millisecond, gpu: time.Hour}
	eq(t, serve(ctx, []string{"--root", root}, &errOut, t.TempDir(), p), 0)
	eq(t, ctx.Err(), nil)
	eq(t, errOut.String(), "")
	_, err := os.Stat(pidFile)
	must(t, err)
	select {
	case <-first:
		t.Fatal("the first sampler stopped")
	default:
	}
	stop()
	eq(t, <-first, 0)
}

func TestSampleStopsWithoutItsConfig(t *testing.T) {
	t.Parallel()
	for name, remove := range map[string]func(root string) error{
		"config": func(root string) error {
			return os.Remove(filepath.Join(root, "etc", "bugnet", "sample.json"))
		},
		// A local destroy removes the whole root, again when a write raced the first pass
		"root": func(root string) error {
			err := os.RemoveAll(root)
			for i := 0; err != nil && i < 50; i++ {
				time.Sleep(10 * time.Millisecond)
				err = os.RemoveAll(root)
			}
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root, done, _ := served(t, "")
			pidFile := filepath.Join(root, "run", "bugnet", "sample.pid")
			waitFor(t, "serve wrote no stats", func() bool {
				_, err := os.Stat(filepath.Join(root, "tmp", "bugnet", "stats.json"))
				return err == nil
			})
			must(t, remove(root))
			select {
			case code := <-done:
				eq(t, code, 0)
			case <-time.After(5 * time.Second):
				t.Fatal("the sampler kept running without its config")
			}
			_, err := os.Stat(pidFile)
			eq(t, errors.Is(err, os.ErrNotExist), true)
		})
	}
}

func TestConfigIsStrict(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for raw, ok := range map[string]bool{
		`{"v":1}`: true, `{"v":2}`: false, `{"v":1,"x":1}`: false, `{"v":1} {}`: false, `[]`: false,
	} {
		path := filepath.Join(dir, "sample.json")
		writeFile(t, path, raw)
		eq(t, loadConfig(path) == nil, ok)
	}
	eq(t, loadConfig(filepath.Join(dir, "missing.json")) != nil, true)
}

func TestDiskPathsHoldEveryHome(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, home := range []string{"home/boxd", "home/user"} {
		must(t, os.MkdirAll(filepath.Join(root, home), 0o755))
	}
	writeFile(t, filepath.Join(root, "home", "notes.txt"), "a file, not a home")
	eq(t, diskPaths(root)(), []string{
		root, filepath.Join(root, "tmp"), filepath.Join(root, "root"),
		filepath.Join(root, "home", "boxd"), filepath.Join(root, "home", "user"),
	})
}
