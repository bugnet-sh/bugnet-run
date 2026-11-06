// Package sample records the whole sandbox's peaks for the router's estimator
package sample

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oynozan/bugnet-run/internal/sandbox"
)

// StatsFile is where the sampler keeps its readings, for the router to read before a destroy
const StatsFile = "/tmp/bugnet/stats.json"

// Stats is the stats file, every number whole as the router's strict decoder wants
type Stats struct {
	V           int    `json:"v"`
	MemPeakMiB  uint64 `json:"mem_peak_mib"`
	SwapPeakMiB uint64 `json:"swap_peak_mib"`
	// DiskPeakMiB is the peak of used bytes above those at the sampler's start
	DiskPeakMiB uint64 `json:"disk_peak_mib"`
	CPUSeconds  uint64 `json:"cpu_seconds"`
	// BusyP95Millicores is the 95th percentile of each second's busy CPU, 1000 per core
	BusyP95Millicores uint64 `json:"busy_p95_millicores"`
	GPUMemPeakMiB     uint64 `json:"gpu_mem_peak_mib"`
	// OOMKills counts the kernel's OOM kills since the sampler started
	OOMKills  uint64 `json:"oom_kills"`
	Samples   uint64 `json:"samples"`
	UpdatedAt string `json:"updated_at"`
}

const (
	readEvery  = time.Second
	writeEvery = 5 * time.Second
	gpuEvery   = 5 * time.Second
	gpuTimeout = 3 * time.Second
	// clockTicks is USER_HZ, the unit of /proc/stat, 100 on every Linux the runner is built for
	clockTicks = 100
	// busyBucket is the width of the busy histogram's buckets, in millicores
	busyBucket = 10
	maxHomes   = 16
)

// sampler keeps the maxima of the readings it takes
type sampler struct {
	procDir string
	out     string
	paths   func() []string
	// usage gives the device and used bytes of a path's filesystem, false for one in memory
	usage func(path string) (dev, used uint64, ok bool)
	gpu   func(ctx context.Context) (usedMiB uint64, ok bool)

	memPeakKiB, swapPeakKiB uint64
	diskStart               map[uint64]uint64
	diskPeak                uint64
	cpu                     cpuTimes
	cpuSeen                 bool
	busyJiffies             uint64
	busy                    map[uint64]uint64
	busyCount               uint64
	oomStart, oomNow        uint64
	oomSeen                 bool
	gpuPeak                 uint64
	samples                 uint64
	updated                 time.Time
}

func newSampler(procDir, out string) *sampler {
	return &sampler{
		procDir: procDir, out: out, usage: diskUsage, gpu: nvidiaSMI,
		diskStart: map[uint64]uint64{}, busy: map[uint64]uint64{},
	}
}

// Run is bugnet-run sample, which runs until SIGTERM
func Run(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("sample", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "sample.json, /etc/bugnet/sample.json under the root")
	rootDir := flags.String("root", "/", "directory standing for the sandbox's /")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 {
		_, _ = fmt.Fprintln(stderr, "bugnet-run sample: usage: sample [--config FILE] [--root DIR]")
		return 2
	}
	root, err := sandbox.NewRoot(*rootDir)
	if err != nil {
		return fatal(stderr, err)
	}
	if *configPath == "" {
		*configPath = root.Path(sandbox.SampleConfig)
	}
	if err := loadConfig(*configPath); err != nil {
		return fatal(stderr, err)
	}
	pid := os.Getpid()
	if err := sandbox.WritePidFile(root, sandbox.Sample.Name, pid); err != nil {
		return fatal(stderr, err)
	}
	defer sandbox.RemovePidFile(root, sandbox.Sample.Name, pid)
	signal.Ignore(syscall.SIGHUP)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	s := newSampler("/proc", root.Path(StatsFile))
	s.paths = diskPaths(root.Dir())
	s.run(ctx, readEvery, writeEvery, gpuEvery)
	return 0
}

func fatal(stderr io.Writer, err error) int {
	_, _ = fmt.Fprintf(stderr, "bugnet-run sample: %v\n", err)
	return 1
}

// config is sample.json, whose presence is what tells setup and respawn to run the sampler
type config struct {
	V int `json:"v"`
}

func loadConfig(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var c config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("config has data after its object")
	}
	if c.V != 1 {
		return fmt.Errorf("config version %d", c.V)
	}
	return nil
}

// diskPaths lists /, /tmp, /root and each home, again at every reading since homes may appear
func diskPaths(dir string) func() []string {
	return func() []string {
		paths := []string{
			filepath.Join(dir, "/"), filepath.Join(dir, "tmp"), filepath.Join(dir, "root"),
		}
		entries, _ := os.ReadDir(filepath.Join(dir, "home"))
		for _, e := range entries {
			if e.IsDir() && len(paths) < 3+maxHomes {
				paths = append(paths, filepath.Join(dir, "home", e.Name()))
			}
		}
		return paths
	}
}

func (s *sampler) run(ctx context.Context, every, writeAfter, gpuAfter time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	var wrote, gpuRead time.Time
	for {
		now := time.Now()
		if gpuRead.IsZero() || now.Sub(gpuRead) >= gpuAfter {
			s.readGPU(ctx)
			gpuRead = now
		}
		s.read(now)
		if wrote.IsZero() || now.Sub(wrote) >= writeAfter {
			_ = s.write()
			wrote = now
		}
		select {
		case <-ctx.Done():
			_ = s.write()
			return
		case <-tick.C:
		}
	}
}

/* Readings */

// read takes one reading, skipping any source the sandbox lacks
func (s *sampler) read(now time.Time) {
	s.samples++
	s.updated = now
	if m, ok := keyedFile(filepath.Join(s.procDir, "meminfo"), ":"); ok {
		if total, avail := m["MemTotal"], m["MemAvailable"]; total >= avail && total > 0 {
			s.memPeakKiB = max(s.memPeakKiB, total-avail)
		}
		if total, free := m["SwapTotal"], m["SwapFree"]; total >= free {
			s.swapPeakKiB = max(s.swapPeakKiB, total-free)
		}
	}
	if v, ok := keyedFile(filepath.Join(s.procDir, "vmstat"), " "); ok {
		if kills, ok := v["oom_kill"]; ok {
			if !s.oomSeen {
				s.oomStart, s.oomSeen = kills, true
			}
			s.oomNow = kills
		}
	}
	s.readCPU()
	s.readDisks()
}

// cpuTimes holds the jiffies of the aggregate cpu line and the number of CPUs
type cpuTimes struct {
	busy, total uint64
	cpus        uint64
}

func (s *sampler) readCPU() {
	b, err := os.ReadFile(filepath.Join(s.procDir, "stat"))
	if err != nil {
		return
	}
	var now cpuTimes
	found := false
	for line := range strings.Lines(string(b)) {
		f := strings.Fields(line)
		switch {
		case len(f) >= 9 && f[0] == "cpu":
			// user nice system idle iowait irq softirq steal, guest is already within user
			var v [8]uint64
			for i := range v {
				v[i], _ = strconv.ParseUint(f[i+1], 10, 64)
			}
			now.busy = v[0] + v[1] + v[2] + v[5] + v[6]
			now.total = now.busy + v[3] + v[4] + v[7]
			found = true
		case len(f) > 0 && strings.HasPrefix(f[0], "cpu"):
			now.cpus++
		}
	}
	if !found || now.cpus == 0 {
		return
	}
	last, seen := s.cpu, s.cpuSeen
	s.cpu, s.cpuSeen = now, true
	if !seen || now.total <= last.total || now.busy < last.busy {
		return
	}
	busy, total := now.busy-last.busy, now.total-last.total
	s.busyJiffies += busy
	millicores := busy * 1000 * now.cpus / total
	s.busy[(millicores+busyBucket/2)/busyBucket]++
	s.busyCount++
}

func (s *sampler) readDisks() {
	seen := map[uint64]bool{}
	var above int64
	for _, p := range s.paths() {
		dev, used, ok := s.usage(p)
		if !ok || seen[dev] {
			continue
		}
		seen[dev] = true
		start, known := s.diskStart[dev]
		if !known {
			s.diskStart[dev], start = used, used
		}
		above += int64(used) - int64(start)
	}
	if above > 0 {
		s.diskPeak = max(s.diskPeak, uint64(above))
	}
}

func (s *sampler) readGPU(ctx context.Context) {
	if used, ok := s.gpu(ctx); ok {
		s.gpuPeak = max(s.gpuPeak, used)
	}
}

// nvidiaSMI sums memory.used over the GPUs, when nvidia-smi exists
func nvidiaSMI(ctx context.Context) (uint64, bool) {
	path, err := exec.LookPath("nvidia-smi")
	if err != nil {
		return 0, false
	}
	ctx, cancel := context.WithTimeout(ctx, gpuTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--query-gpu=memory.used,memory.total",
		"--format=csv,noheader,nounits")
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		return 0, false
	}
	return parseGPU(string(out)), true
}

func parseGPU(out string) uint64 {
	var sum uint64
	for line := range strings.Lines(out) {
		used, _, _ := strings.Cut(line, ",")
		if n, err := strconv.ParseUint(strings.TrimSpace(used), 10, 64); err == nil {
			sum += n
		}
	}
	return sum
}

// keyedFile reads "key<sep> value [unit]" lines into numbers
func keyedFile(path, sep string) (map[string]uint64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	out := map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, rest, ok := strings.Cut(sc.Text(), sep)
		if !ok {
			continue
		}
		if fields := strings.Fields(rest); len(fields) > 0 {
			if n, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
				out[strings.TrimSpace(k)] = n
			}
		}
	}
	return out, true
}

/* Stats */

func (s *sampler) stats() Stats {
	st := Stats{
		V: 1, MemPeakMiB: ceilDiv(s.memPeakKiB, 1024), SwapPeakMiB: ceilDiv(s.swapPeakKiB, 1024),
		DiskPeakMiB: ceilDiv(s.diskPeak, 1<<20), CPUSeconds: (s.busyJiffies + clockTicks/2) /
			clockTicks, BusyP95Millicores: s.busyP95(), GPUMemPeakMiB: s.gpuPeak,
		Samples: s.samples, UpdatedAt: s.updated.UTC().Format(time.RFC3339),
	}
	if s.oomNow > s.oomStart {
		st.OOMKills = s.oomNow - s.oomStart
	}
	return st
}

// busyP95 is the nearest-rank 95th percentile of the per-second busy histogram
func (s *sampler) busyP95() uint64 {
	if s.busyCount == 0 {
		return 0
	}
	rank := (95*s.busyCount + 99) / 100
	keys := slices.Sorted(maps.Keys(s.busy))
	var seen uint64
	for _, k := range keys {
		seen += s.busy[k]
		if seen >= rank {
			return k * busyBucket
		}
	}
	return keys[len(keys)-1] * busyBucket
}

func ceilDiv(n, d uint64) uint64 {
	return (n + d - 1) / d
}

// write renames a whole file into place, never making the directory, which the exec user owns
func (s *sampler) write() error {
	b, err := json.Marshal(s.stats())
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.out), "."+filepath.Base(s.out)+".bugnet-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.Write(append(b, '\n'))
	if err == nil {
		err = tmp.Chmod(0o644)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(name, s.out)
	}
	if err != nil {
		_ = os.Remove(name)
	}
	return err
}
