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
	"io/fs"
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
	// maxStatsBytes bounds the earlier stats file a new sampler reads
	maxStatsBytes = 4096
	// maxCarried bounds each number carried from an earlier sampler, far above any real sandbox
	maxCarried = 1 << 40
)

// pace spaces the readings, the writes and the GPU readings
type pace struct{ read, write, gpu time.Duration }

// sampler keeps the maxima of the readings it takes
type sampler struct {
	procDir string
	out     string
	// config is the sampler's config file, whose removal stops the sampler
	config string
	paths  func() []string
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
	// oomBase counts the kills an earlier sampler of this sandbox saw
	oomBase uint64
	gpuPeak uint64
	samples uint64
	updated time.Time
}

func newSampler(procDir, out string) *sampler {
	return &sampler{
		procDir: procDir, out: out, usage: diskUsage, gpu: nvidiaSMI,
		diskStart: map[uint64]uint64{}, busy: map[uint64]uint64{},
	}
}

// Run is bugnet-run sample, which runs until SIGTERM or until its config is gone
func Run(args []string, stderr io.Writer) int {
	signal.Ignore(syscall.SIGHUP)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	p := pace{read: readEvery, write: writeEvery, gpu: gpuEvery}
	return serve(ctx, args, stderr, "/proc", p)
}

func serve(ctx context.Context, args []string, stderr io.Writer, procDir string, p pace) int {
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
	s := newSampler(procDir, root.Path(StatsFile))
	s.paths = diskPaths(root.Dir())
	s.config = *configPath
	s.resume()
	s.run(ctx, p)
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

func (s *sampler) run(ctx context.Context, p pace) {
	tick := time.NewTicker(p.read)
	defer tick.Stop()
	var wrote, gpuRead time.Time
	for {
		now := time.Now()
		if gpuRead.IsZero() || now.Sub(gpuRead) >= p.gpu {
			s.readGPU(ctx)
			gpuRead = now
		}
		s.read(now)
		if wrote.IsZero() || now.Sub(wrote) >= p.write {
			// A sampler without its config never writes into a directory being deleted
			if s.orphaned() {
				return
			}
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

// orphaned reports that the config is gone, as when a local sandbox's directory is deleted
func (s *sampler) orphaned() bool {
	if s.config == "" {
		return false
	}
	_, err := os.Stat(s.config)
	return errors.Is(err, fs.ErrNotExist)
}

// resume carries on from an earlier sampler's stats file, so a respawn keeps every peak
func (s *sampler) resume() {
	prev, ok := readStats(s.out)
	if !ok || max(prev.MemPeakMiB, prev.SwapPeakMiB, prev.DiskPeakMiB, prev.CPUSeconds,
		prev.BusyP95Millicores, prev.GPUMemPeakMiB, prev.OOMKills, prev.Samples) > maxCarried {
		return
	}
	s.memPeakKiB, s.swapPeakKiB = prev.MemPeakMiB*1024, prev.SwapPeakMiB*1024
	// Disk growth after this start counts from the level at this start
	s.diskPeak = prev.DiskPeakMiB << 20
	s.busyJiffies = prev.CPUSeconds * clockTicks
	s.gpuPeak, s.oomBase, s.samples = prev.GPUMemPeakMiB, prev.OOMKills, prev.Samples
	// The earlier seconds count at their 95th percentile, since only that survives
	if prev.Samples > 0 {
		s.busy[(prev.BusyP95Millicores+busyBucket/2)/busyBucket] = prev.Samples
		s.busyCount = prev.Samples
	}
}

// readStats reads a stats file strictly, never following a link or waiting on a FIFO
func readStats(path string) (Stats, bool) {
	var st Stats
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return st, false
	}
	defer func() { _ = f.Close() }()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return st, false
	}
	b, err := io.ReadAll(io.LimitReader(f, maxStatsBytes+1))
	if err != nil || len(b) > maxStatsBytes {
		return st, false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&st) != nil || st.V != 1 {
		return st, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return st, false
	}
	return st, true
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
	st.OOMKills = s.oomBase
	if s.oomNow > s.oomStart {
		st.OOMKills += s.oomNow - s.oomStart
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
