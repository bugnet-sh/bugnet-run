package runner

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// Values of jobStats.Source
const (
	sourceCgroup = "cgroup"
	sourceRusage = "rusage"
)

// codeSIGKILL is the exit code of a command the kernel ended with SIGKILL, as the OOM killer does
const codeSIGKILL = 128 + int(syscall.SIGKILL)

// jobStats is a job's stats file, written before its exit file
type jobStats struct {
	V int `json:"v"`
	// Source names where PeakMiB came from, cgroup for the job cgroup's memory.peak, else rusage
	Source  string `json:"source"`
	PeakMiB uint32 `json:"peak_mib"`
	OOM     bool   `json:"oom"`
	// OOMKills counts kills in the job's cgroup, or in the whole sandbox for rusage
	OOMKills   uint64 `json:"oom_kills"`
	CPUUsec    uint64 `json:"cpu_usec"`
	ReadBytes  uint64 `json:"io_read_bytes,omitempty"`
	WriteBytes uint64 `json:"io_write_bytes,omitempty"`
}

// meter measures jobs, each in a cgroup v2 directory of its own where it can make one
type meter struct {
	cgroupRoot string
	procDir    string
	cgroup2    func(path string) bool
	// place sets attr to start the command in the cgroup open as fd, reporting whether it can
	place func(attr *syscall.SysProcAttr, fd int) bool
}

var jobMeter = meter{
	cgroupRoot: "/sys/fs/cgroup", procDir: "/proc", cgroup2: isCgroup2, place: intoCgroup,
}

// measured is one job's measurement, from before its start to its exit
type measured struct {
	m meter
	// dir is the job's cgroup, empty once the job runs outside one
	dir      string
	fd       *os.File
	oomStart uint64
	vmstat   bool
}

func (m meter) begin(id string) *measured {
	j := &measured{m: m}
	j.oomStart, j.vmstat = m.vmstatOOM()
	if !m.cgroup2(m.cgroupRoot) {
		return j
	}
	dir, err := m.makeCgroup(id)
	if err != nil {
		return j
	}
	f, err := os.Open(dir)
	if err != nil {
		_ = os.Remove(dir)
		return j
	}
	j.dir, j.fd = dir, f
	return j
}

// makeCgroup makes bugnet/jobs/<id> with each controller the kernel lets the parents hand down
func (m meter) makeCgroup(id string) (string, error) {
	parent := m.cgroupRoot
	for _, sub := range []string{"bugnet", "jobs"} {
		enableControllers(parent)
		parent = filepath.Join(parent, sub)
		if err := os.Mkdir(parent, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	enableControllers(parent)
	dir := filepath.Join(parent, id)
	err := os.Mkdir(dir, 0o755)
	if errors.Is(err, fs.ErrExist) {
		// An earlier job of the same id left it, and it goes only once no process is in it
		if err := os.Remove(dir); err != nil {
			return "", err
		}
		err = os.Mkdir(dir, 0o755)
	}
	return dir, err
}

// enableControllers writes each controller on its own, so one the kernel lacks spares the rest
func enableControllers(dir string) {
	f, err := os.OpenFile(filepath.Join(dir, "cgroup.subtree_control"), os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	// cpu alone on a busy namespace root makes it a thread root, and no job cgroup can start below
	if _, err := f.WriteString("+memory"); err != nil {
		return
	}
	for _, c := range []string{"+cpu", "+io"} {
		_, _ = f.WriteString(c)
	}
}

// start runs cmd in the job's cgroup, and again outside it when the kernel refuses the cgroup
func (j *measured) start(cmd *exec.Cmd) (*exec.Cmd, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if j.fd == nil || !j.m.place(cmd.SysProcAttr, int(j.fd.Fd())) {
		j.drop()
		return cmd, cmd.Start()
	}
	err := cmd.Start()
	_ = j.fd.Close()
	j.fd = nil
	if err == nil {
		return cmd, nil
	}
	j.drop()
	again := &exec.Cmd{
		Path: cmd.Path, Args: cmd.Args, Env: cmd.Env, Dir: cmd.Dir, Stdout: cmd.Stdout,
		Stderr: cmd.Stderr, SysProcAttr: &syscall.SysProcAttr{Setpgid: true},
	}
	return again, again.Start()
}

// drop gives the cgroup up, so the job is measured by rusage and /proc/vmstat
func (j *measured) drop() {
	if j.fd != nil {
		_ = j.fd.Close()
		j.fd = nil
	}
	if j.dir != "" {
		_ = os.Remove(j.dir)
		j.dir = ""
	}
}

// finish reads the job's peaks, from its cgroup where it has one, else from rusage and vmstat
func (j *measured) finish(ps *os.ProcessState, code int) jobStats {
	st := jobStats{V: 1, Source: sourceRusage}
	if ru, ok := ps.SysUsage().(*syscall.Rusage); ok {
		st.PeakMiB = ceilMiB(maxrssBytes(ru.Maxrss))
	}
	st.CPUUsec = uint64(max(ps.UserTime()+ps.SystemTime(), 0).Microseconds())
	counted := false
	if j.dir != "" {
		if peak, ok := readUint(filepath.Join(j.dir, "memory.peak")); ok {
			st.Source, st.PeakMiB = sourceCgroup, ceilMiB(peak)
		}
		if kills, ok := keyed(filepath.Join(j.dir, "memory.events"), "oom_kill"); ok {
			st.OOMKills, st.OOM, counted = kills, kills > 0, true
		}
		if usec, ok := keyed(filepath.Join(j.dir, "cpu.stat"), "usage_usec"); ok {
			st.CPUUsec = usec
		}
		st.ReadBytes, st.WriteBytes = ioBytes(filepath.Join(j.dir, "io.stat"))
		j.drop()
	}
	if counted {
		return st
	}
	// The vmstat count is the whole sandbox's, so a kill counts only when the job failed too
	if end, ok := j.m.vmstatOOM(); ok && j.vmstat {
		if end > j.oomStart {
			st.OOMKills = end - j.oomStart
		}
		st.OOM = st.OOMKills > 0 && code != 0
		return st
	}
	st.OOM = code == codeSIGKILL
	return st
}

func (m meter) vmstatOOM() (uint64, bool) {
	return keyed(filepath.Join(m.procDir, "vmstat"), "oom_kill")
}

// maxrssBytes converts ru_maxrss, which macOS gives in bytes and Linux in KiB
func maxrssBytes(maxrss int64) uint64 {
	if maxrss <= 0 {
		return 0
	}
	if runtime.GOOS == "darwin" {
		return uint64(maxrss)
	}
	return uint64(maxrss) * 1024
}

// ceilMiB rounds up, so a peak is never reported below what the job used
func ceilMiB(b uint64) uint32 {
	mib := b>>20 + min(b&(1<<20-1), 1)
	return uint32(min(mib, math.MaxUint32))
}

func readUint(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v, err == nil
}

// keyed reads the value of key from a file of "key value" lines
func keyed(path, key string) (uint64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), " ")
		if ok && k == key {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			return n, err == nil
		}
	}
	return 0, false
}

// ioBytes sums rbytes and wbytes over the devices of an io.stat file
func ioBytes(path string) (read, written uint64) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0
	}
	for line := range strings.Lines(string(b)) {
		for _, field := range strings.Fields(line) {
			k, v, _ := strings.Cut(field, "=")
			n, err := strconv.ParseUint(v, 10, 64)
			switch {
			case err != nil:
			case k == "rbytes":
				read += n
			case k == "wbytes":
				written += n
			}
		}
	}
	return read, written
}

func writeStats(dir string, st jobStats) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, statsFile), append(b, '\n'))
}

// readStats gives zero values for a job without a readable stats file
func readStats(dir string) jobStats {
	var st jobStats
	b, err := os.ReadFile(filepath.Join(dir, statsFile))
	if err != nil || json.Unmarshal(b, &st) != nil {
		return jobStats{}
	}
	return st
}
