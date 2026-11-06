package sample

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func needContainer(t *testing.T) {
	t.Helper()
	if os.Getenv(inContainerEnv) != "1" {
		t.Skip("runs inside a container, through TestContainerSampleOnLinux")
	}
}

func TestDiskUsageOnLinux(t *testing.T) {
	needContainer(t)
	_, _, ok := diskUsage("/tmp")
	eq(t, ok, false)
	dev, used, ok := diskUsage("/")
	eq(t, ok, true)
	eq(t, used > 0, true)
	var st syscall.Stat_t
	must(t, syscall.Stat("/", &st))
	eq(t, dev, st.Dev)
	rootDev, _, ok := diskUsage("/root")
	eq(t, ok && rootDev == dev, true)
}

func TestRealProcOnLinux(t *testing.T) {
	needContainer(t)
	s := newSampler("/proc", filepath.Join(t.TempDir(), "stats.json"))
	s.paths = diskPaths("/")
	s.read(time.Now())
	time.Sleep(1100 * time.Millisecond)
	s.read(time.Now())
	st := s.stats()
	eq(t, st.MemPeakMiB > 0, true)
	eq(t, s.cpu.cpus > 0, true)
	eq(t, s.busyCount, uint64(1))
	eq(t, s.oomSeen, true)
	eq(t, len(s.diskStart), 1)
}
