package runner_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oynozan/bugnet-run/frame"
)

var containerImages = []string{"debian:12", "ubuntu:22.04", "ubuntu:24.04"}

func needDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("BUGNET_TEST_DOCKER") != "1" {
		t.Skip("container tests run with BUGNET_TEST_DOCKER=1")
	}
}

// docker runs the docker CLI and returns its trimmed stdout
func docker(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", args...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s: %v\n%s%s", strings.Join(args, " "), err, out.String(),
			errOut.String())
	}
	return strings.TrimSpace(out.String())
}

func inContainer(t *testing.T, id, script string) string {
	t.Helper()
	return docker(t, "exec", id, "sh", "-c", script)
}

// linuxBuild builds bugnet-run for the docker daemon's architecture
func linuxBuild(t *testing.T) string {
	t.Helper()
	arch := docker(t, "version", "--format", "{{.Server.Arch}}")
	bin := filepath.Join(t.TempDir(), "bugnet-run")
	build := exec.Command("go", "build", "-trimpath", "-o", bin,
		"github.com/oynozan/bugnet-run/cmd/bugnet-run")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build for linux/%s: %v\n%s", arch, err, out)
	}
	return bin
}

func runnerContainer(t *testing.T, image, bin string, flags ...string) string {
	t.Helper()
	args := append(append([]string{"run", "-d", "--rm", "--init"}, flags...), image, "sleep",
		"600")
	id := docker(t, args...)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	docker(t, "cp", bin, id+":/usr/local/bin/bugnet-run")
	return id
}

// exitOf runs a job in the container and returns its exit frame and its stats file
func exitOf(t *testing.T, id, job, script string) (frame.Frame, map[string]any) {
	t.Helper()
	out := inContainer(t, id, "bugnet-run start --job "+job+" -- sh -c '"+script+"'")
	dec := frame.NewDecoder(strings.NewReader(out))
	var exit *frame.Frame
	for {
		f, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("frames %q: %v", out, err)
		}
		if f.Kind == frame.KindExit {
			exit = &f
		}
	}
	if exit == nil {
		t.Fatalf("no exit frame in %q", out)
	}
	stats := map[string]any{}
	if err := json.Unmarshal([]byte(inContainer(t, id, "cat /tmp/bugnet/jobs/"+job+"/stats")),
		&stats); err != nil {
		t.Fatal(err)
	}
	return *exit, stats
}

const hundredMiB = "dd if=/dev/zero of=/dev/null bs=104857600 count=1"

func TestContainerSupervisePeaksInCgroup(t *testing.T) {
	needDocker(t)
	bin := linuxBuild(t)
	for _, image := range containerImages {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			id := runnerContainer(t, image, bin, "--privileged", "--cgroupns=private")
			// The root hands down controllers as a VM's does, so later execs land in init
			inContainer(t, id, "mkdir -p /sys/fs/cgroup/init && "+
				"for p in $(cat /sys/fs/cgroup/cgroup.procs); do "+
				"echo $p > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true; done && "+
				"echo +memory > /sys/fs/cgroup/cgroup.subtree_control")

			x, stats := exitOf(t, id, "big", "cat /proc/self/cgroup > /tmp/cg; exec "+hundredMiB)
			eq(t, inContainer(t, id, "cat /tmp/cg"), "0::/bugnet/jobs/big")
			eq(t, x.Code, 0)
			eq(t, x.OOM, false)
			if x.PeakMiB < 100 || x.PeakMiB > 400 {
				t.Fatalf("peak %d MiB for a 100 MiB buffer", x.PeakMiB)
			}
			eq(t, stats["source"], any("cgroup"))
			eq(t, stats["peak_mib"], any(float64(x.PeakMiB)))
			inContainer(t, id, "test ! -e /sys/fs/cgroup/bugnet/jobs/big")

			x, stats = exitOf(t, id, "oom", "d=/sys/fs/cgroup/bugnet/jobs/oom; "+
				"echo 0 > $d/memory.swap.max 2>/dev/null; echo 33554432 > $d/memory.max; "+
				"exec "+hundredMiB)
			eq(t, x.Code, 137)
			eq(t, x.OOM, true)
			eq(t, stats["source"], any("cgroup"))
			eq(t, stats["oom_kills"], any(float64(1)))
		})
	}
}

func TestContainerSuperviseFallsBackWithoutWritableCgroups(t *testing.T) {
	needDocker(t)
	bin := linuxBuild(t)
	cases := map[string][]string{
		"read-only cgroupfs": nil,
		// Controllers cannot be enabled while the namespace root holds processes
		"no controllers": {"--privileged", "--cgroupns=private"},
	}
	for name, flags := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			id := runnerContainer(t, "debian:12", bin, flags...)
			x, stats := exitOf(t, id, "big", "exec "+hundredMiB)
			eq(t, x.Code, 0)
			if x.PeakMiB < 100 || x.PeakMiB > 400 {
				t.Fatalf("peak %d MiB for a 100 MiB buffer", x.PeakMiB)
			}
			want := "rusage"
			if flags != nil {
				want = "cgroup"
			}
			eq(t, stats["source"], any(want))
		})
	}
}
