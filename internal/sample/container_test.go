package sample

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var containerImages = []string{"debian:12", "ubuntu:22.04", "ubuntu:24.04"}

// inContainerEnv marks a run of the Linux tests inside a container whose /tmp is a tmpfs
const inContainerEnv = "BUGNET_TEST_IN_CONTAINER"

func needDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("BUGNET_TEST_DOCKER") != "1" {
		t.Skip("container tests run with BUGNET_TEST_DOCKER=1")
	}
}

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

// statsIn waits for the sampler in the container to report at least n samples
func statsIn(t *testing.T, id string, n uint64) Stats {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		var st Stats
		out := inContainer(t, id, "cat /tmp/bugnet/stats.json 2>/dev/null || true")
		if json.Unmarshal([]byte(out), &st) == nil && st.Samples >= n {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("no stats with %d samples, last %q", n, out)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func TestContainerSampleReadsTheSandbox(t *testing.T) {
	needDocker(t)
	bin := linuxBuild(t)
	for _, image := range containerImages {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			id := docker(t, "run", "-d", "--rm", "--init", "--tmpfs", "/tmp", image, "sleep",
				"300")
			t.Cleanup(func() { _ = exec.Command("docker", "kill", id).Run() })
			docker(t, "cp", bin, id+":/usr/local/bin/bugnet-run")
			inContainer(t, id, "mkdir -p /etc/bugnet /tmp/bugnet && "+
				`echo '{"v":1}' > /etc/bugnet/sample.json`)
			eq(t, inContainer(t, id, "bugnet-run respawn"), `{"started":["sample"]}`)
			first := statsIn(t, id, 1)
			eq(t, first.MemPeakMiB > 0, true)

			// The container shares the VM's disk and CPU, so only lower bounds hold here
			inContainer(t, id, "timeout 3 sh -c 'while :; do :; done' || true")
			st := statsIn(t, id, first.Samples+6)
			eq(t, st.CPUSeconds >= 2, true)
			eq(t, st.BusyP95Millicores >= 900, true)
			eq(t, st.GPUMemPeakMiB, uint64(0))
			eq(t, st.UpdatedAt[len(st.UpdatedAt)-1:], "Z")

			pid := inContainer(t, id, "cat /run/bugnet/sample.pid")
			inContainer(t, id, "kill "+pid)
			eq(t, inContainer(t, id, "bugnet-run respawn"), `{"started":["sample"]}`)
		})
	}
}

// TestContainerSampleOnLinux runs this package's Linux tests in a container with /tmp on tmpfs
func TestContainerSampleOnLinux(t *testing.T) {
	needDocker(t)
	arch := docker(t, "version", "--format", "{{.Server.Arch}}")
	bin := filepath.Join(t.TempDir(), "sample.test")
	build := exec.Command("go", "test", "-c", "-o", bin, ".")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the tests for linux/%s: %v\n%s", arch, err, out)
	}
	for _, image := range containerImages {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			id := docker(t, "run", "-d", "--rm", "--init", "--tmpfs", "/tmp", image, "sleep",
				"300")
			t.Cleanup(func() { _ = exec.Command("docker", "kill", id).Run() })
			docker(t, "cp", bin, id+":/sample.test")
			out := docker(t, "exec", "-e", inContainerEnv+"=1", id, "/sample.test",
				"-test.run", "OnLinux$", "-test.v")
			eq(t, strings.Contains(out, "--- PASS: TestDiskUsageOnLinux"), true)
			eq(t, strings.Contains(out, "--- PASS: TestRealProcOnLinux"), true)
		})
	}
}
