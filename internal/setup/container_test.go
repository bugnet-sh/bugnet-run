package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oynozan/bugnet-run/internal/gate"
)

var containerImages = []string{"debian:12", "ubuntu:22.04", "ubuntu:24.04"}

func needDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("BUGNET_TEST_DOCKER") != "1" {
		t.Skip("container tests run with BUGNET_TEST_DOCKER=1")
	}
}

// docker runs the docker CLI, feeding it stdin, and returns its trimmed stdout
func docker(t *testing.T, stdin []byte, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, errOut.String())
	}
	return strings.TrimSpace(out.String())
}

// linuxBuild builds bugnet-run for the docker daemon's architecture
func linuxBuild(t *testing.T) string {
	t.Helper()
	arch := docker(t, nil, "version", "--format", "{{.Server.Arch}}")
	bin := filepath.Join(t.TempDir(), "bugnet-run")
	build := exec.Command("go", "build", "-trimpath", "-o", bin,
		"github.com/oynozan/bugnet-run/cmd/bugnet-run")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build for linux/%s: %v\n%s", arch, err, out)
	}
	return bin
}

// noIPv6Container starts image with IPv6 off on every interface and the gate port published
func noIPv6Container(t *testing.T, image, bin string) string {
	t.Helper()
	id := docker(t, nil, "run", "-d", "--rm", "--init", "-p", "127.0.0.1::29417",
		"--sysctl", "net.ipv6.conf.all.disable_ipv6=1",
		"--sysctl", "net.ipv6.conf.default.disable_ipv6=1",
		"--sysctl", "net.ipv6.conf.lo.disable_ipv6=1", image, "sleep", "600")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	docker(t, nil, "cp", bin, id+":/usr/local/bin/bugnet-run")
	return id
}

func containerSetup(t *testing.T, id string, spec []byte) string {
	t.Helper()
	docker(t, spec, "exec", "-i", id, "sh", "-c",
		"umask 077 && mkdir -p /tmp/bugnet && cat > /tmp/bugnet/setup-spec.json")
	out := docker(t, nil, "exec", id, "bugnet-run", "setup", "--spec",
		"/tmp/bugnet/setup-spec.json")
	docker(t, nil, "exec", id, "test", "!", "-e", "/tmp/bugnet/setup-spec.json")
	return out
}

func TestContainerGateWithoutIPv6(t *testing.T) {
	needDocker(t)
	bin := linuxBuild(t)
	spec, err := json.Marshal(Spec{
		V: 1, GateKey: testKey, GateListen: ":29417", DenyPorts: []int{29417, 22, 2022},
		PreviewDomain: "preview.example",
	})
	must(t, err)
	for _, image := range containerImages {
		t.Run(image, func(t *testing.T) {
			id := noIPv6Container(t, image, bin)
			eq(t, docker(t, nil, "exec", id, "cat", "/proc/sys/net/ipv6/conf/lo/disable_ipv6"), "1")

			want := `{"gate":"listening","ca":"skipped","init":"setsid"}`
			eq(t, containerSetup(t, id, spec), want)
			addr := strings.Split(docker(t, nil, "port", id, "29417/tcp"), "\n")[0]
			waitHealthy(t, addr)
			pid := docker(t, nil, "exec", id, "cat", "/run/bugnet/gate.pid")

			eq(t, containerSetup(t, id, spec), want)
			eq(t, docker(t, nil, "exec", id, "cat", "/run/bugnet/gate.pid"), pid)
			eq(t, docker(t, nil, "exec", id, "bugnet-run", "respawn"), `{"started":[]}`)

			inContainer(t, id, "kill -9 "+pid)
			eq(t, docker(t, nil, "exec", id, "bugnet-run", "respawn"), `{"started":["gate"]}`)
			waitHealthy(t, addr)
			again := docker(t, nil, "exec", id, "cat", "/run/bugnet/gate.pid")
			if again == pid {
				t.Fatal("respawn left the dead gate's pid in place")
			}

			// A live process that is not the gate holds the pid, as after a pid is reused
			stranger := inContainer(t, id, "sleep 600 </dev/null >/dev/null 2>&1 & echo $!")
			inContainer(t, id, "kill -9 "+again)
			inContainer(t, id, "echo "+stranger+" > /run/bugnet/gate.pid")
			eq(t, docker(t, nil, "exec", id, "bugnet-run", "respawn"), `{"started":["gate"]}`)
			waitHealthy(t, addr)
			inContainer(t, id, "kill -0 "+stranger)
			if docker(t, nil, "exec", id, "cat", "/run/bugnet/gate.pid") == stranger {
				t.Fatal("respawn left the stranger's pid in place")
			}
		})
	}
}

// inContainer runs script with the container's sh, so it needs no kill or ps binary
func inContainer(t *testing.T, id, script string) string {
	t.Helper()
	return docker(t, nil, "exec", id, "sh", "-c", script)
}

func waitHealthy(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := gate.Healthy(ctx, addr, testKey)
		cancel()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("gate at %s never answered: %v", addr, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
