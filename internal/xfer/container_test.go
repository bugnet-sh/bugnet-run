package xfer

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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

// helper runs a bugnet-run subcommand in the container and returns its line, whatever its status
func helper(id string, args ...string) string {
	out, _ := exec.Command("docker", append([]string{"exec", id, "bugnet-run"}, args...)...).
		Output()
	return strings.TrimSpace(string(out))
}

func TestContainerTransferHelpersAsRoot(t *testing.T) {
	needDocker(t)
	arch := docker(t, "version", "--format", "{{.Server.Arch}}")
	bin := filepath.Join(t.TempDir(), "bugnet-run")
	build := exec.Command("go", "build", "-trimpath", "-o", bin,
		"github.com/bugnet-sh/bugnet-run/cmd/bugnet-run")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build for linux/%s: %v\n%s", arch, err, out)
	}
	for _, image := range containerImages {
		t.Run(image, func(t *testing.T) {
			id := docker(t, "run", "-d", "--rm", "--init", "--tmpfs", "/mnt", image, "sleep",
				"600")
			t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
			docker(t, "cp", bin, id+":/usr/local/bin/bugnet-run")
			inContainer(t, id, "useradd -m bx && mkdir -p /opt/app && printf secret > "+
				"/opt/app/key && chmod 600 /opt/app/key && touch -d @1700000000 /opt/app/key")

			staged := "/home/bx/.bugnet/xfer/t1/key"
			var got Info
			must(t, json.Unmarshal([]byte(helper(id, "stage-out", "--from", "/opt/app/key",
				"--to", staged, "--owner", "bx")), &got))
			eq(t, got, Info{
				Path: staged, Size: 6, Mode: 0o600, ModifiedUnixNano: 1700000000 * 1e9,
				Regular: true,
			})
			eq(t, inContainer(t, id, "stat -c '%U %G %a' "+staged), "bx bx 600")
			eq(t, inContainer(t, id, "stat -c '%U %a' /home/bx/.bugnet /home/bx/.bugnet/xfer "+
				"/home/bx/.bugnet/xfer/t1"), "bx 700\nbx 700\nbx 700")
			eq(t, inContainer(t, id, "su -s /bin/sh bx -c 'cat "+staged+" && rm "+staged+"'"),
				"secret")

			inContainer(t, id, "mkfifo /opt/app/pipe")
			eq(t, helper(id, "stage-out", "--from", "/opt/app/pipe", "--to", staged, "--owner",
				"bx"), `{"error":"not_regular"}`)
			eq(t, helper(id, "stage-out", "--from", "/opt/app/key", "--to", staged, "--owner",
				"nobody-here"), `{"error":"bad_args"}`)

			upload := "/home/bx/.bugnet/xfer/t2/conf"
			inContainer(t, id, "su -s /bin/sh bx -c 'mkdir -p /home/bx/.bugnet/xfer/t2 && "+
				"printf new > "+upload+"'")
			must(t, json.Unmarshal([]byte(inContainer(t, id, "umask 077 && bugnet-run place "+
				"--from "+upload+" --to /mnt/etc/app/conf --mode 0640")), &got))
			eq(t, got.Size, int64(3))
			eq(t, got.Mode, uint32(0o640))
			// A new file and its new parents keep the staged file's owner, as sudo mv would
			eq(t, inContainer(t, id, "stat -c '%U %G %a' /mnt/etc/app/conf"), "bx bx 640")
			eq(t, inContainer(t, id, "stat -c '%U %G %a' /mnt/etc /mnt/etc/app"),
				"bx bx 755\nbx bx 755")
			eq(t, inContainer(t, id, "test -e "+upload+" && echo left || echo gone"), "gone")
			eq(t, inContainer(t, id, "ls -A /mnt/etc/app"), "conf")

			inContainer(t, id, "su -s /bin/sh bx -c 'printf again > "+upload+"' && "+
				"chown bx:bx /opt/app/key")
			must(t, json.Unmarshal([]byte(helper(id, "place", "--from", upload, "--to",
				"/opt/app/key")), &got))
			eq(t, inContainer(t, id, "stat -c '%U %G %a' /opt/app/key && cat /opt/app/key"),
				"bx bx 644\nagain")
		})
	}
}
