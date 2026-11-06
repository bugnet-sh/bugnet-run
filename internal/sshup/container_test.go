package sshup

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
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
		t.Fatalf("docker %s: %v\n%s%s", strings.Join(args, " "), err, out.String(),
			errOut.String())
	}
	return strings.TrimSpace(out.String())
}

// inContainer runs script with the container's sh, so it needs no kill or ps binary
func inContainer(t *testing.T, id, script string) string {
	t.Helper()
	return docker(t, nil, "exec", id, "sh", "-c", script)
}

func failsInContainer(id, script string) bool {
	return exec.Command("docker", "exec", id, "sh", "-c", script).Run() != nil
}

func waitIn(t *testing.T, id, script string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for failsInContainer(id, script) {
		if time.Now().After(deadline) {
			t.Fatalf("%q never held in the container", script)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

var (
	runnerOnce sync.Once
	runnerBin  string
	runnerErr  string
)

// linuxRunner builds bugnet-run once for the docker daemon's architecture
func linuxRunner(t *testing.T) string {
	t.Helper()
	runnerOnce.Do(func() {
		arch := docker(t, nil, "version", "--format", "{{.Server.Arch}}")
		dir, err := os.MkdirTemp("", "bugnet-run-sshup-linux-")
		if err != nil {
			runnerErr = err.Error()
			return
		}
		cleanups = append(cleanups, func() { _ = os.RemoveAll(dir) })
		runnerBin = filepath.Join(dir, "bugnet-run")
		build := exec.Command("go", "build", "-trimpath", "-o", runnerBin,
			"github.com/oynozan/bugnet-run/cmd/bugnet-run")
		build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			runnerErr = "build for linux/" + arch + ": " + err.Error() + "\n" + string(out)
		}
	})
	if runnerErr != "" {
		t.Fatal(runnerErr)
	}
	return runnerBin
}

var (
	imagesMu sync.Mutex
	images   = map[string]string{}
	// cleanups run once every test has finished, removing what the container tests made
	cleanups []func()
)

// installedImage commits image with openssh-server installed, once per image and test run
func installedImage(t *testing.T, image string) string {
	t.Helper()
	imagesMu.Lock()
	defer imagesMu.Unlock()
	if tag, ok := images[image]; ok {
		return tag
	}
	id := docker(t, nil, "run", "-d", "--init", image, "sleep", "600")
	defer func() { _ = exec.Command("docker", "rm", "-f", id).Run() }()
	inContainer(t, id, "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install "+
		"-y -qq --no-install-recommends openssh-server >/dev/null")
	tag := "bugnet-run-sshup-test:" + strings.ReplaceAll(image, ":", "-") + "-" +
		strconv.Itoa(os.Getpid())
	docker(t, nil, "commit", id, tag)
	images[image] = tag
	cleanups = append(cleanups, func() { _ = exec.Command("docker", "rmi", "-f", tag).Run() })
	return tag
}

// container starts image with bugnet-run in /usr/local/bin, removed when the test ends
func container(t *testing.T, image string) string {
	t.Helper()
	id := docker(t, nil, "run", "-d", "--rm", "--init", image, "sleep", "600")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	docker(t, nil, "cp", linuxRunner(t), id+":/usr/local/bin/bugnet-run")
	return id
}

// containerUp runs ssh-up in the container and returns the line it printed
func containerUp(t *testing.T, id string, s Spec, extra ...string) string {
	t.Helper()
	b, err := json.Marshal(s)
	must(t, err)
	docker(t, b, "exec", "-i", id, "sh", "-c",
		"umask 077 && mkdir -p /tmp/bugnet && cat > /tmp/bugnet/ssh-spec.json")
	args := append([]string{"exec", id, "bugnet-run", "ssh-up", "--spec",
		"/tmp/bugnet/ssh-spec.json"}, extra...)
	cmd := exec.Command("docker", args...)
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	out, _ := cmd.Output()
	if !failsInContainer(id, "test -e /tmp/bugnet/ssh-spec.json") {
		t.Fatal("ssh-up left its spec behind")
	}
	if errOut.Len() > 0 {
		t.Logf("ssh-up stderr: %s", errOut.String())
	}
	return strings.TrimSpace(string(out))
}

func mustUp(t *testing.T, id string, s Spec, extra ...string) Result {
	t.Helper()
	line := containerUp(t, id, s, extra...)
	var res Result
	must(t, json.Unmarshal([]byte(line), &res))
	if res.Error != "" || res.Port == 0 {
		t.Fatalf("ssh-up printed %s", line)
	}
	return res
}

// clientKey makes a client key in the container and returns its authorized_keys line
func clientKey(t *testing.T, id string) string {
	t.Helper()
	inContainer(t, id, "rm -f /root/k /root/k.pub && ssh-keygen -q -t ed25519 -N '' -f /root/k")
	return `restrict,pty,port-forwarding,permitopen="127.0.0.1:*",permitopen="[::1]:*" ` +
		inContainer(t, id, "cat /root/k.pub")
}

// login runs cmd over ssh from inside the container, pinning the host key ssh-up reported
func login(t *testing.T, id, user string, res Result, cmd string) string {
	t.Helper()
	pin(t, id, res)
	return inContainer(t, id, sshCommand(user, res, cmd))
}

// pin makes the host key ssh-up reported the only one the container's ssh client accepts
func pin(t *testing.T, id string, res Result) {
	t.Helper()
	host := "127.0.0.1"
	if res.Port != 22 {
		host = "[127.0.0.1]:" + strconv.Itoa(res.Port)
	}
	docker(t, []byte(host+" "+res.HostKey+"\n"), "exec", "-i", id, "sh", "-c",
		"cat > /root/known_hosts")
}

func sshCommand(user string, res Result, cmd string) string {
	return "ssh -i /root/k -o IdentitiesOnly=yes -o BatchMode=yes " +
		"-o StrictHostKeyChecking=yes -o UserKnownHostsFile=/root/known_hosts -p " +
		strconv.Itoa(res.Port) + " " + user + "@127.0.0.1 " + cmd
}

// sessionEnv returns the environment a new ssh session sees
func sessionEnv(t *testing.T, id string, res Result) map[string]string {
	t.Helper()
	env := map[string]string{}
	for line := range strings.Lines(login(t, id, "root", res, "env")) {
		k, v, ok := strings.Cut(strings.TrimSuffix(line, "\n"), "=")
		if ok {
			env[k] = v
		}
	}
	return env
}

// scanKey returns the ed25519 host key sshd serves on port, empty when nothing answers
func scanKey(id string, port int) string {
	out, _ := exec.Command("docker", "exec", id, "sh", "-c", "ssh-keyscan -t ed25519 -p "+
		strconv.Itoa(port)+" 127.0.0.1 2>/dev/null").Output()
	fields := strings.Fields(string(out))
	if len(fields) < 3 {
		return ""
	}
	return strings.Join(fields[1:3], " ")
}

func containerSpec(user string) Spec {
	return Spec{
		V: 1, User: user, Ports: []int{22, 2022}, SSHDPath: "/usr/sbin/sshd",
		InstallTimeoutS: 120,
	}
}

// holdPort22 runs a gate on port 22 from a scratch root, standing in for a distro sshd
func holdPort22(t *testing.T, id string) {
	t.Helper()
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
	inContainer(t, id, "mkdir -p /tmp/s/etc/bugnet && echo "+key+
		" > /tmp/s/etc/bugnet/gate.key && echo '{\"listen\":\":22\","+
		"\"key_file\":\"/etc/bugnet/gate.key\",\"deny\":[],\"ssh_port_file\":\"\"}'"+
		" > /tmp/s/etc/bugnet/gate.json")
	docker(t, nil, "exec", "-d", id, "bugnet-run", "gate", "--config",
		"/tmp/s/etc/bugnet/gate.json", "--root", "/tmp/s")
	waitIn(t, id, "test -e /tmp/s/run/bugnet/gate.pid")
}

func TestContainerSshUpInstallsOnEmptyLists(t *testing.T) {
	needDocker(t)
	for _, image := range containerImages {
		t.Run(image, func(t *testing.T) {
			id := container(t, image)
			eq(t, inContainer(t, id, "ls /var/lib/apt/lists | grep -c _Packages || true"), "0")
			eq(t, failsInContainer(id, "test -e /usr/sbin/sshd"), true)
			s := containerSpec("root")
			s.Authorize = []string{gwLine}
			s.Install = false
			eq(t, containerUp(t, id, s), `{"error":"sshd_missing"}`)

			s.Install = true
			res := mustUp(t, id, s)
			eq(t, res.Port, 22)
			// openssh-server and openssh-client recommend both, so a full install would add them
			for _, pkg := range []string{"xauth", "ncurses-term"} {
				eq(t, failsInContainer(id, "dpkg -s "+pkg), true)
			}
			eq(t, inContainer(t, id, "cat /etc/bugnet/ssh/port"), "22")
			pid := inContainer(t, id, "cat /run/bugnet/sshd.pid")
			// sshd retitles its listener, keeping the command line inside the title
			eq(t, strings.Contains(inContainer(t, id, "tr '\\0' ' ' </proc/"+pid+"/cmdline"),
				"/usr/sbin/sshd -D -e -f /etc/bugnet/ssh/sshd_config"), true)
			eq(t, failsInContainer(id, "kill -0 $(cat /run/sshd.pid 2>/dev/null)"), true)
			eq(t, inContainer(t, id, "stat -c '%U %a' /etc/bugnet/ssh/host_ed25519_key"),
				"root 600")
			eq(t, inContainer(t, id, "cat /etc/bugnet/ssh/authorized_keys"), gwLine)

			// sshd wrote its pid file after reading its files, so nothing counts as owed
			loaded := inContainer(t, id, "stat -c %y /run/bugnet/sshd.pid")
			s.Authorize = []string{clientKey(t, id)}
			eq(t, mustUp(t, id, s), res)
			eq(t, inContainer(t, id, "cat /run/bugnet/sshd.pid"), pid)
			eq(t, inContainer(t, id, "stat -c %y /run/bugnet/sshd.pid"), loaded)
			eq(t, login(t, id, "root", res, "id -un"), "root")

			inContainer(t, id, "kill -9 "+pid)
			holdPort22(t, id)
			moved := mustUp(t, id, s)
			eq(t, moved.Port, 2022)
			eq(t, moved.HostKey, res.HostKey)
			eq(t, inContainer(t, id, "cat /etc/bugnet/ssh/port"), "2022")
			eq(t, login(t, id, "root", moved, "id -un"), "root")
			eq(t, strings.Count(inContainer(t, id, "cat /etc/bugnet/ssh/authorized_keys"), "\n"),
				1)

			fresh := mustUp(t, id, s, "--new-host-key")
			eq(t, fresh.Port, 2022)
			eq(t, fresh.HostKey != moved.HostKey, true)
			eq(t, inContainer(t, id, "ls -A /etc/bugnet/ssh"),
				"authorized_keys\nhost_ed25519_key\nport\nsshd_config\nsshd_path")
			// ssh-up prints once sshd listens again after its SIGHUP, so a scan right after works
			for range 20 {
				fresh = mustUp(t, id, s, "--new-host-key")
				eq(t, scanKey(id, fresh.Port), fresh.HostKey)
			}
			eq(t, login(t, id, "root", fresh, "id -un"), "root")
		})
	}
}

func TestContainerKeyLoginWithBangPassword(t *testing.T) {
	needDocker(t)
	for _, image := range containerImages {
		t.Run(image, func(t *testing.T) {
			id := container(t, installedImage(t, image))
			inContainer(t, id, "useradd -m bx")
			eq(t, inContainer(t, id, "grep '^bx:' /etc/shadow | cut -d: -f2"), "!")
			s := containerSpec("bx")
			s.Authorize = []string{clientKey(t, id)}
			res := mustUp(t, id, s)
			eq(t, inContainer(t, id, "grep '^bx:' /etc/shadow | cut -d: -f2"), "*")
			eq(t, login(t, id, "bx", res, "id -un"), "bx")
			eq(t, strings.Fields(inContainer(t, id,
				"ssh-keyscan -t ed25519 -p 22 127.0.0.1 2>/dev/null"))[1:],
				strings.Fields(res.HostKey))

			if !failsInContainer(id, "ssh -i /root/k -o BatchMode=yes "+
				"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1 true") {
				t.Fatal("root logged in although AllowUsers names bx alone")
			}
		})
	}
}

func TestContainerSetEnvWithoutPAM(t *testing.T) {
	needDocker(t)
	token := "bnt_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	placeholder := "bnsec_" + strings.Repeat("a", 26)
	apply, err := json.Marshal(map[string]any{
		"v": 1, "token": token, "endpoint": "egress.test.example", "ips": []string{"127.0.0.1"},
		"port": 9443, "listen": "127.77.0.1:443", "hosts": []string{"huggingface.co"},
		"env": []map[string]string{{"name": "HF_TOKEN", "value": placeholder}}, "home": "/root",
	})
	must(t, err)
	for _, image := range containerImages {
		t.Run(image, func(t *testing.T) {
			id := container(t, installedImage(t, image))
			inContainer(t, id, "mkdir -p /etc/bugnet && "+
				"echo SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt > /etc/bugnet/env")
			s := containerSpec("root")
			s.Authorize = []string{clientKey(t, id)}
			res := mustUp(t, id, s)
			eq(t, inContainer(t, id, "grep -c '^UsePAM no$' /etc/bugnet/ssh/sshd_config"), "1")
			env := sessionEnv(t, id, res)
			eq(t, env["SSL_CERT_FILE"], "/etc/ssl/certs/ca-certificates.crt")
			eq(t, env["HF_TOKEN"], "")
			pid := inContainer(t, id, "cat /run/bugnet/sshd.pid")

			docker(t, apply, "exec", "-i", id, "sh", "-c",
				"umask 077 && cat > /tmp/bugnet/egress-spec.json")
			eq(t, inContainer(t, id, "bugnet-run egress apply --spec /tmp/bugnet/egress-spec.json"),
				`{"forward":"listening","hosts":1,"secrets":1}`)
			env = sessionEnv(t, id, res)
			eq(t, env["HF_TOKEN"], placeholder)
			eq(t, env["SSL_CERT_FILE"], "/etc/ssl/certs/ca-certificates.crt")
			eq(t, inContainer(t, id, "cat /run/bugnet/sshd.pid"), pid)
			eq(t, inContainer(t, id, "grep -c '^SetEnv ' /etc/bugnet/ssh/sshd_config"), "1")
		})
	}
}

func TestContainerSshdAfterRunWiped(t *testing.T) {
	needDocker(t)
	for _, image := range containerImages {
		t.Run(image, func(t *testing.T) {
			id := container(t, installedImage(t, image))
			s := containerSpec("root")
			s.Authorize = []string{clientKey(t, id)}
			res := mustUp(t, id, s)
			eq(t, login(t, id, "root", res, "id -un"), "root")

			pid := inContainer(t, id, "cat /run/bugnet/sshd.pid")
			inContainer(t, id, "kill -9 "+pid+" && rm -rf /run/sshd /run/bugnet")
			waitIn(t, id, "! kill -0 "+pid+" 2>/dev/null")
			eq(t, inContainer(t, id, "bugnet-run respawn"), `{"started":["sshd"]}`)
			waitIn(t, id, "test -s /run/bugnet/sshd.pid")
			eq(t, inContainer(t, id, "stat -c '%U %a' /run/sshd"), "root 755")
			eq(t, login(t, id, "root", res, "id -un"), "root")
			eq(t, inContainer(t, id, "bugnet-run respawn"), `{"started":[]}`)
		})
	}
}
