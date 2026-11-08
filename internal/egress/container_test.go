package egress

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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

// failsInContainer reports whether script exits non-zero in the container
func failsInContainer(id, script string) bool {
	return exec.Command("docker", "exec", id, "sh", "-c", script).Run() != nil
}

// linuxBuild builds pkg for the docker daemon's architecture
func linuxBuild(t *testing.T, pkg string) string {
	t.Helper()
	arch := docker(t, nil, "version", "--format", "{{.Server.Arch}}")
	bin := filepath.Join(t.TempDir(), filepath.Base(pkg))
	build := exec.Command("go", "build", "-trimpath", "-o", bin, pkg)
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s for linux/%s: %v\n%s", pkg, arch, err, out)
	}
	return bin
}

func keyPEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
	must(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func containerApply(t *testing.T, id string, spec []byte) string {
	t.Helper()
	docker(t, spec, "exec", "-i", id, "sh", "-c",
		"umask 077 && mkdir -p /tmp/bugnet && cat > /tmp/bugnet/egress-spec.json")
	cmd := exec.Command("docker", "exec", id, "bugnet-run", "egress", "apply", "--spec",
		"/tmp/bugnet/egress-spec.json")
	out, _ := cmd.Output()
	if inContainer(t, id, "test -e /tmp/bugnet/egress-spec.json && echo left || true") != "" {
		t.Fatal("egress apply left its spec behind")
	}
	return strings.TrimSpace(string(out))
}

// throughHosts sends msg to huggingface.co:443 as the sandbox resolves it, and returns the echo
func throughHosts(t *testing.T, id, msg string) string {
	t.Helper()
	return inContainer(t, id, "exec bash -c 'exec 3<>/dev/tcp/huggingface.co/443 && "+
		"printf "+msg+" >&3 && head -c "+strconv.Itoa(len(msg))+" <&3'")
}

func TestContainerApplyOnBindMountedHosts(t *testing.T) {
	needDocker(t)
	runner := linuxBuild(t, "github.com/bugnet-sh/bugnet-run/cmd/bugnet-run")
	echo := linuxBuild(t, "./testdata/tunnelecho")
	p := newPKI(t)
	leaf := p.leaf(t, testEndpoint)
	dir := t.TempDir()
	writeFile(t, dir+"/leaf.pem", string(certPEM(leaf.Certificate[0])))
	writeFile(t, dir+"/leaf.key", string(keyPEM(t, leaf.PrivateKey)))
	s := spec("huggingface.co")
	s.Endpoint, s.IPs, s.Port, s.Home = testEndpoint, []string{"127.0.0.1"}, 9443, "/root"
	first, err := json.Marshal(s)
	must(t, err)
	s.Token = ""
	again, err := json.Marshal(s)
	must(t, err)
	gateKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))

	for _, image := range containerImages {
		t.Run(image, func(t *testing.T) {
			id := docker(t, nil, "run", "-d", "--rm", "--init", image, "sleep", "600")
			t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
			docker(t, nil, "cp", runner, id+":/usr/local/bin/bugnet-run")
			docker(t, nil, "cp", echo, id+":/usr/local/bin/tunnelecho")
			docker(t, nil, "cp", dir+"/leaf.pem", id+":/tmp/leaf.pem")
			docker(t, nil, "cp", dir+"/leaf.key", id+":/tmp/leaf.key")
			docker(t, p.pem, "exec", "-i", id, "sh", "-c",
				"mkdir -p /etc/ssl/certs && cat > /etc/ssl/certs/ca-certificates.crt")
			docker(t, nil, "exec", "-d", id, "tunnelecho", "/tmp/leaf.pem", "/tmp/leaf.key",
				"127.0.0.1:9443")
			eq(t, inContainer(t, id, "grep -c ' /etc/hosts ' /proc/self/mountinfo"), "1")
			inContainer(t, id, "echo '10.0.0.9 hand.example' >> /etc/hosts")
			inode := inContainer(t, id, "stat -c %i /etc/hosts")
			outside := "sed '/# bugnet begin/,/# bugnet end/d' /etc/hosts"
			before := inContainer(t, id, "cat /etc/hosts")

			want := `{"forward":"listening","hosts":1,"secrets":1}`
			eq(t, containerApply(t, id, first), want)
			eq(t, inContainer(t, id, "stat -c %i /etc/hosts"), inode)
			eq(t, inContainer(t, id, outside), before)
			eq(t, strings.Fields(inContainer(t, id, "getent hosts huggingface.co")),
				[]string{"127.77.0.1", "huggingface.co"})
			eq(t, inContainer(t, id, "sed -n '/# bugnet begin/,/# bugnet end/p' /etc/hosts"),
				"# bugnet begin\n127.77.0.1 huggingface.co\n# bugnet end")
			waitEcho(t, id)
			eq(t, failsInContainer(id, "exec bash -c ': </dev/tcp/127.0.0.1/443'"), true)
			pid := inContainer(t, id, "cat /run/bugnet/forward.pid")
			// The forwarder runs the copy apply made, never the binary the router uploaded
			eq(t, inContainer(t, id, "tr '\\0' ' ' </proc/"+pid+"/cmdline"),
				"/usr/local/lib/bugnet/bugnet-run forward --config /etc/bugnet/egress.json")
			eq(t, inContainer(t, id, "stat -c '%a %U:%G' /usr/local/lib/bugnet/bugnet-run"),
				"755 root:root")

			hosts := inContainer(t, id, "cat /etc/hosts")
			eq(t, containerApply(t, id, again), want)
			eq(t, inContainer(t, id, "cat /run/bugnet/forward.pid"), pid)
			eq(t, inContainer(t, id, "cat /etc/hosts"), hosts)
			inContainer(t, id, "echo '10.0.0.10 later.example' >> /etc/hosts")
			s.Hosts = []string{"huggingface.co", "api.github.com"}
			wider, err := json.Marshal(s)
			must(t, err)
			eq(t, containerApply(t, id, wider), `{"forward":"listening","hosts":2,"secrets":1}`)
			eq(t, inContainer(t, id, outside), before+"\n10.0.0.10 later.example")
			eq(t, inContainer(t, id, "stat -c %i /etc/hosts"), inode)
			eq(t, strings.Fields(inContainer(t, id, "getent hosts api.github.com"))[0],
				"127.77.0.1")

			inContainer(t, id, "useradd -m bx")
			npmrc := func(placeholder, want string) {
				t.Helper()
				npm := s
				npm.Home, npm.NPMPlaceholder = "/home/bx", placeholder
				b, err := json.Marshal(npm)
				must(t, err)
				eq(t, containerApply(t, id, b), `{"forward":"listening","hosts":2,"secrets":1}`)
				eq(t, inContainer(t, id, "stat -c '%U %G %a' /home/bx/.npmrc"), "bx bx 600")
				eq(t, inContainer(t, id, "su -s /bin/sh bx -c 'cat ~/.npmrc'"), want)
			}
			block := "# bugnet begin\n//registry.npmjs.org/:_authToken="
			npmrc(npmPlaceholder, block+npmPlaceholder+"\n# bugnet end")
			inContainer(t, id, "su -s /bin/sh bx -c 'echo color=false >> ~/.npmrc'")
			npmrc(ghPlaceholder, block+ghPlaceholder+"\n# bugnet end\ncolor=false")
			npmrc("", "color=false")

			// A process on 0.0.0.0:443 takes the forwarder's address, as user code could
			inContainer(t, id, "kill -9 "+pid)
			inContainer(t, id, "mkdir -p /tmp/s/etc/bugnet && echo "+gateKey+
				" > /tmp/s/etc/bugnet/gate.key && echo '{\"listen\":\":443\","+
				"\"key_file\":\"/etc/bugnet/gate.key\",\"deny\":[],\"ssh_port_file\":\"\"}'"+
				" > /tmp/s/etc/bugnet/gate.json")
			docker(t, nil, "exec", "-d", id, "bugnet-run", "gate", "--config",
				"/tmp/s/etc/bugnet/gate.json", "--root", "/tmp/s")
			waitIn(t, id, "test -e /tmp/s/run/bugnet/gate.pid")
			eq(t, containerApply(t, id, again), `{"error":"port_443_taken"}`)

			inContainer(t, id, "kill $(cat /tmp/s/run/bugnet/gate.pid)")
			waitIn(t, id, "! test -e /tmp/s/run/bugnet/gate.pid")
			eq(t, inContainer(t, id, "bugnet-run respawn"), `{"started":["forward"]}`)
			waitEcho(t, id)
		})
	}
}

func TestContainerApplyX402Hosts(t *testing.T) {
	needDocker(t)
	runner := linuxBuild(t, "github.com/bugnet-sh/bugnet-run/cmd/bugnet-run")
	p := newPKI(t)
	s := spec("agent402.tools")
	s.Endpoint, s.IPs, s.Port, s.Home = testEndpoint, []string{"127.0.0.1"}, 9443, "/root"
	s.Env, s.X402Hosts = []EnvVar{}, []string{"agent402.tools"}
	with, err := json.Marshal(s)
	must(t, err)
	s.Token, s.X402Hosts = "", nil
	without, err := json.Marshal(s)
	must(t, err)

	for _, image := range containerImages {
		t.Run(image, func(t *testing.T) {
			id := docker(t, nil, "run", "-d", "--rm", "--init", image, "sleep", "600")
			t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
			docker(t, nil, "cp", runner, id+":/usr/local/bin/bugnet-run")
			docker(t, p.pem, "exec", "-i", id, "sh", "-c",
				"mkdir -p /etc/ssl/certs && cat > /etc/ssl/certs/ca-certificates.crt")
			want := `{"forward":"listening","hosts":1,"secrets":0}`
			eq(t, containerApply(t, id, with), want)
			eq(t, strings.Fields(inContainer(t, id, "getent hosts agent402.tools")),
				[]string{"127.77.0.1", "agent402.tools"})
			eq(t, loginX402(t, id), "1 agent402.tools")

			eq(t, containerApply(t, id, without), want)
			eq(t, loginX402(t, id), " ")
		})
	}
}

// loginX402 prints the x402 variables as a login shell with an empty environment sees them
func loginX402(t *testing.T, id string) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", id, "env", "-i", "PATH=/usr/bin:/bin", "bash",
		"-lc", `printf "%s %s" "$BUGNET_X402" "$BUGNET_X402_HOSTS"`).Output()
	must(t, err)
	return string(out)
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

// waitEcho checks a tunnel through /etc/hosts, the real 127.77.0.1:443 and the forwarder
func waitEcho(t *testing.T, id string) {
	t.Helper()
	waitIn(t, id, "test -e /run/bugnet/forward.pid")
	eq(t, throughHosts(t, id, "ping"), "ping")
}
