package harden

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
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

func inContainer(t *testing.T, id, script string) string {
	t.Helper()
	return docker(t, nil, "exec", id, "sh", "-c", script)
}

func failsInContainer(id, script string) bool {
	return exec.Command("docker", "exec", id, "sh", "-c", script).Run() != nil
}

// linuxBuild builds bugnet-run for the docker daemon's architecture
func linuxBuild(t *testing.T) string {
	t.Helper()
	arch := docker(t, nil, "version", "--format", "{{.Server.Arch}}")
	bin := filepath.Join(t.TempDir(), "bugnet-run")
	build := exec.Command("go", "build", "-trimpath", "-o", bin,
		"github.com/bugnet-sh/bugnet-run/cmd/bugnet-run")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build for linux/%s: %v\n%s", arch, err, out)
	}
	return bin
}

func hardenContainer(t *testing.T, image, bin string, flags ...string) string {
	t.Helper()
	args := append(append([]string{"run", "-d", "--rm", "--init"}, flags...), image, "sleep",
		"900")
	id := docker(t, nil, args...)
	t.Cleanup(func() { _ = exec.Command("docker", "kill", id).Run() })
	docker(t, nil, "cp", bin, id+":/usr/local/bin/bugnet-run")
	return id
}

// containerHarden runs harden on spec and returns what it printed and its exit status
func containerHarden(t *testing.T, id string, spec []byte) (string, int) {
	t.Helper()
	docker(t, spec, "exec", "-i", id, "sh", "-c",
		"umask 077 && mkdir -p /tmp/bugnet && cat > /tmp/bugnet/harden-spec.json")
	cmd := exec.Command("docker", "exec", id, "bugnet-run", "harden", "--spec",
		"/tmp/bugnet/harden-spec.json")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	code := 0
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	inContainer(t, id, "test ! -e /tmp/bugnet/harden-spec.json")
	if code != 0 {
		t.Logf("harden stderr: %s", errOut.String())
	}
	return strings.TrimSpace(out.String()), code
}

func defaultSpecJSON(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(Spec{
		V: 1, MailPorts: []int{25, 465, 587}, DenyRanges: defaultDeny,
		Pools: []string{"198.51.100.0/24"},
	})
	must(t, err)
	return b
}

// peer starts a gate on 29417 in its own container and returns its address on the bridge
func peer(t *testing.T, image, bin string) string {
	t.Helper()
	id := hardenContainer(t, image, bin)
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	spec := `{"v":1,"gate_key":"` + key + `","gate_listen":":29417","deny_ports":[29417]}`
	docker(t, []byte(spec), "exec", "-i", id, "sh", "-c",
		"mkdir -p /tmp/bugnet && cat > /tmp/bugnet/setup-spec.json")
	inContainer(t, id, "bugnet-run setup --spec /tmp/bugnet/setup-spec.json")
	return docker(t, nil, "inspect", "-f",
		"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", id)
}

// reaches is a script that connects to addr within 5 s with bash alone
func reaches(addr string) string {
	return "timeout 5 bash -c 'echo > /dev/tcp/" + addr + "/29417'"
}

// refusedFast fails unless every blocked kind of connect fails within 1 s, not at a timeout
func refusedFast(t *testing.T, id, peer string) {
	t.Helper()
	refusedFastFrom(t, id, "", peer)
}

// refusedFastFrom runs each connect behind the command prefix from, such as nest
func refusedFastFrom(t *testing.T, id, from, peer string) {
	t.Helper()
	// The peer is in a private range, 25 is a mail port and 198.51.100.0/24 is the spec's pool
	for _, dest := range []string{peer + "/29417", "192.0.2.1/25", "198.51.100.7/80"} {
		refusedWithin1s(t, id, from, dest)
	}
}

// refusedWithin1s fails unless a connect to dest, an address and port, is refused within 1 s
func refusedWithin1s(t *testing.T, id, from, dest string) {
	t.Helper()
	got := inContainer(t, id, "out=$("+from+"timeout 1 bash -c 'echo > /dev/tcp/"+dest+
		"' 2>&1); echo \"$? $out\"")
	if !strings.HasPrefix(got, "1 ") || !strings.Contains(got, "Connection refused") {
		t.Fatalf("a connect to %s gave %q, want a refusal within 1 s", dest, got)
	}
}

func TestContainerHardenTwiceOneTable(t *testing.T) {
	needDocker(t)
	bin := linuxBuild(t)
	spec := defaultSpecJSON(t)
	for _, image := range containerImages {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			addr := peer(t, image, bin)
			id := hardenContainer(t, image, bin, "--cap-add", "NET_ADMIN")
			if failsInContainer(id, reaches(addr)) {
				t.Fatalf("the peer at %s is unreachable before harden", addr)
			}

			for range 2 {
				out, code := containerHarden(t, id, spec)
				eq(t, out, `{"firewall":"nft"}`)
				eq(t, code, 0)
			}
			eq(t, strings.Count(inContainer(t, id, "nft list tables"), "table inet bugnet"), 1)
			chains := inContainer(t, id, "nft list chains inet")
			for _, hook := range []string{"hook output", "hook forward"} {
				eq(t, strings.Count(chains, hook), 1)
			}
			// Forwarded traffic that leaves by no uplink passes, eth0 being the one uplink
			eq(t, inContainer(t, id, "nft list chain inet bugnet forward | "+
				"grep -c 'oifname != .*\"eth0\".* accept'"), "1")
			eq(t, inContainer(t, id, "stat -c '%a %U' /etc/bugnet/firewall.rules"), "644 root")
			refusedFast(t, id, addr)
			// The resolver docker hands out sits in a private range, and must still answer
			inContainer(t, id, "getent hosts deb.debian.org")
			// A check that finds every chain loaded leaves the table alone
			inContainer(t, id, "touch -d '2 minutes ago' /run/bugnet/firewall.checked")
			eq(t, inContainer(t, id, "bugnet-run respawn"), `{"started":[]}`)

			inContainer(t, id, "nft delete table inet bugnet && "+
				"echo > /run/bugnet/firewall.checked && touch -d '2 minutes ago' "+
				"/run/bugnet/firewall.checked")
			eq(t, inContainer(t, id, "bugnet-run respawn"), `{"started":["firewall"]}`)
			eq(t, strings.Count(inContainer(t, id, "nft list tables"), "table inet bugnet"), 1)
			refusedFast(t, id, addr)
			eq(t, inContainer(t, id, "bugnet-run respawn"), `{"started":[]}`)
		})
	}
}

func TestContainerHardenWithIptables(t *testing.T) {
	needDocker(t)
	bin := linuxBuild(t)
	spec := defaultSpecJSON(t)
	for _, image := range containerImages {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			addr := peer(t, image, bin)
			id := hardenContainer(t, image, bin, "--cap-add", "NET_ADMIN")
			inContainer(t, id, "apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive "+
				"apt-get install -y -qq --no-install-recommends iptables >/dev/null")
			// The second restore refills the chain, so it holds as many rules as after the first
			var once []string
			for i := range 2 {
				out, code := containerHarden(t, id, spec)
				eq(t, out, `{"firewall":"iptables"}`)
				eq(t, code, 0)
				var counts []string
				for _, tool := range []string{"iptables", "ip6tables"} {
					counts = append(counts, inContainer(t, id, tool+" -S BUGNET | wc -l"))
				}
				if i == 0 {
					once = counts
				}
				eq(t, counts, once)
			}
			if once[0] == "1" || once[1] == "1" {
				t.Fatalf("a BUGNET chain is empty, with %v lines", once)
			}
			for _, tool := range []string{"iptables", "ip6tables"} {
				eq(t, inContainer(t, id, tool+" -S OUTPUT | grep -- '-j BUGNET'"),
					"-A OUTPUT -j BUGNET")
				eq(t, inContainer(t, id, tool+" -S FORWARD | grep -- '-j BUGNET'"),
					"-A FORWARD -o eth0 -j BUGNET")
			}
			refusedFast(t, id, addr)
			inContainer(t, id, "getent hosts deb.debian.org")
			inContainer(t, id, "touch -d '2 minutes ago' /run/bugnet/firewall.checked")
			eq(t, inContainer(t, id, "bugnet-run respawn"), `{"started":[]}`)

			inContainer(t, id, "iptables -D OUTPUT -j BUGNET && "+
				"touch -d '2 minutes ago' /run/bugnet/firewall.checked")
			eq(t, inContainer(t, id, "bugnet-run respawn"), `{"started":["firewall"]}`)
			eq(t, inContainer(t, id, "iptables -S OUTPUT | grep -c -- '-j BUGNET'"), "1")
			refusedFast(t, id, addr)
		})
	}
}

// nest and nest2 run a command in the nested namespaces nestedNamespace makes
const (
	nest  = "ip netns exec nest "
	nest2 = "ip netns exec nest2 "
)

// nestedNamespace joins namespace nest to the container by a veth pair and nest2 by bridge nestbr
func nestedNamespace(t *testing.T, id, nat string) {
	t.Helper()
	inContainer(t, id, "ip netns add nest && ip link add nest0 type veth peer name nest1 && "+
		"ip link set nest1 netns nest && ip addr add 10.200.0.1/24 dev nest0 && "+
		"ip link set nest0 up && "+nest+"ip addr add 10.200.0.2/24 dev nest1 && "+
		nest+"ip link set nest1 up && "+nest+"ip link set lo up && "+
		nest+"ip route add default via 10.200.0.1 && "+
		"ip link add nestbr type bridge && ip addr add 10.201.0.1/24 dev nestbr && "+
		"ip link set nestbr up && ip netns add nest2 && "+
		"ip link add nest2b type veth peer name nest2a && ip link set nest2b master nestbr && "+
		"ip link set nest2b up && ip link set nest2a netns nest2 && "+
		nest2+"ip addr add 10.201.0.2/24 dev nest2a && "+nest2+"ip link set nest2a up && "+
		nest2+"ip link set lo up && "+nest2+"ip route add default via 10.201.0.1 && "+nat)
	// A listener in nest that nest2 reaches through the container, never by its uplink
	docker(t, nil, "exec", "-d", id, "ip", "netns", "exec", "nest", "perl", "-MIO::Socket::INET",
		"-e", acceptAndClose, "10.200.0.2", "8080")
}

// inside is a script that connects from nest2 to the listener in nest within 5 s
const inside = nest2 + "timeout 5 bash -c 'echo > /dev/tcp/10.200.0.2/8080'"

// Docker or a network namespace in the sandbox sends through the forward hook, never output
func TestContainerHardenForwardsFromANestedNamespace(t *testing.T) {
	needDocker(t)
	bin := linuxBuild(t)
	spec := defaultSpecJSON(t)
	for _, c := range []struct{ firewall, pkg, nat, list, unhook string }{{
		firewall: FirewallNft, pkg: "nftables",
		nat: "nft add table ip nest && nft 'add chain ip nest post " +
			"{ type nat hook postrouting priority 100; }' && " +
			"nft 'add rule ip nest post oifname \"eth0\" ip saddr 10.200.0.0/15 masquerade'",
		list:   "nft list table inet bugnet",
		unhook: "nft flush chain inet bugnet forward && nft delete chain inet bugnet forward",
	}, {
		firewall: FirewallIptables, pkg: "iptables",
		nat:    "iptables -t nat -A POSTROUTING -s 10.200.0.0/15 -o eth0 -j MASQUERADE",
		list:   "iptables -S && ip6tables -S",
		unhook: "iptables -D FORWARD -o eth0 -j BUGNET",
	}} {
		t.Run(c.firewall, func(t *testing.T) {
			t.Parallel()
			addr := peer(t, "ubuntu:24.04", bin)
			id := hardenContainer(t, "ubuntu:24.04", bin, "--privileged")
			inContainer(t, id, "apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive "+
				"apt-get install -y -qq --no-install-recommends iproute2 "+c.pkg+" >/dev/null")
			nestedNamespace(t, id, c.nat)
			for _, from := range []string{nest, nest2} {
				if failsInContainer(id, from+reaches(addr)) {
					t.Fatalf("the peer at %s is unreachable from %q before harden", addr, from)
				}
			}
			reachesInside(t, id)

			// The second load leaves the rules the first one made
			var once string
			for i := range 2 {
				out, code := containerHarden(t, id, spec)
				eq(t, out, `{"firewall":"`+c.firewall+`"}`)
				eq(t, code, 0)
				rules := inContainer(t, id, c.list)
				if i == 0 {
					once = rules
				}
				eq(t, rules, once)
			}
			// Leaving by the uplink meets the blocks, while traffic between nested networks passes
			refusedFastFrom(t, id, nest, addr)
			refusedFastFrom(t, id, nest2, addr)
			reachesInside(t, id)
			// The resolver docker hands out sits in a private range, and must still answer
			inContainer(t, id, nest+"getent hosts deb.debian.org")

			// Only the forward hook stands between the namespace and the peer
			inContainer(t, id, c.unhook+" && touch -d '2 minutes ago' /run/bugnet/firewall.checked")
			if failsInContainer(id, nest+reaches(addr)) {
				t.Fatalf("the peer at %s is unreachable with the forward hook gone", addr)
			}
			eq(t, inContainer(t, id, "bugnet-run respawn"), `{"started":["firewall"]}`)
			eq(t, inContainer(t, id, c.list), once)
			refusedFastFrom(t, id, nest, addr)
			reachesInside(t, id)
		})
	}
}

// reachesInside fails unless nest2 reaches the listener in nest, waiting while it starts
func reachesInside(t *testing.T, id string) {
	t.Helper()
	for range 25 {
		if !failsInContainer(id, inside) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("nest2 never reached the listener in nest, got %q",
		inContainer(t, id, inside+" 2>&1; echo $?"))
}

// userNetwork makes a bridge network whose containers resolve through docker's 127.0.0.11
func userNetwork(t *testing.T) (name, gateway string) {
	t.Helper()
	name = "bugnet-harden-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	docker(t, nil, "network", "create", name)
	t.Cleanup(func() {
		// docker removes a killed container, and with it the network's endpoint, a moment later
		for range 20 {
			if exec.Command("docker", "network", "rm", name).Run() == nil {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	})
	gateway = docker(t, nil, "network", "inspect", "-f",
		"{{range .IPAM.Config}}{{.Gateway}}{{end}}", name)
	return name, gateway
}

// acceptAndClose is a perl script that listens on its address and port and prints ready
const acceptAndClose = "$| = 1; my $s = IO::Socket::INET->new(LocalAddr => $ARGV[0], " +
	"LocalPort => $ARGV[1], Listen => 16, ReuseAddr => 1) or die qq(listen: $!\\n); " +
	"print qq(ready\\n); while (my $c = $s->accept) { close $c }"

// hostListener accepts and closes connections to addr:port in the docker host's namespace
func hostListener(t *testing.T, addr string, port int) {
	t.Helper()
	// No capability, so the host's own firewall stays out of reach
	id := docker(t, nil, "run", "-d", "--rm", "--network", "host", "--cap-drop", "ALL",
		"ubuntu:24.04", "perl", "-MIO::Socket::INET", "-e", acceptAndClose, addr,
		strconv.Itoa(port))
	t.Cleanup(func() { _ = exec.Command("docker", "kill", id).Run() })
	for range 50 {
		if docker(t, nil, "logs", id) == "ready" {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("nothing listens on %s:%d", addr, port)
}

// On Lium the gateway is the host, whose executor listens on 8080
func TestContainerHardenNoGateway(t *testing.T) {
	needDocker(t)
	bin := linuxBuild(t)
	network, gateway := userNetwork(t)
	hostListener(t, gateway, 8080)
	executor := gateway + "/8080"
	for _, c := range []struct {
		firewall, pkg string
		noGateway     bool
	}{
		{FirewallNft, "nftables", false}, {FirewallNft, "nftables", true},
		{FirewallIptables, "iptables", false}, {FirewallIptables, "iptables", true},
	} {
		t.Run(c.firewall+"/no_gateway="+strconv.FormatBool(c.noGateway), func(t *testing.T) {
			t.Parallel()
			id := hardenContainer(t, "ubuntu:24.04", bin, "--network", network, "--cap-add",
				"NET_ADMIN")
			// Installing the tool first keeps harden's own 60 s install out of this test
			inContainer(t, id, "apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive "+
				"apt-get install -y -qq --no-install-recommends "+c.pkg+" >/dev/null")
			eq(t, inContainer(t, id, "sed -n 's/^nameserver //p' /etc/resolv.conf"), "127.0.0.11")
			reach := "timeout 5 bash -c 'echo > /dev/tcp/" + executor + "'"
			if failsInContainer(id, reach) {
				t.Fatalf("the gateway's port at %s is unreachable before harden", executor)
			}

			b, err := json.Marshal(Spec{
				V: 1, MailPorts: []int{25, 465, 587}, DenyRanges: defaultDeny,
				Pools: []string{"198.51.100.0/24"}, NoGateway: c.noGateway,
			})
			must(t, err)
			out, code := containerHarden(t, id, b)
			eq(t, out, `{"firewall":"`+c.firewall+`"}`)
			eq(t, code, 0)
			if c.noGateway {
				refusedWithin1s(t, id, "", executor)
			} else if failsInContainer(id, reach) {
				t.Fatalf("the gateway's port at %s is unreachable after harden", executor)
			}
			// Docker's resolver forwards from the host's namespace, past the sandbox's rules
			inContainer(t, id, "getent hosts deb.debian.org")
		})
	}
}

func TestContainerHardenWithoutCapFails(t *testing.T) {
	needDocker(t)
	bin := linuxBuild(t)
	spec := defaultSpecJSON(t)
	for _, image := range containerImages {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			id := hardenContainer(t, image, bin)
			out, code := containerHarden(t, id, spec)
			eq(t, out, `{"error":"firewall_unavailable"}`)
			eq(t, code, 1)
			inContainer(t, id, "test -x /usr/sbin/nft && test ! -e /etc/bugnet/firewall.rules")
		})
	}
}
