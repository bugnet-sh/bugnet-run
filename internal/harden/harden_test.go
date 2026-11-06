package harden

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oynozan/bugnet-run/internal/sandbox"
)

func TestRulesetAllowsBeforeBlocks(t *testing.T) {
	t.Parallel()
	more := []option{
		resolvConf("nameserver 10.0.0.2\nnameserver fd00::53\n"),
		procFile("net/route", routeTable), procFile("net/ipv6_route", ipv6RouteTable),
		withSpec(func(s *Spec) {
			s.Allow = []string{"10.9.0.0/16", "2001:db8::/32"}
			s.Pools = []string{"198.51.100.0/24", "2001:db8:bad::/48"}
		}),
	}
	rs := buildNft(t, spec(), more...)
	eq(t, lastIndex(rs, "accept") < firstIndex(rs, "drop"), true)
	v4, v6 := buildIptables(t, spec(), more...)
	for _, rs := range []string{v4, v6} {
		eq(t, lastIndex(rs, "-j ACCEPT") < firstIndex(rs, "-j DROP"), true)
	}
}

func TestResolverInPrivateRangeStaysReachable(t *testing.T) {
	t.Parallel()
	rs := buildNft(t, spec(), resolvConf("nameserver 10.0.0.2\n"))
	eq(t, index(rs, "ip daddr 10.0.0.2 udp dport 53 accept") < index(rs, "10.0.0.0/8"), true)
	eq(t, index(rs, "ip daddr 10.0.0.2 tcp dport 53 accept") < index(rs, "10.0.0.0/8"), true)
	v4, _ := buildIptables(t, spec(), resolvConf("nameserver 10.0.0.2\n"))
	eq(t, index(v4, "-A BUGNET -d 10.0.0.2/32 -p udp -m udp --dport 53 -j ACCEPT") <
		index(v4, "-A BUGNET -d 10.0.0.0/8 -j DROP"), true)
}

func TestResolversFromBothFiles(t *testing.T) {
	t.Parallel()
	upstream := func(t *testing.T, f *fixture) {
		writeFile(t, f.h.root.Path("/run/systemd/resolve/resolv.conf"),
			"# managed\nnameserver 172.31.0.2\nnameserver 10.0.0.2\n")
	}
	r := ruleset(t, spec(), upstream, resolvConf("nameserver 127.0.0.53\nsearch x\n"+
		"nameserver fe80::1%eth0\nnameserver 10.0.0.2\nnameserver bogus\n"))
	var got []string
	for _, a := range r.resolvers {
		got = append(got, a.String())
	}
	// Loopback is open already, the zone goes, and each address appears once
	eq(t, got, []string{"fe80::1", "10.0.0.2", "172.31.0.2"})
	eq(t, strings.Contains(r.nft(), "ip6 daddr fe80::1 udp dport 53 accept"), true)
}

// routeTable has a default route through 10.0.0.1 and a link route
const routeTable = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\t" +
	"Window\tIRTT\n" +
	"eth0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
	"eth0\t0000000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"

const ipv6RouteTable = "" +
	"00000000000000000000000000000000 00 00000000000000000000000000000000 00 " +
	"fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n" +
	"00000000000000000000000000000000 00 00000000000000000000000000000000 00 " +
	"00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n" +
	"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 " +
	"00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n"

func TestDefaultGatewaysStayReachable(t *testing.T) {
	t.Parallel()
	rs := buildNft(t, spec(), procFile("net/route", routeTable),
		procFile("net/ipv6_route", ipv6RouteTable))
	eq(t, index(rs, "ip daddr 10.0.0.1 accept") < index(rs, "10.0.0.0/8"), true)
	eq(t, index(rs, "ip6 daddr fe80::1 accept") < index(rs, "fe80::/10"), true)
	_, v6 := buildIptables(t, spec(), procFile("net/ipv6_route", ipv6RouteTable))
	eq(t, index(v6, "-A BUGNET -d fe80::1/128 -j ACCEPT") <
		index(v6, "-A BUGNET -d fe80::/10 -j DROP"), true)
}

func TestNeighbourDiscoveryAndDHCPStayOpen(t *testing.T) {
	t.Parallel()
	rs := buildNft(t, spec())
	for _, rule := range []string{
		"icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept",
		"udp sport 68 udp dport 67 accept", "udp sport 546 udp dport 547 accept",
	} {
		eq(t, index(rs, rule) < index(rs, "drop"), true)
	}
}

func TestEveryBlockOfTheSpec(t *testing.T) {
	t.Parallel()
	rs := buildNft(t, spec())
	for _, rule := range []string{
		"tcp dport { 25, 465, 587 } drop", "ip daddr 10.0.0.0/8 drop",
		"ip daddr 169.254.0.0/16 drop", "ip6 daddr fc00::/7 drop", "ip6 daddr fe80::/10 drop",
		"ip6 daddr fd00:ec2::254 drop", "ip daddr @pools4 drop",
	} {
		index(rs, rule)
	}
	eq(t, strings.Contains(rs, "pools6"), false)
	eq(t, strings.HasPrefix(rs, "# bugnet-run harden nft\ntable inet bugnet\n"+
		"delete table inet bugnet\ntable inet bugnet {\n"), true)
	index(rs, "type filter hook output priority 0; policy accept;")

	// E2B's spec blocks only mail and pools inside, its ranges go outside the VM
	rs = buildNft(t, spec(withSpec(func(s *Spec) { s.DenyRanges, s.Pools = nil, nil })))
	eq(t, strings.Contains(rs, "daddr 10.0.0.0/8"), false)
	eq(t, strings.Contains(rs, "@pools"), false)
	index(rs, "tcp dport { 25, 465, 587 } drop")
}

func TestPoolsCapped(t *testing.T) {
	t.Parallel()
	eq(t, run(t, spec(pools(10001))), `{"error":"bad_spec"}`)
	eq(t, run(t, spec(pools(10000))), `{"firewall":"nft"}`)
}

func TestPoolsMergedAndSplitByFamily(t *testing.T) {
	t.Parallel()
	rs := buildNft(t, spec(withSpec(func(s *Spec) {
		s.Pools = []string{"198.51.100.7", "198.51.100.0/24", "198.51.100.0/25",
			"192.0.2.1/24", "2001:db8::1", "2001:db8::/32", "198.51.100.0/24"}
	})))
	eq(t, strings.Contains(rs, "elements = { 192.0.2.0/24,\n\t\t\t     198.51.100.0/24 }"), true)
	eq(t, strings.Contains(rs, "type ipv6_addr\n\t\tflags interval\n"+
		"\t\telements = { 2001:db8::/32 }"), true)
	index(rs, "ip6 daddr @pools6 drop")
}

func TestBadSpec(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]string{
		"version":       `{"v":2}`,
		"unknown field": `{"v":1,"pools":[],"extra":1}`,
		"trailing data": `{"v":1} {}`,
		"port zero":     `{"v":1,"mail_ports":[0]}`,
		"port too high": `{"v":1,"mail_ports":[65536]}`,
		"bad range":     `{"v":1,"deny_ranges":["10.0.0.0/33"]}`,
		"bad pool":      `{"v":1,"pools":["mining.example"]}`,
		"zoned allow":   `{"v":1,"allow":["fe80::1%eth0"]}`,
		"not json":      `nope`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			eq(t, f.runRaw(t, []byte(raw)), `{"error":"bad_spec"}`)
			eq(t, f.fakes.take(), []call(nil))
		})
	}
}

func TestBadSpecNeverQuotesTheValue(t *testing.T) {
	t.Parallel()
	s := Spec{V: 1, Pools: []string{"198.51.100.0/24", "secret-looking.example"}}
	err := s.check()
	eq(t, err != nil && strings.Contains(err.Error(), "pools[1]"), true)
	eq(t, strings.Contains(err.Error(), "secret-looking"), false)
}

func TestHardenLoadsNftAndKeepsTheRuleset(t *testing.T) {
	t.Parallel()
	f := newFixture(t, resolvConf("nameserver 10.0.0.2\n"))
	eq(t, f.run(t), `{"firewall":"nft"}`)
	calls := f.fakes.take()
	eq(t, names(calls), []string{"nft -f FILE"})
	path := f.h.root.Path(RulesFile)
	b, err := os.ReadFile(path)
	must(t, err)
	eq(t, string(b), calls[0].stdin)
	eq(t, string(b), f.h.rules(f.spec).nft())
	info, err := os.Stat(path)
	must(t, err)
	eq(t, info.Mode().Perm(), os.FileMode(0o644))
	leftovers, err := os.ReadDir(f.h.root.Path(sandbox.EtcDir))
	must(t, err)
	eq(t, len(leftovers), 1)

	eq(t, f.run(t), `{"firewall":"nft"}`)
	eq(t, names(f.fakes.take()), []string{"nft -f FILE"})
	b2, err := os.ReadFile(path)
	must(t, err)
	eq(t, string(b2), string(b))
}

func TestHardenFallsBackToIptables(t *testing.T) {
	t.Parallel()
	f := newFixture(t, procFile("net/if_inet6", "x"))
	f.fakes = newFakeTools("iptables")
	f.h.tools = f.fakes.tools()
	f.fakes.answer = func(c call) (string, error) {
		if len(c.args) > 1 && c.args[1] == "-C" {
			return "", errors.New("exit status 1")
		}
		return "", nil
	}
	eq(t, f.run(t), `{"firewall":"iptables"}`)
	calls := f.fakes.take()
	eq(t, names(calls), []string{
		"iptables-restore --noflush", "iptables -w -C OUTPUT -j BUGNET",
		"iptables -w -I OUTPUT 1 -j BUGNET",
		"ip6tables-restore --noflush", "ip6tables -w -C OUTPUT -j BUGNET",
		"ip6tables -w -I OUTPUT 1 -j BUGNET",
	})
	v4, v6 := f.h.rules(f.spec).iptables()
	eq(t, calls[0].stdin, v4)
	eq(t, calls[3].stdin, v6)
	eq(t, strings.HasPrefix(v4, "*filter\n:BUGNET - [0:0]\n"), true)
	eq(t, strings.HasSuffix(v4, "COMMIT\n"), true)
	b, err := os.ReadFile(f.h.root.Path(RulesFile))
	must(t, err)
	eq(t, string(b), "# bugnet-run harden iptables\n"+v4+"# ipv6\n"+v6)

	// A jump already in OUTPUT is never added twice
	f.fakes.answer = nil
	eq(t, f.run(t), `{"firewall":"iptables"}`)
	eq(t, names(f.fakes.take()), []string{
		"iptables-restore --noflush", "iptables -w -C OUTPUT -j BUGNET",
		"ip6tables-restore --noflush", "ip6tables -w -C OUTPUT -j BUGNET",
	})
}

func TestIptablesWithoutIPv6SkipsIt(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.fakes = newFakeTools("iptables")
	f.h.tools = f.fakes.tools()
	f.fakes.answer = func(c call) (string, error) {
		if c.name == "ip6tables-restore" {
			return "can't initialize ip6tables table `filter'", errors.New("exit status 3")
		}
		return "", nil
	}
	eq(t, f.run(t), `{"firewall":"iptables"}`)

	writeFile(t, f.h.procDir+"/net/if_inet6", "x")
	eq(t, f.run(t), `{"error":"firewall_unavailable"}`)
}

func TestHardenInstallsNftablesWithNeither(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.fakes = newFakeTools()
	f.fakes.installs = []string{"nft"}
	f.h.tools = f.fakes.tools()
	eq(t, f.run(t), `{"firewall":"nft"}`)
	eq(t, names(f.fakes.take()), []string{"apt-get install", "nft -f FILE"})
}

func TestFirewallUnavailable(t *testing.T) {
	t.Parallel()
	refused := newFixture(t)
	refused.fakes.answer = func(call) (string, error) {
		return "Error: Could not process rule: Operation not permitted", errors.New("exit status 1")
	}
	eq(t, refused.run(t), `{"error":"firewall_unavailable"}`)
	_, err := os.Stat(refused.h.root.Path(RulesFile))
	eq(t, errors.Is(err, os.ErrNotExist), true)
	leftovers, err := os.ReadDir(refused.h.root.Path(sandbox.EtcDir))
	must(t, err)
	eq(t, len(leftovers), 0)

	noInstall := newFixture(t)
	noInstall.fakes = newFakeTools()
	noInstall.fakes.install = errors.New("apt-get: exit status 100")
	noInstall.h.tools = noInstall.fakes.tools()
	eq(t, noInstall.run(t), `{"error":"firewall_unavailable"}`)

	// An install that leaves no nft is unavailable too, never a crash
	empty := newFixture(t)
	empty.fakes = newFakeTools()
	empty.h.tools = empty.fakes.tools()
	eq(t, empty.run(t), `{"error":"firewall_unavailable"}`)
}

func TestRecheckReloadsAMissingTable(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	eq(t, Due(f.h.root, now), false)
	eq(t, f.run(t), `{"firewall":"nft"}`)
	f.fakes.take()
	// harden itself counts as a check
	eq(t, Due(f.h.root, time.Now()), false)
	eq(t, Due(f.h.root, time.Now().Add(time.Minute)), true)

	f.fakes.answer = func(c call) (string, error) {
		if c.args[0] == "list" {
			return "table ip filter\ntable inet bugnet\n", nil
		}
		return "", nil
	}
	later := time.Now().Add(2 * time.Minute)
	reloaded, err := f.h.recheck(t.Context(), later)
	must(t, err)
	eq(t, reloaded, false)
	eq(t, names(f.fakes.take()), []string{"nft list tables"})
	eq(t, Due(f.h.root, later.Add(59*time.Second)), false)
	eq(t, Due(f.h.root, later.Add(time.Minute)), true)

	f.fakes.answer = func(c call) (string, error) {
		if c.args[0] == "list" {
			return "table ip filter\ntable inet bugnetx\n", nil
		}
		return "", nil
	}
	reloaded, err = f.h.recheck(t.Context(), later.Add(time.Minute))
	must(t, err)
	eq(t, reloaded, true)
	calls := f.fakes.take()
	eq(t, names(calls), []string{"nft list tables", "nft -f FILE"})
	b, err := os.ReadFile(f.h.root.Path(RulesFile))
	must(t, err)
	eq(t, calls[1].stdin, string(b))
}

func TestRecheckIptables(t *testing.T) {
	t.Parallel()
	f := newFixture(t, procFile("net/if_inet6", "x"))
	f.fakes = newFakeTools("iptables")
	f.h.tools = f.fakes.tools()
	eq(t, f.run(t), `{"firewall":"iptables"}`)
	f.fakes.take()

	reloaded, err := f.h.recheck(t.Context(), time.Now().Add(time.Hour))
	must(t, err)
	eq(t, reloaded, false)
	eq(t, names(f.fakes.take()), []string{
		"iptables -w -C OUTPUT -j BUGNET", "ip6tables -w -C OUTPUT -j BUGNET",
	})

	f.fakes.answer = func(c call) (string, error) {
		if c.name == "ip6tables" && c.args[1] == "-C" {
			return "", errors.New("exit status 1")
		}
		return "", nil
	}
	reloaded, err = f.h.recheck(t.Context(), time.Now().Add(2*time.Hour))
	must(t, err)
	eq(t, reloaded, true)
	eq(t, names(f.fakes.take())[2:], []string{
		"iptables-restore --noflush", "iptables -w -C OUTPUT -j BUGNET",
		"ip6tables-restore --noflush", "ip6tables -w -C OUTPUT -j BUGNET",
		"ip6tables -w -I OUTPUT 1 -j BUGNET",
	})
}

func TestRecheckWithoutRulesDoesNothing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	reloaded, err := f.h.recheck(t.Context(), time.Now())
	must(t, err)
	eq(t, reloaded, false)
	eq(t, f.fakes.take(), []call(nil))

	writeFile(t, f.h.root.Path(RulesFile), "# written by hand\n")
	_, err = f.h.recheck(t.Context(), time.Now())
	eq(t, err != nil, true)
	eq(t, f.fakes.take(), []call(nil))
}
