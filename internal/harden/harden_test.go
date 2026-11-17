package harden

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bugnet-sh/bugnet-run/internal/sandbox"
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
	chains := strings.Split(buildNft(t, spec(), more...), "\tchain ")[1:]
	eq(t, len(chains), 2)
	for _, rs := range chains {
		eq(t, lastIndex(t, rs, "accept") < firstIndex(t, rs, "reject"), true)
	}
	v4, v6 := buildIptables(t, spec(), more...)
	for _, rs := range []string{v4, v6} {
		eq(t, lastIndex(t, rs, "-j ACCEPT") < firstIndex(t, rs, "-j REJECT"), true)
	}
}

// A dropped SYN is sent again until the client gives up, which a paying agent waits out
func TestBlocksRejectAndNeverDrop(t *testing.T) {
	t.Parallel()
	more := []option{procFile("net/if_inet6", "x"), withSpec(func(s *Spec) {
		s.Pools = []string{"198.51.100.0/24", "2001:db8:bad::/48"}
	})}
	rs := buildNft(t, spec(), more...)
	v4, v6 := buildIptables(t, spec(), more...)
	for _, text := range []string{rs, v4, v6} {
		for line := range strings.Lines(text) {
			if f := strings.Fields(line); len(f) > 0 && strings.EqualFold(f[len(f)-1], "drop") {
				t.Fatalf("a rule drops: %q", line)
			}
		}
	}

	// TCP takes a reset before the rule that answers everything else
	for _, match := range []string{
		"ip daddr 10.0.0.0/8", "ip6 daddr fe80::/10", "ip6 daddr fd00:ec2::254",
		"ip daddr @pools4", "ip6 daddr @pools6",
	} {
		eq(t, index(t, rs, match+" meta l4proto tcp reject with tcp reset\n") <
			index(t, rs, match+" reject with icmpx type admin-prohibited\n"), true)
	}
	for _, c := range []struct{ text, dest, prohibited string }{
		{v4, "10.0.0.0/8", "icmp-admin-prohibited"},
		{v4, "198.51.100.0/24", "icmp-admin-prohibited"},
		{v6, "fe80::/10", "icmp6-adm-prohibited"},
		{v6, "2001:db8:bad::/48", "icmp6-adm-prohibited"},
	} {
		reset := "-A BUGNET -d " + c.dest + " -p tcp -j REJECT --reject-with tcp-reset\n"
		other := "-A BUGNET -d " + c.dest + " -j REJECT --reject-with " + c.prohibited + "\n"
		eq(t, index(t, c.text, reset) < index(t, c.text, other), true)
	}
	for _, port := range []string{"25", "465", "587"} {
		for _, text := range []string{v4, v6} {
			index(t, text, "-A BUGNET -p tcp -m tcp --dport "+port+
				" -j REJECT --reject-with tcp-reset\n")
		}
	}
}

func TestResolverInPrivateRangeStaysReachable(t *testing.T) {
	t.Parallel()
	rs := buildNft(t, spec(), resolvConf("nameserver 10.0.0.2\n"))
	eq(t, index(t, rs, "ip daddr 10.0.0.2 udp dport 53 accept") < index(t, rs, "10.0.0.0/8"), true)
	eq(t, index(t, rs, "ip daddr 10.0.0.2 tcp dport 53 accept") < index(t, rs, "10.0.0.0/8"), true)
	v4, _ := buildIptables(t, spec(), resolvConf("nameserver 10.0.0.2\n"))
	eq(t, index(t, v4, "-A BUGNET -d 10.0.0.2/32 -p udp -m udp --dport 53 -j ACCEPT") <
		index(t, v4, "-A BUGNET -d 10.0.0.0/8 -p tcp -j REJECT"), true)
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
	eq(t, index(t, rs, "ip daddr 10.0.0.1 accept") < index(t, rs, "10.0.0.0/8"), true)
	eq(t, index(t, rs, "ip6 daddr fe80::1 accept") < index(t, rs, "fe80::/10"), true)
	_, v6 := buildIptables(t, spec(), procFile("net/ipv6_route", ipv6RouteTable))
	eq(t, index(t, v6, "-A BUGNET -d fe80::1/128 -j ACCEPT") <
		index(t, v6, "-A BUGNET -d fe80::/10 -p tcp -j REJECT"), true)
}

// A gateway that is the provider's host falls under the private-range blocks
func TestHardenNoGateway(t *testing.T) {
	t.Parallel()
	opts := spec(resolvConf("nameserver 10.0.0.1\n"), procFile("net/route", routeTable),
		procFile("net/ipv6_route", ipv6RouteTable))
	noGateway := withSpec(func(s *Spec) { s.NoGateway = true })
	v4, v6 := buildIptables(t, opts)
	offV4, offV6 := buildIptables(t, opts, noGateway)
	for _, c := range []struct {
		kept, dropped string
		accepts       []string
	}{
		{buildNft(t, opts), buildNft(t, opts, noGateway),
			[]string{"\t\tip daddr 10.0.0.1 accept\n", "\t\tip6 daddr fe80::1 accept\n"}},
		{v4, offV4, []string{"-A BUGNET -d 10.0.0.1/32 -j ACCEPT\n"}},
		{v6, offV6, []string{"-A BUGNET -d fe80::1/128 -j ACCEPT\n"}},
	} {
		// The default keeps each gateway accept, and no_gateway drops those lines alone
		want := c.kept
		for _, line := range c.accepts {
			index(t, c.kept, line)
			want = strings.ReplaceAll(want, line, "")
		}
		eq(t, c.dropped, want)
	}

	// The resolver at the gateway still answers, and every other port of it is rejected
	rs := buildNft(t, opts, noGateway)
	eq(t, index(t, rs, "ip daddr 10.0.0.1 udp dport 53 accept") <
		index(t, rs, "ip daddr 10.0.0.0/8 meta l4proto tcp reject with tcp reset"), true)
	eq(t, index(t, offV4, "-A BUGNET -d 10.0.0.1/32 -p tcp -m tcp --dport 53 -j ACCEPT") <
		index(t, offV4, "-A BUGNET -d 10.0.0.0/8 -p tcp -j REJECT"), true)

	f := newFixture(t, opts...)
	eq(t, f.runRaw(t, []byte(`{"v":1,"deny_ranges":["10.0.0.0/8"],"no_gateway":true}`)),
		`{"firewall":"nft"}`)
	calls := f.fakes.take()
	eq(t, names(calls), []string{"nft -f FILE"})
	eq(t, strings.Contains(calls[0].stdin, "daddr 10.0.0.1 accept"), false)
	index(t, calls[0].stdin, "ip daddr 10.0.0.0/8 meta l4proto tcp reject with tcp reset")
}

func TestNeighbourDiscoveryAndDHCPStayOpen(t *testing.T) {
	t.Parallel()
	rs := buildNft(t, spec())
	for _, rule := range []string{
		"icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept",
		"udp sport 68 udp dport 67 accept", "udp sport 546 udp dport 547 accept",
	} {
		eq(t, index(t, rs, rule) < index(t, rs, "reject"), true)
	}
}

func TestEveryBlockOfTheSpec(t *testing.T) {
	t.Parallel()
	rs := buildNft(t, spec())
	for _, rule := range []string{
		"tcp dport { 25, 465, 587 } reject with tcp reset", "ip daddr 10.0.0.0/8 ",
		"ip daddr 169.254.0.0/16 ", "ip6 daddr fc00::/7 ", "ip6 daddr fe80::/10 ",
		"ip6 daddr fd00:ec2::254 ", "ip daddr @pools4 ",
	} {
		index(t, rs, rule)
	}
	eq(t, strings.Contains(rs, "pools6"), false)
	eq(t, strings.HasPrefix(rs, "# bugnet-run harden nft\ntable inet bugnet\n"+
		"delete table inet bugnet\ntable inet bugnet {\n"), true)
	index(t, rs, "type filter hook output priority 0; policy accept;")

	// E2B's spec blocks only mail and pools inside, its ranges go outside the VM
	rs = buildNft(t, spec(withSpec(func(s *Spec) { s.DenyRanges, s.Pools = nil, nil })))
	eq(t, strings.Contains(rs, "daddr 10.0.0.0/8"), false)
	eq(t, strings.Contains(rs, "@pools"), false)
	index(t, rs, "tcp dport { 25, 465, 587 } reject with tcp reset")
}

// Docker or a nested namespace in the sandbox sends through forward, which output never sees
func TestForwardChainCarriesTheOutputRules(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		opts []option
		// stays is the forward chain's first rule, which passes what leaves by no uplink
		stays string
	}{
		"defaults": {spec(), ""},
		"e2b":      {spec(withSpec(func(s *Spec) { s.DenyRanges, s.Pools = nil, nil })), ""},
		"addresses": {spec(resolvConf("nameserver 10.0.0.2\n"), procFile("net/route", routeTable),
			withSpec(func(s *Spec) {
				s.Allow = []string{"10.9.0.0/16"}
				s.Pools = []string{"198.51.100.0/24", "2001:db8:bad::/48"}
			})), "\t\toifname != { \"eth0\" } accept\n"},
		"two uplinks": {spec(procFile("net/route", routeTable),
			procFile("net/ipv6_route", wg0RouteTable)),
			"\t\toifname != { \"eth0\", \"wg0\" } accept\n"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := ruleset(t, c.opts)
			rs := r.nft()
			body := "\t\t" + strings.Join(r.nftRules(), "\n\t\t") + "\n\t}\n"
			output := index(t, rs, "\tchain output {\n"+
				"\t\ttype filter hook output priority 0; policy accept;\n"+body)
			forward := index(t, rs, "\tchain forward {\n"+
				"\t\ttype filter hook forward priority 0; policy accept;\n"+c.stays+body)
			eq(t, output < forward, true)
			eq(t, strings.Count(rs, "\tchain "), 2)
			eq(t, strings.Count(rs, "oifname !="), strings.Count(c.stays, "oifname !="))
			eq(t, strings.HasSuffix(rs, "\t}\n}\n"), true)
		})
	}
}

// wg0RouteTable has an IPv6 default route out of wg0 with no next hop
const wg0RouteTable = "" +
	"00000000000000000000000000000000 00 00000000000000000000000000000000 00 " +
	"00000000000000000000000000000000 00000400 00000001 00000000 00000001 wg0\n"

// ipv4Route is a line of /proc/net/route for a route through gateway on dev with flags
func ipv4Route(dev, dest, gateway, flags, mask string) string {
	return dev + "\t" + dest + "\t" + gateway + "\t" + flags + "\t0\t0\t0\t" + mask + "\t0\t0\t0\n"
}

// An uplink carries a default route, the one way forwarded traffic leaves the sandbox
func TestUplinksFromTheDefaultRoutes(t *testing.T) {
	t.Parallel()
	header := strings.SplitAfter(routeTable, "\n")[0]
	many := header
	for i := range 17 {
		many += ipv4Route("eth"+strconv.Itoa(i), "00000000", "0100000A", "0003", "00000000")
	}
	unreachable := ipv4Route("*", "00000000", "00000000", "0201", "00000000")
	blackhole := ipv4Route("*", "00000000", "00000000", "0001", "00000000")
	for name, c := range map[string]struct {
		route, route6 string
		want          []string
	}{
		"no routes": {"", "", nil},
		"one":       {routeTable, ipv6RouteTable, []string{"eth0"}},
		"two":       {routeTable, wg0RouteTable, []string{"eth0", "wg0"}},
		"two of ipv4": {routeTable + ipv4Route("eth1", "00000000", "0101A8C0", "0003", "00000000"),
			"", []string{"eth0", "eth1"}},
		"link routes alone": {header + ipv4Route("eth0", "0000000A", "00000000", "0001",
			"00FFFFFF"), "", nil},
		"rejects and blackholes": {header + unreachable + blackhole,
			strings.SplitAfter(ipv6RouteTable, "\n")[1], nil},
		"sixteen": {strings.Join(strings.SplitAfter(many, "\n")[:17], ""), "",
			[]string{"eth0", "eth1", "eth10", "eth11", "eth12", "eth13", "eth14", "eth15", "eth2",
				"eth3", "eth4", "eth5", "eth6", "eth7", "eth8", "eth9"}},
		// Leaving out a device that carries a default route would pass what leaves by it
		"seventeen": {many, "", nil},
		"unsafe name": {routeTable + ipv4Route(`e"0`, "00000000", "0101A8C0", "0003",
			"00000000"), "", nil},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := spec()
			if c.route != "" {
				opts = append(opts, procFile("net/route", c.route))
			}
			if c.route6 != "" {
				opts = append(opts, procFile("net/ipv6_route", c.route6))
			}
			eq(t, ruleset(t, opts).uplinks, c.want)
		})
	}

	// A default route with no next hop names an uplink and no gateway
	r := ruleset(t, spec(procFile("net/route", routeTable), procFile("net/ipv6_route",
		wg0RouteTable)))
	eq(t, len(r.gateways), 1)
	eq(t, r.gateways[0].String(), "10.0.0.1")
	// no_gateway drops the gateways and keeps the uplinks
	r = ruleset(t, spec(procFile("net/route", routeTable), withSpec(func(s *Spec) {
		s.NoGateway = true
	})))
	eq(t, len(r.gateways), 0)
	eq(t, r.uplinks, []string{"eth0"})
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
	index(t, rs, "ip6 daddr @pools6 meta l4proto tcp reject with tcp reset")
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

func TestWrongArgumentAfterTheSpecStillDeletesIt(t *testing.T) {
	t.Parallel()
	for name, extra := range map[string]string{"unknown flag": "--bogus", "extra": "extra"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			path := filepath.Join(t.TempDir(), "harden-spec.json")
			writeFile(t, path, `{"v":1}`)
			var out bytes.Buffer
			code := f.h.main(t.Context(), []string{"--spec", path, extra}, &out, io.Discard)
			eq(t, code, 1)
			eq(t, out.String(), "{\"error\":\"bad_spec\"}\n")
			_, err := os.Stat(path)
			eq(t, errors.Is(err, os.ErrNotExist), true)
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

// With no uplink found, FORWARD jumps for every packet
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
		"iptables -w -I OUTPUT 1 -j BUGNET", "iptables -w -C FORWARD -j BUGNET",
		"iptables -w -I FORWARD 1 -j BUGNET",
		"ip6tables-restore --noflush", "ip6tables -w -C OUTPUT -j BUGNET",
		"ip6tables -w -I OUTPUT 1 -j BUGNET", "ip6tables -w -C FORWARD -j BUGNET",
		"ip6tables -w -I FORWARD 1 -j BUGNET",
	})
	v4, v6 := f.h.rules(f.spec).iptables()
	eq(t, calls[0].stdin, v4)
	eq(t, calls[5].stdin, v6)
	eq(t, strings.HasPrefix(v4, "*filter\n:BUGNET - [0:0]\n"), true)
	eq(t, strings.HasSuffix(v4, "COMMIT\n"), true)
	b, err := os.ReadFile(f.h.root.Path(RulesFile))
	must(t, err)
	eq(t, string(b), "# bugnet-run harden iptables\n"+v4+"# ipv6\n"+v6)

	// A jump already in OUTPUT or FORWARD is never added twice
	f.fakes.answer = nil
	eq(t, f.run(t), `{"firewall":"iptables"}`)
	eq(t, names(f.fakes.take()), []string{
		"iptables-restore --noflush", "iptables -w -C OUTPUT -j BUGNET",
		"iptables -w -C FORWARD -j BUGNET",
		"ip6tables-restore --noflush", "ip6tables -w -C OUTPUT -j BUGNET",
		"ip6tables -w -C FORWARD -j BUGNET",
	})

	// A chain kept from a runner without the forward hook gains the FORWARD jump alone
	f.fakes.answer = func(c call) (string, error) {
		if len(c.args) > 2 && c.args[1] == "-C" && c.args[2] == "FORWARD" {
			return "", errors.New("exit status 1")
		}
		return "", nil
	}
	eq(t, f.run(t), `{"firewall":"iptables"}`)
	eq(t, names(f.fakes.take()), []string{
		"iptables-restore --noflush", "iptables -w -C OUTPUT -j BUGNET",
		"iptables -w -C FORWARD -j BUGNET", "iptables -w -I FORWARD 1 -j BUGNET",
		"ip6tables-restore --noflush", "ip6tables -w -C OUTPUT -j BUGNET",
		"ip6tables -w -C FORWARD -j BUGNET", "ip6tables -w -I FORWARD 1 -j BUGNET",
	})
}

// Forwarded traffic that leaves by no uplink stays inside the sandbox and skips BUGNET
func TestIptablesForwardJumpsByEachUplink(t *testing.T) {
	t.Parallel()
	f := newFixture(t, procFile("net/if_inet6", "x"), procFile("net/route", routeTable),
		procFile("net/ipv6_route", wg0RouteTable))
	f.fakes = newFakeTools("iptables")
	f.h.tools = f.fakes.tools()
	missing := func(rule string) func(c call) (string, error) {
		return func(c call) (string, error) {
			if rule == "all" && len(c.args) > 1 && c.args[1] == "-C" || c.String() == rule {
				return "", errors.New("exit status 1")
			}
			return "", nil
		}
	}
	f.fakes.answer = missing("all")
	eq(t, f.run(t), `{"firewall":"iptables"}`)
	calls := f.fakes.take()
	var want []string
	for _, tool := range []string{"iptables", "ip6tables"} {
		want = append(want, tool+"-restore --noflush",
			tool+" -w -C OUTPUT -j BUGNET", tool+" -w -I OUTPUT 1 -j BUGNET",
			tool+" -w -C FORWARD -o eth0 -j BUGNET", tool+" -w -I FORWARD 1 -o eth0 -j BUGNET",
			tool+" -w -C FORWARD -o wg0 -j BUGNET", tool+" -w -I FORWARD 1 -o wg0 -j BUGNET")
	}
	eq(t, names(calls), want)
	v4, v6 := f.h.rules(f.spec).iptables()
	b, err := os.ReadFile(f.h.root.Path(RulesFile))
	must(t, err)
	eq(t, string(b), "# bugnet-run harden iptables\n# uplinks eth0 wg0\n"+v4+"# ipv6\n"+v6)

	// Each jump goes in once
	f.fakes.answer = nil
	eq(t, f.run(t), `{"firewall":"iptables"}`)
	checks := []string{
		"iptables -w -C OUTPUT -j BUGNET", "iptables -w -C FORWARD -o eth0 -j BUGNET",
		"iptables -w -C FORWARD -o wg0 -j BUGNET", "ip6tables -w -C OUTPUT -j BUGNET",
		"ip6tables -w -C FORWARD -o eth0 -j BUGNET", "ip6tables -w -C FORWARD -o wg0 -j BUGNET",
	}
	eq(t, names(f.fakes.take()), slices.Concat([]string{"iptables-restore --noflush"},
		checks[:3], []string{"ip6tables-restore --noflush"}, checks[3:]))

	// The recheck checks the uplinks the kept ruleset names, whatever the routes say now
	writeFile(t, filepath.Join(f.h.procDir, "net", "route"), "")
	writeFile(t, filepath.Join(f.h.procDir, "net", "ipv6_route"), "")
	reloaded, err := f.h.recheck(t.Context(), time.Now())
	must(t, err)
	eq(t, reloaded, false)
	eq(t, names(f.fakes.take()), checks)

	// A jump gone alone counts as the table gone, and comes back alone
	f.fakes.answer = missing("iptables -w -C FORWARD -o wg0 -j BUGNET")
	reloaded, err = f.h.recheck(t.Context(), time.Now())
	must(t, err)
	eq(t, reloaded, true)
	eq(t, names(f.fakes.take()), slices.Concat(checks[:3], []string{"iptables-restore --noflush"},
		checks[:3], []string{"iptables -w -I FORWARD 1 -o wg0 -j BUGNET",
			"ip6tables-restore --noflush"}, checks[3:]))
	after, err := os.ReadFile(f.h.root.Path(RulesFile))
	must(t, err)
	eq(t, string(after), string(b))

	// A ruleset kept by a runner that named no uplinks filters every forwarded packet
	writeFile(t, f.h.root.Path(RulesFile), "# bugnet-run harden iptables\n"+v4+"# ipv6\n"+v6)
	f.fakes.answer = nil
	reloaded, err = f.h.recheck(t.Context(), time.Now())
	must(t, err)
	eq(t, reloaded, false)
	eq(t, names(f.fakes.take()), []string{
		"iptables -w -C OUTPUT -j BUGNET", "iptables -w -C FORWARD -j BUGNET",
		"ip6tables -w -C OUTPUT -j BUGNET", "ip6tables -w -C FORWARD -j BUGNET",
	})

	// An uplink name that is no interface name makes the kept ruleset unreadable
	writeFile(t, f.h.root.Path(RulesFile), "# bugnet-run harden iptables\n# uplinks -j\n"+v4+
		"# ipv6\n"+v6)
	_, err = f.h.recheck(t.Context(), time.Now())
	eq(t, err != nil, true)
	eq(t, f.fakes.take(), []call(nil))
}

func TestIptablesForwardJumpsByOneUplink(t *testing.T) {
	t.Parallel()
	f := newFixture(t, procFile("net/route", routeTable))
	f.fakes = newFakeTools("iptables")
	f.h.tools = f.fakes.tools()
	eq(t, f.run(t), `{"firewall":"iptables"}`)
	eq(t, names(f.fakes.take()), []string{
		"iptables-restore --noflush", "iptables -w -C OUTPUT -j BUGNET",
		"iptables -w -C FORWARD -o eth0 -j BUGNET",
		"ip6tables-restore --noflush", "ip6tables -w -C OUTPUT -j BUGNET",
		"ip6tables -w -C FORWARD -o eth0 -j BUGNET",
	})
	b, err := os.ReadFile(f.h.root.Path(RulesFile))
	must(t, err)
	eq(t, strings.HasPrefix(string(b), "# bugnet-run harden iptables\n# uplinks eth0\n*filter\n"),
		true)
}

func TestNftFailureFallsBackToIptables(t *testing.T) {
	t.Parallel()
	f := newFixture(t, procFile("net/if_inet6", "x"))
	f.fakes = newFakeTools("nft", "iptables")
	f.h.tools = f.fakes.tools()
	f.fakes.answer = func(c call) (string, error) {
		if c.name == "nft" {
			return "Error: Could not process rule: No such file or directory",
				errors.New("exit status 1")
		}
		return "", nil
	}
	eq(t, f.run(t), `{"firewall":"iptables"}`)
	eq(t, names(f.fakes.take()), []string{
		"nft -f FILE", "iptables-restore --noflush", "iptables -w -C OUTPUT -j BUGNET",
		"iptables -w -C FORWARD -j BUGNET", "ip6tables-restore --noflush",
		"ip6tables -w -C OUTPUT -j BUGNET", "ip6tables -w -C FORWARD -j BUGNET",
	})
	b, err := os.ReadFile(f.h.root.Path(RulesFile))
	must(t, err)
	eq(t, strings.HasPrefix(string(b), "# bugnet-run harden iptables\n"), true)
	entries, err := os.ReadDir(f.h.root.Path(sandbox.EtcDir))
	must(t, err)
	eq(t, len(entries), 1)
}

func TestRefusedLoadKeepsTheEarlierRuleset(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	eq(t, f.run(t), `{"firewall":"nft"}`)
	f.fakes.take()
	path := f.h.root.Path(RulesFile)
	before, err := os.ReadFile(path)
	must(t, err)

	// One more pool changes the text, so a refused ruleset that took the old one's place shows
	f.spec.Pools = append(f.spec.Pools, "203.0.113.0/24")
	f.fakes.answer = func(call) (string, error) {
		return "Error: Could not process rule: Operation not permitted", errors.New("exit status 1")
	}
	eq(t, f.run(t), `{"error":"firewall_unavailable"}`)
	calls := f.fakes.take()
	eq(t, names(calls), []string{"nft -f FILE"})
	eq(t, calls[0].stdin != string(before), true)
	after, err := os.ReadFile(path)
	must(t, err)
	eq(t, string(after), string(before))
	entries, err := os.ReadDir(f.h.root.Path(sandbox.EtcDir))
	must(t, err)
	eq(t, len(entries), 1)
	eq(t, entries[0].Name(), "firewall.rules")

	// The kept ruleset still brings a lost table back
	f.fakes.answer = func(c call) (string, error) {
		if c.args[0] == "list" {
			return "table inet filter {\n\tchain input {\n\t}\n}\n", nil
		}
		return "", nil
	}
	reloaded, err := f.h.recheck(t.Context(), time.Now().Add(time.Hour))
	must(t, err)
	eq(t, reloaded, true)
	calls = f.fakes.take()
	eq(t, names(calls), []string{"nft list chains inet", "nft -f FILE"})
	eq(t, calls[1].stdin, string(before))
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

// A failed IPv6 load puts back the IPv4 chain firewall.rules keeps, so the two never differ
func TestIptablesLoadsBothChainsOrNeither(t *testing.T) {
	t.Parallel()
	f := newFixture(t, procFile("net/if_inet6", "x"))
	f.fakes = newFakeTools("iptables")
	f.h.tools = f.fakes.tools()
	eq(t, f.run(t), `{"firewall":"iptables"}`)
	f.fakes.take()
	path := f.h.root.Path(RulesFile)
	kept, err := os.ReadFile(path)
	must(t, err)
	oldV4, _ := f.h.rules(f.spec).iptables()

	f.spec.Pools = append(f.spec.Pools, "203.0.113.0/24")
	newV4, _ := f.h.rules(f.spec).iptables()
	f.fakes.answer = func(c call) (string, error) {
		if c.name == "ip6tables-restore" {
			return "ip6tables-restore: line 3 failed", errors.New("exit status 1")
		}
		return "", nil
	}
	eq(t, f.run(t), `{"error":"firewall_unavailable"}`)
	calls := f.fakes.take()
	eq(t, names(calls), []string{
		"iptables-restore --noflush", "iptables -w -C OUTPUT -j BUGNET",
		"iptables -w -C FORWARD -j BUGNET", "ip6tables-restore --noflush",
		"iptables-restore --noflush", "iptables -w -C OUTPUT -j BUGNET",
		"iptables -w -C FORWARD -j BUGNET",
	})
	eq(t, calls[0].stdin, newV4)
	eq(t, calls[4].stdin, oldV4)
	after, err := os.ReadFile(path)
	must(t, err)
	eq(t, string(after), string(kept))

	// fresh answers as iptables with no jump to BUGNET yet, each one present once inserted
	fresh := func() func(c call) (string, error) {
		jumps := map[string]bool{}
		return func(c call) (string, error) {
			if c.name == "ip6tables-restore" {
				return "ip6tables-restore: line 3 failed", errors.New("exit status 1")
			}
			if len(c.args) < 3 {
				return "", nil
			}
			// An insert names its position after the chain, which a check leaves out
			at := 3
			if c.args[1] == "-I" {
				at = 4
			}
			key := strings.Join(slices.Concat([]string{c.name, c.args[2]}, c.args[at:]), " ")
			if c.args[1] == "-I" {
				jumps[key] = true
			} else if !jumps[key] {
				return "", errors.New("exit status 1")
			}
			return "", nil
		}
	}

	// With no iptables ruleset kept, the IPv4 chain is left empty behind the jumps the load made
	for _, earlier := range []string{"", "# bugnet-run harden nft\ntable inet bugnet\n"} {
		for _, c := range []struct{ routes, by string }{{"", ""}, {routeTable, " -o eth0"}} {
			g := newFixture(t, procFile("net/if_inet6", "x"), procFile("net/route", c.routes))
			g.fakes = newFakeTools("iptables")
			g.fakes.answer = fresh()
			g.h.tools = g.fakes.tools()
			if earlier != "" {
				writeFile(t, g.h.root.Path(RulesFile), earlier)
			}
			eq(t, g.run(t), `{"error":"firewall_unavailable"}`)
			calls := g.fakes.take()
			check := "iptables -w -C FORWARD" + c.by + " -j BUGNET"
			eq(t, names(calls), []string{
				"iptables-restore --noflush", "iptables -w -C OUTPUT -j BUGNET",
				"iptables -w -I OUTPUT 1 -j BUGNET", check,
				"iptables -w -I FORWARD 1" + c.by + " -j BUGNET", "ip6tables-restore --noflush",
				"iptables-restore --noflush", "iptables -w -C OUTPUT -j BUGNET", check,
			})
			eq(t, calls[6].stdin, "*filter\n:BUGNET - [0:0]\nCOMMIT\n")
			got, err := os.ReadFile(g.h.root.Path(RulesFile))
			if earlier == "" {
				eq(t, errors.Is(err, os.ErrNotExist), true)
			} else {
				must(t, err)
				eq(t, string(got), earlier)
			}
		}
	}
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

func TestInstallNftablesRunsAptGet(t *testing.T) {
	t.Parallel()
	apt := fakeApt(t)
	must(t, installNftables(context.Background(), apt.path, installTimeout))
	opts := "-o DPkg::Lock::Timeout=60 -o Dpkg::Options::=--force-confdef " +
		"-o Dpkg::Options::=--force-confold "
	env := "DEBIAN_FRONTEND=noninteractive "
	eq(t, apt.calls(t), env+opts+"update\n"+
		env+opts+"install -y --no-install-recommends nftables\n")

	apt.exit(t, 100)
	err := installNftables(context.Background(), apt.path, installTimeout)
	eq(t, err != nil, true)
	eq(t, strings.Contains(err.Error(), "apt-get update: exit status 100: E: The repository"),
		true)
	eq(t, strings.Count(apt.calls(t), "\n"), 1)
}

func TestInstallTimeoutCoversBothCommands(t *testing.T) {
	t.Parallel()
	apt := fakeApt(t)
	// Each command alone fits the timeout
	for _, sleeps := range [][2]string{{"1.8", "0"}, {"0", "1.8"}} {
		apt.sleep(t, sleeps[0], sleeps[1])
		must(t, installNftables(context.Background(), apt.path, 3*time.Second))
	}
	apt.sleep(t, "1.8", "1.8")
	err := installNftables(context.Background(), apt.path, 3*time.Second)
	eq(t, err != nil && strings.Contains(err.Error(), "apt-get install"), true)
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
	// A clock stepped back makes the last check look like the future, which never waits
	eq(t, Due(f.h.root, time.Now().Add(-time.Hour)), true)

	f.fakes.answer = listing(bothChains)
	later := time.Now().Add(2 * time.Minute)
	reloaded, err := f.h.recheck(t.Context(), later)
	must(t, err)
	eq(t, reloaded, false)
	eq(t, names(f.fakes.take()), []string{"nft list chains inet"})
	eq(t, Due(f.h.root, later.Add(59*time.Second)), false)
	eq(t, Due(f.h.root, later.Add(time.Minute)), true)

	f.fakes.answer = listing("table inet bugnetx {\n\tchain output {\n\t}\n" +
		"\tchain forward {\n\t}\n}\n")
	reloaded, err = f.h.recheck(t.Context(), later.Add(time.Minute))
	must(t, err)
	eq(t, reloaded, true)
	calls := f.fakes.take()
	eq(t, names(calls), []string{"nft list chains inet", "nft -f FILE"})
	b, err := os.ReadFile(f.h.root.Path(RulesFile))
	must(t, err)
	eq(t, calls[1].stdin, string(b))
}

// bothChains is how nft lists the chains of the table harden loads
const bothChains = "table inet bugnet {\n" +
	"\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n\t}\n" +
	"\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t}\n}\n"

// listing makes nft list chains as text and succeed at everything else
func listing(text string) func(call) (string, error) {
	return func(c call) (string, error) {
		if c.args[0] == "list" {
			return text, nil
		}
		return "", nil
	}
}

func TestRecheckNeedsEveryChainOfTheKeptTable(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	eq(t, f.run(t), `{"firewall":"nft"}`)
	f.fakes.take()
	outputOnly := "table inet bugnet {\n\tchain output {\n\t}\n}\n"
	for i, c := range []struct {
		listed string
		reload bool
	}{
		{bothChains, false},
		{outputOnly, true},
		{outputOnly + "table inet other {\n\tchain forward {\n\t}\n}\n", true},
		{"table inet other {\n\tchain output {\n\t}\n\tchain forward {\n\t}\n}\n", true},
	} {
		f.fakes.answer = listing(c.listed)
		reloaded, err := f.h.recheck(t.Context(), time.Now())
		must(t, err)
		if reloaded != c.reload {
			t.Fatalf("listing %d reloaded %v, want %v", i, reloaded, c.reload)
		}
		f.fakes.take()
	}

	// A ruleset kept by a runner without the forward chain is whole with its output chain
	writeFile(t, f.h.root.Path(RulesFile), nftHeader+"table inet bugnet\n"+
		"delete table inet bugnet\ntable inet bugnet {\n\tchain output {\n"+
		"\t\ttype filter hook output priority 0; policy accept;\n\t}\n}\n")
	f.fakes.answer = listing(outputOnly)
	reloaded, err := f.h.recheck(t.Context(), time.Now())
	must(t, err)
	eq(t, reloaded, false)
	eq(t, names(f.fakes.take()), []string{"nft list chains inet"})
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
		"iptables -w -C OUTPUT -j BUGNET", "iptables -w -C FORWARD -j BUGNET",
		"ip6tables -w -C OUTPUT -j BUGNET", "ip6tables -w -C FORWARD -j BUGNET",
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
	eq(t, names(f.fakes.take())[3:], []string{
		"iptables-restore --noflush", "iptables -w -C OUTPUT -j BUGNET",
		"iptables -w -C FORWARD -j BUGNET",
		"ip6tables-restore --noflush", "ip6tables -w -C OUTPUT -j BUGNET",
		"ip6tables -w -I OUTPUT 1 -j BUGNET", "ip6tables -w -C FORWARD -j BUGNET",
		"ip6tables -w -I FORWARD 1 -j BUGNET",
	})

	// A FORWARD jump gone alone counts as the table gone
	f.fakes.answer = func(c call) (string, error) {
		if c.name == "iptables" && c.args[1] == "-C" && c.args[2] == "FORWARD" {
			return "", errors.New("exit status 1")
		}
		return "", nil
	}
	reloaded, err = f.h.recheck(t.Context(), time.Now().Add(3*time.Hour))
	must(t, err)
	eq(t, reloaded, true)
	eq(t, names(f.fakes.take()), []string{
		"iptables -w -C OUTPUT -j BUGNET", "iptables -w -C FORWARD -j BUGNET",
		"iptables-restore --noflush", "iptables -w -C OUTPUT -j BUGNET",
		"iptables -w -C FORWARD -j BUGNET", "iptables -w -I FORWARD 1 -j BUGNET",
		"ip6tables-restore --noflush", "ip6tables -w -C OUTPUT -j BUGNET",
		"ip6tables -w -C FORWARD -j BUGNET",
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
