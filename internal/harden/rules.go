package harden

import (
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Headers of the kept ruleset, which name the tool that loads it
const (
	nftHeader      = "# bugnet-run harden nft\n"
	iptablesHeader = "# bugnet-run harden iptables\n"
	ipv6Marker     = "# ipv6\n"
)

// maxHostAddrs bounds the resolvers and the gateways read from the sandbox
const maxHostAddrs = 16

// resolvConfs are read for resolvers, the second holding systemd-resolved's upstream servers
var resolvConfs = []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"}

// rules is a checked spec with the sandbox's own addresses that stay reachable
type rules struct {
	resolvers []netip.Addr
	gateways  []netip.Addr
	allow     []netip.Prefix
	mailPorts []int
	deny      []netip.Prefix
	pools4    []netip.Prefix
	pools6    []netip.Prefix
}

// rules builds the ruleset of a spec that passed check
func (h hardener) rules(s Spec) rules {
	r := rules{
		resolvers: h.resolvers(), allow: prefixes(s.Allow),
		deny: prefixes(s.DenyRanges), mailPorts: slices.Compact(slices.Sorted(slices.Values(
			s.MailPorts))),
	}
	if !s.NoGateway {
		r.gateways = h.gateways()
	}
	for _, p := range merge(prefixes(s.Pools)) {
		if p.Addr().Is4() {
			r.pools4 = append(r.pools4, p)
		} else {
			r.pools6 = append(r.pools6, p)
		}
	}
	return r
}

// parsePrefix takes a CIDR or a bare address, which stands for itself alone
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if a.Zone() != "" {
		return netip.Prefix{}, errors.New("an address with a zone")
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// prefixes keeps the first of each repeated entry, in order
func prefixes(entries []string) []netip.Prefix {
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, e := range entries {
		if p, err := parsePrefix(e); err == nil && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// merge drops prefixes inside others, since nft refuses overlapping elements of an interval set
func merge(ps []netip.Prefix) []netip.Prefix {
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
	})
	var out []netip.Prefix
	for _, p := range ps {
		if n := len(out); n > 0 && out[n-1].Contains(p.Addr()) {
			continue
		}
		out = append(out, p)
	}
	return out
}

/* The sandbox's own addresses */

// resolvers skips loopback, which the first rule opens, and drops zones nft cannot read
func (h hardener) resolvers() []netip.Addr {
	var out []netip.Addr
	for _, file := range resolvConfs {
		b, err := os.ReadFile(h.root.Path(file))
		if err != nil {
			continue
		}
		for line := range strings.Lines(string(b)) {
			f := strings.Fields(line)
			if len(f) < 2 || f[0] != "nameserver" {
				continue
			}
			host, _, _ := strings.Cut(f[1], "%")
			a, err := netip.ParseAddr(host)
			if err == nil && !a.IsLoopback() && !a.IsUnspecified() {
				out = appendAddr(out, a.Unmap())
			}
		}
	}
	return out
}

// gateways reads the next hops of the default routes in /proc/net/route and ipv6_route
func (h hardener) gateways() []netip.Addr {
	var out []netip.Addr
	for _, f := range fields(filepath.Join(h.procDir, "net", "route")) {
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		v, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || v == 0 {
			continue
		}
		// The kernel prints the address as a number in host order
		var a [4]byte
		binary.NativeEndian.PutUint32(a[:], uint32(v))
		out = appendAddr(out, netip.AddrFrom4(a))
	}
	for _, f := range fields(filepath.Join(h.procDir, "net", "ipv6_route")) {
		if len(f) < 10 || f[0] != strings.Repeat("0", 32) || f[1] != "00" {
			continue
		}
		b, err := hex.DecodeString(f[4])
		if err != nil || len(b) != 16 {
			continue
		}
		if a := netip.AddrFrom16([16]byte(b)); !a.IsUnspecified() {
			out = appendAddr(out, a)
		}
	}
	return out
}

func fields(path string) [][]string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out [][]string
	for line := range strings.Lines(string(b)) {
		out = append(out, strings.Fields(line))
	}
	return out
}

func appendAddr(out []netip.Addr, a netip.Addr) []netip.Addr {
	if len(out) >= maxHostAddrs || slices.Contains(out, a) {
		return out
	}
	return append(out, a)
}

/* nftables */

// hooks are filtered alike, forward carrying what Docker or a nested namespace sends
var hooks = []string{"output", "forward"}

// nft replaces the whole table in one transaction, so a second load leaves one table
func (r rules) nft() string {
	var b strings.Builder
	b.WriteString(nftHeader)
	b.WriteString("table inet bugnet\ndelete table inet bugnet\ntable inet bugnet {\n")
	writeSet(&b, "pools4", "ipv4_addr", r.pools4)
	writeSet(&b, "pools6", "ipv6_addr", r.pools6)
	rules := r.nftRules()
	for _, hook := range hooks {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority 0; policy accept;\n",
			hook, hook)
		for _, rule := range rules {
			b.WriteString("\t\t" + rule + "\n")
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func writeSet(b *strings.Builder, name, typ string, ps []netip.Prefix) {
	if len(ps) == 0 {
		return
	}
	elems := make([]string, len(ps))
	for i, p := range ps {
		elems[i] = nftAddr(p)
	}
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s\n\t\tflags interval\n\t\telements = { %s }\n\t}\n",
		name, typ, strings.Join(elems, ",\n\t\t\t     "))
}

// nftRules puts every accept before every reject
func (r rules) nftRules() []string {
	rs := []string{`oifname "lo" accept`, "ct state established,related accept"}
	for _, a := range r.resolvers {
		for _, proto := range []string{"udp", "tcp"} {
			rs = append(rs, fmt.Sprintf("%s daddr %s %s dport 53 accept", family(a), a, proto))
		}
	}
	for _, a := range r.gateways {
		rs = append(rs, fmt.Sprintf("%s daddr %s accept", family(a), a))
	}
	// DHCP renewals and neighbour discovery reach servers and routers inside the blocked ranges
	rs = append(rs, "udp sport 68 udp dport 67 accept", "udp sport 546 udp dport 547 accept",
		"icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept")
	for _, p := range r.allow {
		rs = append(rs, fmt.Sprintf("%s daddr %s accept", family(p.Addr()), nftAddr(p)))
	}
	if len(r.mailPorts) > 0 {
		ports := make([]string, len(r.mailPorts))
		for i, p := range r.mailPorts {
			ports[i] = strconv.Itoa(p)
		}
		rs = append(rs, "tcp dport { "+strings.Join(ports, ", ")+" } reject with tcp reset")
	}
	for _, p := range r.deny {
		rs = append(rs, nftReject(fmt.Sprintf("%s daddr %s", family(p.Addr()), nftAddr(p)))...)
	}
	if len(r.pools4) > 0 {
		rs = append(rs, nftReject("ip daddr @pools4")...)
	}
	if len(r.pools6) > 0 {
		rs = append(rs, nftReject("ip6 daddr @pools6")...)
	}
	return rs
}

// nftReject answers TCP with a reset and the rest with admin-prohibited, so no client waits
func nftReject(match string) []string {
	return []string{
		match + " meta l4proto tcp reject with tcp reset",
		match + " reject with icmpx type admin-prohibited",
	}
}

func family(a netip.Addr) string {
	if a.Is4() {
		return "ip"
	}
	return "ip6"
}

func nftAddr(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

/* iptables */

// emptyChain makes iptables-restore --noflush empty BUGNET, so the jumps to it block nothing
const emptyChain = "*filter\n:BUGNET - [0:0]\nCOMMIT\n"

// iptables gives iptables-restore and ip6tables-restore input that refills the BUGNET chain
func (r rules) iptables() (v4, v6 string) {
	return r.restore(true), r.restore(false)
}

func (r rules) restore(four bool) string {
	var b strings.Builder
	b.WriteString("*filter\n:BUGNET - [0:0]\n")
	add := func(rule string) { b.WriteString("-A BUGNET " + rule + "\n") }
	mine := func(a netip.Addr) bool { return a.Is4() == four }
	add("-o lo -j ACCEPT")
	add("-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	for _, a := range r.resolvers {
		if mine(a) {
			for _, proto := range []string{"udp", "tcp"} {
				add(fmt.Sprintf("-d %s -p %s -m %s --dport 53 -j ACCEPT", host(a), proto, proto))
			}
		}
	}
	for _, a := range r.gateways {
		if mine(a) {
			add("-d " + host(a) + " -j ACCEPT")
		}
	}
	if four {
		add("-p udp -m udp --sport 68 --dport 67 -j ACCEPT")
	} else {
		add("-p udp -m udp --sport 546 --dport 547 -j ACCEPT")
		for _, typ := range []string{
			"neighbour-solicitation", "neighbour-advertisement", "router-solicitation",
		} {
			add("-p ipv6-icmp -m icmp6 --icmpv6-type " + typ + " -j ACCEPT")
		}
	}
	for _, p := range r.allow {
		if mine(p.Addr()) {
			add("-d " + p.String() + " -j ACCEPT")
		}
	}
	for _, port := range r.mailPorts {
		add(fmt.Sprintf("-p tcp -m tcp --dport %d -j REJECT --reject-with tcp-reset", port))
	}
	pools, prohibited := r.pools6, "icmp6-adm-prohibited"
	if four {
		pools, prohibited = r.pools4, "icmp-admin-prohibited"
	}
	for _, p := range append(slices.Clone(r.deny), pools...) {
		if mine(p.Addr()) {
			add("-d " + p.String() + " -p tcp -j REJECT --reject-with tcp-reset")
			add("-d " + p.String() + " -j REJECT --reject-with " + prohibited)
		}
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

func host(a netip.Addr) string {
	return netip.PrefixFrom(a, a.BitLen()).String()
}
