package harden

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bugnet-sh/bugnet-run/internal/sandbox"
)

// tools runs the firewall programs, a seam so tests never touch the host's firewall
type tools struct {
	look    func(name string) (string, bool)
	run     func(ctx context.Context, stdin []byte, path string, args ...string) ([]byte, error)
	install func(ctx context.Context) error
}

var systemTools = tools{look: lookTool, run: runTool, install: func(ctx context.Context) error {
	apt, ok := lookTool("apt-get")
	if !ok {
		return errors.New("neither nft, iptables-restore nor apt-get is installed")
	}
	return installNftables(ctx, apt, installTimeout)
}}

// ensureTool installs nftables only where neither nft nor iptables-restore exists
func (h hardener) ensureTool(ctx context.Context) error {
	if _, ok := h.tools.look("nft"); ok {
		return nil
	}
	if _, ok := h.tools.look("iptables-restore"); ok {
		return nil
	}
	return h.tools.install(ctx)
}

// load tries nft, then iptables, and keeps the ruleset that loaded in RulesFile
func (h hardener) load(ctx context.Context, rs rules) (string, error) {
	var errs []error
	if nft, ok := h.tools.look("nft"); ok {
		err := h.keep(rs.nft(), func(path string) error { return h.loadNft(ctx, nft, path) })
		if err == nil {
			return FirewallNft, nil
		}
		errs = append(errs, err)
	}
	if _, ok := h.tools.look("iptables-restore"); ok {
		v4, v6 := rs.iptables()
		err := h.keep(iptablesHeader+v4+ipv6Marker+v6, func(string) error {
			return h.loadIptables(ctx, v4, v6)
		})
		if err == nil {
			return FirewallIptables, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		errs = append(errs, errors.New("neither nft nor iptables-restore is installed"))
	}
	return "", errors.Join(errs...)
}

// keep writes text beside RulesFile and renames it over only once load accepted it
func (h hardener) keep(text string, load func(path string) error) error {
	tmp, err := os.CreateTemp(h.root.Path(sandbox.EtcDir), ".firewall.rules.bugnet-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.WriteString(text)
	if err == nil {
		err = tmp.Chmod(0o644)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = load(name)
	}
	if err == nil {
		err = os.Rename(name, h.root.Path(RulesFile))
	}
	if err != nil {
		_ = os.Remove(name)
	}
	return err
}

func (h hardener) loadNft(ctx context.Context, nft, path string) error {
	_, err := h.tools.run(ctx, nil, nft, "-f", path)
	return err
}

// loadIptables loads both chains or neither, leaving IPv6 out only where the kernel has none
func (h hardener) loadIptables(ctx context.Context, v4, v6 string) error {
	if err := h.restore(ctx, "iptables", v4); err != nil {
		return err
	}
	err := h.restore(ctx, "ip6tables", v6)
	if err == nil || !h.ipv6() {
		return nil
	}
	return errors.Join(err, h.restore(ctx, "iptables", h.keptV4()))
}

// keptV4 is the IPv4 chain the kept ruleset holds, or an empty chain when it holds none
func (h hardener) keptV4() string {
	b, err := os.ReadFile(h.root.Path(RulesFile))
	if err == nil {
		if k, err := parseKept(b); err == nil && k.firewall == FirewallIptables {
			return k.v4
		}
	}
	return emptyChain
}

// restore refills the BUGNET chain and makes OUTPUT jump to it once
func (h hardener) restore(ctx context.Context, tool, text string) error {
	restore, ok := h.tools.look(tool + "-restore")
	if !ok {
		return fmt.Errorf("%s-restore is not installed", tool)
	}
	if _, err := h.tools.run(ctx, []byte(text), restore, "--noflush"); err != nil {
		return err
	}
	if h.jumps(ctx, tool) {
		return nil
	}
	path, ok := h.tools.look(tool)
	if !ok {
		return fmt.Errorf("%s is not installed", tool)
	}
	_, err := h.tools.run(ctx, nil, path, "-w", "-I", "OUTPUT", "1", "-j", "BUGNET")
	return err
}

func (h hardener) jumps(ctx context.Context, tool string) bool {
	path, ok := h.tools.look(tool)
	if !ok {
		return false
	}
	_, err := h.tools.run(ctx, nil, path, "-w", "-C", "OUTPUT", "-j", "BUGNET")
	return err == nil
}

func (h hardener) ipv6() bool {
	_, err := os.Stat(filepath.Join(h.procDir, "net", "if_inet6"))
	return err == nil
}

/* The kept ruleset */

type kept struct {
	firewall string
	v4, v6   string
}

func parseKept(b []byte) (kept, error) {
	text := string(b)
	if strings.HasPrefix(text, nftHeader) {
		return kept{firewall: FirewallNft}, nil
	}
	if rest, ok := strings.CutPrefix(text, iptablesHeader); ok {
		v4, v6, ok := strings.Cut(rest, ipv6Marker)
		if ok {
			return kept{firewall: FirewallIptables, v4: v4, v6: v6}, nil
		}
	}
	return kept{}, errors.New("the kept ruleset names no firewall")
}

// present reports whether the table the kept ruleset makes is still loaded
func (h hardener) present(ctx context.Context, k kept) bool {
	if k.firewall == FirewallIptables {
		return h.jumps(ctx, "iptables") && (!h.ipv6() || h.jumps(ctx, "ip6tables"))
	}
	nft, ok := h.tools.look("nft")
	if !ok {
		return false
	}
	out, err := h.tools.run(ctx, nil, nft, "list", "tables")
	if err != nil {
		return false
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "table inet bugnet" {
			return true
		}
	}
	return false
}

func (h hardener) loadKept(ctx context.Context, k kept, path string) error {
	if k.firewall == FirewallIptables {
		return h.loadIptables(ctx, k.v4, k.v6)
	}
	nft, ok := h.tools.look("nft")
	if !ok {
		return errors.New("nft is not installed")
	}
	return h.loadNft(ctx, nft, path)
}

/* The real tools */

// lookTool falls back to the usual place, since a root shell may run without /usr/sbin on PATH
func lookTool(name string) (string, bool) {
	if p, err := exec.LookPath(name); err == nil {
		return p, true
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin"} {
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() &&
			info.Mode().Perm()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}

func runTool(ctx context.Context, stdin []byte, path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, toolTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", filepath.Base(path), args[0], err, tail(out))
	}
	return out, nil
}

// installNftables runs apt-get as ssh-up does, both steps within one timeout
func installNftables(ctx context.Context, apt string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	opts := []string{
		"-o", "DPkg::Lock::Timeout=" + strconv.Itoa(int(timeout.Seconds())),
		"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold",
	}
	for _, args := range [][]string{
		append(slices.Clone(opts), "update"),
		append(slices.Clone(opts), "install", "-y", "--no-install-recommends", "nftables"),
	} {
		cmd := exec.CommandContext(ctx, apt, args...)
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		cmd.WaitDelay = time.Second
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("apt-get %s: %w: %s", args[len(opts)], err, tail(out))
		}
	}
	return nil
}

func tail(out []byte) []byte {
	out = bytes.TrimSpace(out)
	if len(out) > 1024 {
		out = out[len(out)-1024:]
	}
	return out
}
