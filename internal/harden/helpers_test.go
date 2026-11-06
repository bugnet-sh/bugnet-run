package harden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/oynozan/bugnet-run/internal/sandbox"
)

func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Dir(path), 0o755))
	must(t, os.WriteFile(path, []byte(content), 0o644))
}

// option changes a fixture before the ruleset is built
type option func(t *testing.T, f *fixture)

type fixture struct {
	spec  Spec
	h     hardener
	fakes *fakeTools
}

var defaultDeny = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7",
	"169.254.0.0/16", "fe80::/10", "fd00:ec2::254/128",
}

// newFixture holds the spec of CP 6.9's defaults and a sandbox whose tools are fakes
func newFixture(t *testing.T, opts ...option) *fixture {
	t.Helper()
	root, err := sandbox.NewRoot(t.TempDir())
	must(t, err)
	fakes := newFakeTools("nft")
	f := &fixture{
		spec: Spec{
			V: 1, MailPorts: []int{25, 465, 587}, DenyRanges: defaultDeny,
			Pools: []string{"198.51.100.0/24"},
		},
		h:     hardener{root: root, procDir: t.TempDir(), tools: fakes.tools()},
		fakes: fakes,
	}
	for _, o := range opts {
		o(t, f)
	}
	return f
}

func spec(opts ...option) []option { return opts }

func pools(n int) option {
	return func(_ *testing.T, f *fixture) {
		f.spec.Pools = make([]string, n)
		for i := range n {
			f.spec.Pools[i] = fmt.Sprintf("203.%d.%d.0/24", i/256, i%256)
		}
	}
}

func resolvConf(text string) option {
	return func(t *testing.T, f *fixture) { writeFile(t, f.h.root.Path("/etc/resolv.conf"), text) }
}

func procFile(name, text string) option {
	return func(t *testing.T, f *fixture) { writeFile(t, filepath.Join(f.h.procDir, name), text) }
}

func withSpec(change func(*Spec)) option {
	return func(_ *testing.T, f *fixture) { change(&f.spec) }
}

func ruleset(t *testing.T, opts []option, more ...option) rules {
	t.Helper()
	f := newFixture(t, append(opts, more...)...)
	must(t, f.spec.check())
	return f.h.rules(f.spec)
}

func buildNft(t *testing.T, opts []option, more ...option) string {
	t.Helper()
	return ruleset(t, opts, more...).nft()
}

func buildIptables(t *testing.T, opts []option, more ...option) (string, string) {
	t.Helper()
	return ruleset(t, opts, more...).iptables()
}

// index fails the test alone when sub is missing, so the other parallel tests run on
func index(t *testing.T, s, sub string) int {
	t.Helper()
	i := strings.Index(s, sub)
	if i < 0 {
		t.Fatalf("%q not in the ruleset", sub)
	}
	return i
}

func firstIndex(t *testing.T, s, sub string) int {
	t.Helper()
	return index(t, s, sub)
}

func lastIndex(t *testing.T, s, sub string) int {
	t.Helper()
	index(t, s, sub)
	return strings.LastIndex(s, sub)
}

// run runs harden on the fixture's spec and returns the line it printed
func (f *fixture) run(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(f.spec)
	must(t, err)
	return f.runRaw(t, b)
}

func (f *fixture) runRaw(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "harden-spec.json")
	must(t, os.WriteFile(path, raw, 0o600))
	var out, errOut bytes.Buffer
	code := f.h.main(context.Background(), []string{"--spec", path}, &out, &errOut)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("harden left its spec file behind")
	}
	line := strings.TrimSpace(out.String())
	if strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("harden printed %q, want one line", out.String())
	}
	if (code == 0) != strings.HasPrefix(line, `{"firewall"`) {
		t.Fatalf("harden exited %d after printing %s, stderr %q", code, line, errOut.String())
	}
	return line
}

func run(t *testing.T, opts []option) string {
	t.Helper()
	return newFixture(t, opts...).run(t)
}

/* Fake tools */

type call struct {
	name  string
	args  []string
	stdin string
}

func (c call) String() string { return strings.Join(append([]string{c.name}, c.args...), " ") }

// fakeTools stands in for nft, iptables and apt-get, never touching the host's firewall
type fakeTools struct {
	mu      sync.Mutex
	present map[string]bool
	calls   []call
	// answer gives a program's output and error, nil meaning success with no output
	answer func(c call) (string, error)
	// installs names the programs an install makes present
	installs []string
	install  error
}

func newFakeTools(present ...string) *fakeTools {
	f := &fakeTools{present: map[string]bool{}}
	for _, p := range present {
		f.add(p)
	}
	return f
}

// add makes name present, with the restore tools that ship beside iptables
func (f *fakeTools) add(name string) {
	f.present[name] = true
	if name == "iptables" {
		for _, p := range []string{"iptables-restore", "ip6tables", "ip6tables-restore"} {
			f.present[p] = true
		}
	}
}

func (f *fakeTools) tools() tools {
	return tools{
		look: func(name string) (string, bool) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return "/fake/" + name, f.present[name]
		},
		run: func(_ context.Context, stdin []byte, path string, args ...string) ([]byte, error) {
			c := call{name: strings.TrimPrefix(path, "/fake/"), args: args, stdin: string(stdin)}
			if len(args) == 2 && args[0] == "-f" {
				b, err := os.ReadFile(args[1])
				if err != nil {
					return nil, err
				}
				c.stdin = string(b)
			}
			f.mu.Lock()
			f.calls = append(f.calls, c)
			answer := f.answer
			f.mu.Unlock()
			if answer == nil {
				return nil, nil
			}
			out, err := answer(c)
			return []byte(out), err
		},
		install: func(context.Context) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.calls = append(f.calls, call{name: "apt-get", args: []string{"install"}})
			if f.install != nil {
				return f.install
			}
			for _, p := range f.installs {
				f.add(p)
			}
			return nil
		},
	}
}

func (f *fakeTools) take() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	calls := f.calls
	f.calls = nil
	return calls
}

func names(calls []call) []string {
	out := make([]string, len(calls))
	for i, c := range calls {
		args := c.args
		if len(args) == 2 && args[0] == "-f" {
			args = []string{"-f", "FILE"}
		}
		out[i] = call{name: c.name, args: args}.String()
	}
	return out
}

// aptStandIn is an apt-get stand-in that logs DEBIAN_FRONTEND and its arguments, then sleeps
type aptStandIn struct {
	path string
	dir  string
}

// fakeApt writes the stand-in and runs it once, so the first run's exec check costs no test time
func fakeApt(t *testing.T) aptStandIn {
	t.Helper()
	a := aptStandIn{dir: t.TempDir()}
	a.path = filepath.Join(a.dir, "apt-get")
	// exec makes sleep the process the timeout kills, so no orphan outlives the test
	writeFile(t, a.path, "#!/bin/sh\n"+
		"d='"+a.dir+"'\n"+
		"printf '%s %s\\n' \"DEBIAN_FRONTEND=$DEBIAN_FRONTEND\" \"$*\" >> \"$d/log\"\n"+
		"case \" $* \" in *' update '*) v=update ;; *) v=install ;; esac\n"+
		"if [ -s \"$d/exit\" ]; then\n"+
		"\techo 'E: The repository is not signed.'\n"+
		"\tread -r code < \"$d/exit\"\n"+
		"\texit \"$code\"\n"+
		"fi\n"+
		"read -r s < \"$d/$v\"\n"+
		"exec sleep \"$s\"\n")
	must(t, os.Chmod(a.path, 0o755))
	a.sleep(t, "0", "0")
	must(t, exec.Command(a.path, "update").Run())
	must(t, os.Remove(filepath.Join(a.dir, "log")))
	return a
}

// sleep sets how long update and install each take
func (a aptStandIn) sleep(t *testing.T, update, install string) {
	t.Helper()
	writeFile(t, filepath.Join(a.dir, "update"), update+"\n")
	writeFile(t, filepath.Join(a.dir, "install"), install+"\n")
}

// exit makes every command print an error and exit with code
func (a aptStandIn) exit(t *testing.T, code int) {
	t.Helper()
	writeFile(t, filepath.Join(a.dir, "exit"), strconv.Itoa(code)+"\n")
}

// calls returns the lines the stand-in logged and forgets them
func (a aptStandIn) calls(t *testing.T) string {
	t.Helper()
	path := filepath.Join(a.dir, "log")
	b, err := os.ReadFile(path)
	must(t, err)
	must(t, os.Remove(path))
	return string(b)
}
