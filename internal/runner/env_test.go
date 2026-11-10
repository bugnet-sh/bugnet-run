package runner_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type files map[string]string

// prepared runs env as a job under a root holding files and returns the job's environment
func prepared(t *testing.T, fs files, args ...string) map[string]string {
	t.Helper()
	return inheriting(t, nil, fs, args...)
}

// inheriting is prepared with inherited added to the environment the runner itself starts with
func inheriting(t *testing.T, inherited []string, fs files, args ...string) map[string]string {
	t.Helper()
	root := t.TempDir()
	for path, content := range fs {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	args = append(append([]string{"--root", root}, args...), "--", "env")
	res := startJob(t, t.TempDir(), "env", inherited, args...).collect(t, 0, 0)
	if x := res.mustExit(t); x.Code != 0 {
		t.Fatalf("env exited %d, stderr %q", x.Code, res.stderr)
	}
	env := map[string]string{}
	for line := range strings.Lines(string(res.stdout)) {
		if k, v, ok := strings.Cut(strings.TrimSuffix(line, "\n"), "="); ok {
			env[k] = v
		}
	}
	return env
}

func has(env map[string]string, name string) bool {
	_, ok := env[name]
	return ok
}

func eq[T comparable](t *testing.T, got, want T) {
	t.Helper()
	if got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestPrepareLoadsEnvFiles(t *testing.T) {
	t.Parallel()
	env := prepared(t, files{"/etc/bugnet/env": "A=1\nB=$HOME\n9X=no\n",
		"/etc/bugnet/secrets.env": "A=2\nHF_TOKEN=bnsec_x\n"}, "--env", "HF_TOKEN=mine")
	eq(t, env["A"], "2")
	eq(t, env["B"], "$HOME")
	eq(t, env["HF_TOKEN"], "mine")
	eq(t, has(env, "9X"), false)
}

func TestPrepareLoadsImageEnvFirst(t *testing.T) {
	t.Parallel()
	env := prepared(t, files{"/etc/bugnet/image.env": "LANG=C.UTF-8\nA=1\nI=img\n",
		"/etc/bugnet/env": "A=2\n"})
	eq(t, env["LANG"], "C.UTF-8")
	eq(t, env["A"], "2")
	eq(t, env["I"], "img")
}

func TestPrepareReadsEnvFilesAtEveryStart(t *testing.T) {
	t.Parallel()
	env := prepared(t, files{"/etc/bugnet/secrets.env": "HF_TOKEN=bnsec_x\n"})
	eq(t, env["HF_TOKEN"], "bnsec_x")
	env = prepared(t, files{})
	eq(t, has(env, "HF_TOKEN") && env["HF_TOKEN"] == "bnsec_x", false)
}

func TestPrepareSetsUTF8Locale(t *testing.T) {
	t.Parallel()
	env := prepared(t, files{})
	eq(t, env["LANG"], "C.UTF-8")
	eq(t, env["LC_ALL"], "C.UTF-8")

	env = prepared(t, files{}, "--env", "LANG=de_DE.UTF-8")
	eq(t, env["LANG"], "de_DE.UTF-8")
	eq(t, has(env, "LC_ALL"), false)

	env = prepared(t, files{}, "--env", "LC_CTYPE=tr_TR.UTF-8")
	eq(t, env["LANG"], "C.UTF-8")
	eq(t, env["LC_CTYPE"], "tr_TR.UTF-8")
	eq(t, has(env, "LC_ALL"), false)

	env = prepared(t, files{}, "--env", "LC_ALL=POSIX")
	eq(t, env["LANG"], "C.UTF-8")
	eq(t, env["LC_ALL"], "POSIX")

	// An LC_ALL the runner inherited would mask the locale the request names
	inherited := []string{"LC_ALL=en_US.UTF-8"}
	env = inheriting(t, inherited, files{}, "--env", "LANG=de_DE.UTF-8")
	eq(t, env["LANG"], "de_DE.UTF-8")
	eq(t, has(env, "LC_ALL"), false)

	env = inheriting(t, inherited, files{})
	eq(t, env["LANG"], "C.UTF-8")
	eq(t, env["LC_ALL"], "C.UTF-8")
}
