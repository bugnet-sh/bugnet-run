package xfer

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
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

func writeFile(t *testing.T, path, content string, perm fs.FileMode) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Dir(path), 0o755))
	must(t, os.WriteFile(path, []byte(content), perm))
	must(t, os.Chmod(path, perm))
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	must(t, err)
	return string(b)
}

type subcommand func(args []string, stdout, stderr io.Writer) int

// call runs a subcommand and returns the one line it printed and its status
func call(t *testing.T, cmd subcommand, args ...string) (string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := cmd(args, &out, &errOut)
	if strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("printed %q, want one line, stderr %q", out.String(), errOut.String())
	}
	return strings.TrimSpace(out.String()), code
}

func info(t *testing.T, cmd subcommand, args ...string) Info {
	t.Helper()
	line, code := call(t, cmd, args...)
	if code != 0 {
		t.Fatalf("printed %s and exited %d", line, code)
	}
	var got Info
	dec := json.NewDecoder(strings.NewReader(line))
	dec.DisallowUnknownFields()
	must(t, dec.Decode(&got))
	return got
}

func me(t *testing.T) *user.User {
	t.Helper()
	u, err := user.Current()
	must(t, err)
	return u
}

func owner(t *testing.T, path string) (int, int) {
	t.Helper()
	info, err := os.Lstat(path)
	must(t, err)
	st := info.Sys().(*syscall.Stat_t)
	return int(st.Uid), int(st.Gid)
}

var hooks sync.Mutex

// withAfterOpen sets the hook that runs once a source is open, for one test at a time
func withAfterOpen(t *testing.T, fn func(*os.File)) {
	t.Helper()
	hooks.Lock()
	afterOpen = fn
	t.Cleanup(func() {
		afterOpen = func(*os.File) {}
		hooks.Unlock()
	})
}

func TestStatReportsKindWithoutFollowing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, "data.csv")
	writeFile(t, file, "a,b\n1,2\n", 0o640)
	when := time.Date(2026, 11, 6, 10, 0, 0, 123456789, time.UTC)
	must(t, os.Chtimes(file, when, when))
	eq(t, info(t, Stat, "--path", file), Info{
		Path: file, Size: 8, Mode: 0o640, ModifiedUnixNano: when.UnixNano(), Regular: true,
	})
	line, _ := call(t, Stat, "--path", file)
	eq(t, strings.HasPrefix(line, `{"path":`+strconv.Quote(file)+`,"size":8,"mode":416,`+
		`"modified_unix_nano":`), true)

	got := info(t, Stat, "--path", dir+"/")
	eq(t, got.Path, dir)
	eq(t, got.IsDir, true)
	eq(t, got.Regular, false)

	fifo := filepath.Join(dir, "pipe")
	must(t, syscall.Mkfifo(fifo, 0o600))
	got = info(t, Stat, "--path", fifo)
	eq(t, got.Regular, false)
	eq(t, got.IsDir, false)

	sub := filepath.Join(dir, "sub")
	must(t, os.Mkdir(sub, 0o755))
	for target, link := range map[string]string{file: "to-file", sub: "to-dir"} {
		path := filepath.Join(dir, link)
		must(t, os.Symlink(target, path))
		for _, p := range []string{path, path + "/"} {
			got = info(t, Stat, "--path", p)
			eq(t, got.Path, path)
			eq(t, got.Regular, false)
			eq(t, got.IsDir, false)
			eq(t, got.Size, int64(len(target)))
		}
	}

	for _, p := range []string{filepath.Join(dir, "missing"), filepath.Join(file, "inside")} {
		line, code := call(t, Stat, "--path", p)
		eq(t, line, `{"error":"not_found"}`)
		eq(t, code, 1)
	}
	for _, args := range [][]string{{}, {"--path", ""}, {"--path", "rel/x"}, {"--path", file, "x"},
		{"--nope"}} {
		line, code := call(t, Stat, args...)
		eq(t, line, `{"error":"bad_args"}`)
		eq(t, code, 2)
	}
}

func TestStageOutFreezesSize(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "opt", "big.bin")
	body := strings.Repeat("0123456789", 100)
	writeFile(t, src, body, 0o600)
	when := time.Date(2026, 11, 6, 9, 30, 0, 0, time.UTC)
	must(t, os.Chtimes(src, when, when))
	withAfterOpen(t, func(*os.File) {
		f, err := os.OpenFile(src, os.O_WRONLY|os.O_APPEND, 0)
		must(t, err)
		_, err = f.WriteString(strings.Repeat("x", 500))
		must(t, err)
		must(t, f.Close())
	})
	home := filepath.Join(dir, "home")
	must(t, os.Mkdir(home, 0o755))
	staged := filepath.Join(home, ".bugnet", "xfer", "t1", "big.bin")
	u := me(t)
	got := info(t, StageOut, "--from", src, "--to", staged, "--owner", u.Username)
	eq(t, got, Info{
		Path: staged, Size: 1000, Mode: 0o600, ModifiedUnixNano: when.UnixNano(), Regular: true,
	})
	eq(t, readFile(t, staged), body)
	eq(t, len(readFile(t, src)), 1500)
	uid, _ := owner(t, staged)
	eq(t, strconv.Itoa(uid), u.Uid)
	for _, d := range []string{"", "/.bugnet", "/.bugnet/xfer", "/.bugnet/xfer/t1"} {
		info, err := os.Stat(home + d)
		must(t, err)
		if d == "" {
			eq(t, info.Mode().Perm(), fs.FileMode(0o755))
			continue
		}
		eq(t, info.Mode().Perm(), fs.FileMode(0o700))
		uid, _ := owner(t, home+d)
		eq(t, strconv.Itoa(uid), u.Uid)
	}

	afterOpen = func(*os.File) {}
	got = info(t, StageOut, "--from", src, "--to", staged, "--owner", u.Username)
	eq(t, got.Size, int64(1500))
	entries, err := os.ReadDir(filepath.Dir(staged))
	must(t, err)
	eq(t, len(entries), 1)

	withShrink := filepath.Join(dir, "shrinks")
	writeFile(t, withShrink, body, 0o644)
	afterOpen = func(*os.File) { must(t, os.Truncate(withShrink, 10)) }
	line, code := call(t, StageOut, "--from", withShrink, "--to", staged+".2", "--owner",
		u.Username)
	eq(t, line, `{"error":"file_changed"}`)
	eq(t, code, 1)
	eq(t, len(mustReadDir(t, filepath.Dir(staged))), 1)
}

func mustReadDir(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(dir)
	must(t, err)
	return entries
}

func TestStageOutRefusesWhatIsNotARegularFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	u := me(t)
	file := filepath.Join(dir, "f")
	writeFile(t, file, "x", 0o644)
	fifo := filepath.Join(dir, "pipe")
	must(t, syscall.Mkfifo(fifo, 0o600))
	link := filepath.Join(dir, "link")
	must(t, os.Symlink(file, link))
	to := filepath.Join(dir, "staged", "out")
	for from, want := range map[string]string{
		dir: "is_directory", fifo: "not_regular", link: "not_regular",
		filepath.Join(dir, "missing"): "not_found", filepath.Join(file, "x"): "not_found",
	} {
		var out bytes.Buffer
		code := make(chan int, 1)
		go func() {
			code <- StageOut([]string{"--from", from, "--to", to, "--owner", u.Username}, &out,
				io.Discard)
		}()
		select {
		case c := <-code:
			eq(t, out.String(), `{"error":"`+want+`"}`+"\n")
			eq(t, c, 1)
		case <-time.After(5 * time.Second):
			t.Fatalf("stage-out of %s hangs", from)
		}
	}
	_, err := os.Stat(filepath.Dir(to))
	eq(t, os.IsNotExist(err), true)

	for _, args := range [][]string{
		{"--from", file, "--to", to},
		{"--from", file, "--to", to, "--owner", "no-such-user-bugnet"},
		{"--from", "f", "--to", to, "--owner", u.Username},
		{"--from", file, "--to", "staged/out", "--owner", u.Username},
		{"--from", file, "--to", "/", "--owner", u.Username},
		{"--from", file, "--to", to, "--owner", u.Username, "extra"},
	} {
		line, code := call(t, StageOut, args...)
		eq(t, line, `{"error":"bad_args"}`)
		eq(t, code, 2)
	}
}

func TestPlaceCrossDevice(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, "home", ".bugnet", "xfer", "t2", "app.conf")
	writeFile(t, staged, "listen 8080\n", 0o600)
	target := filepath.Join(dir, "opt", "app", "app.conf")
	hooks.Lock()
	var tries []string
	rename = func(from, to string) error {
		tries = append(tries, filepath.Base(from))
		if filepath.Dir(from) != filepath.Dir(to) {
			return &os.LinkError{Op: "rename", Old: from, New: to, Err: syscall.EXDEV}
		}
		return os.Rename(from, to)
	}
	t.Cleanup(func() {
		rename = os.Rename
		hooks.Unlock()
	})
	got := info(t, Place, "--from", staged, "--to", target, "--mode", "0644")
	eq(t, got.Path, target)
	eq(t, got.Size, int64(12))
	eq(t, got.Mode, uint32(0o644))
	eq(t, readFile(t, target), "listen 8080\n")
	_, err := os.Stat(staged)
	eq(t, os.IsNotExist(err), true)
	eq(t, len(tries), 2)
	eq(t, tries[0], "app.conf")
	eq(t, strings.HasPrefix(tries[1], ".app.conf.bugnet-"), true)
	eq(t, len(mustReadDir(t, filepath.Dir(target))), 1)
}

func TestPlaceNeverFollowsASwappedSource(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, "staged", "f")
	writeFile(t, staged, "upload", 0o600)
	victim := filepath.Join(dir, "etc", "shadow")
	writeFile(t, victim, "secret", 0o600)
	target := filepath.Join(dir, "opt", "f")
	withAfterOpen(t, func(*os.File) {
		must(t, os.Rename(staged, staged+".opened"))
		must(t, os.Symlink(victim, staged))
	})
	line, code := call(t, Place, "--from", staged, "--to", target, "--mode", "0644")
	eq(t, line, `{"error":"place_failed"}`)
	eq(t, code, 1)
	fi, err := os.Stat(victim)
	must(t, err)
	eq(t, fi.Mode().Perm(), fs.FileMode(0o600))
	eq(t, readFile(t, victim), "secret")
	fi, err = os.Stat(staged + ".opened")
	must(t, err)
	eq(t, fi.Mode().Perm(), fs.FileMode(0o644))
}

func TestPlaceParentsGetTheNewFilesOwnerAndMode(t *testing.T) {
	// Not parallel, since the umask belongs to the whole process
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })
	dir := t.TempDir()
	staged := filepath.Join(dir, "home", ".bugnet", "xfer", "t3", "f")
	writeFile(t, staged, "one", 0o600)
	uid, gid := owner(t, staged)
	must(t, os.Mkdir(filepath.Join(dir, "out"), 0o700))
	target := filepath.Join(dir, "out", "new", "deeper", "f")
	info(t, Place, "--from", staged, "--to", target)
	for _, d := range []string{"out/new", "out/new/deeper"} {
		fi, err := os.Lstat(filepath.Join(dir, d))
		must(t, err)
		eq(t, fi.Mode().Perm(), fs.FileMode(0o755))
		u, g := owner(t, filepath.Join(dir, d))
		eq(t, [2]int{u, g}, [2]int{uid, gid})
	}
	fi, err := os.Stat(filepath.Join(dir, "out"))
	must(t, err)
	eq(t, fi.Mode().Perm(), fs.FileMode(0o700))
}

func TestPlaceCreatesParentsAndReplaces(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	staged := filepath.Join(dir, "staged", "f")
	target := filepath.Join(dir, "new", "deep", "f")
	writeFile(t, staged, "one", 0o600)
	got := info(t, Place, "--from", staged, "--to", target, "--mode", "0640")
	eq(t, got.Mode, uint32(0o640))
	eq(t, got.Regular, true)
	for _, d := range []string{"new", "new/deep"} {
		info, err := os.Stat(filepath.Join(dir, d))
		must(t, err)
		eq(t, info.Mode().Perm(), fs.FileMode(0o755))
	}

	writeFile(t, staged, "two!", 0o600)
	must(t, os.Chmod(target, 0o600))
	uid, gid := owner(t, target)
	got = info(t, Place, "--from", staged, "--to", target)
	eq(t, got.Size, int64(4))
	eq(t, got.Mode, uint32(0o644))
	eq(t, readFile(t, target), "two!")
	u2, g2 := owner(t, target)
	eq(t, [2]int{u2, g2}, [2]int{uid, gid})

	link := filepath.Join(dir, "link")
	must(t, os.Symlink(target, link))
	sub := filepath.Join(dir, "sub")
	must(t, os.Mkdir(sub, 0o755))
	writeFile(t, staged, "three", 0o600)
	for _, tc := range []struct {
		from, to, want string
	}{
		{staged, sub, "is_directory"},
		{filepath.Join(dir, "missing"), target, "not_found"},
		{link, filepath.Join(dir, "x"), "not_regular"},
		{sub, filepath.Join(dir, "x"), "is_directory"},
	} {
		line, code := call(t, Place, "--from", tc.from, "--to", tc.to, "--mode", "0644")
		eq(t, line, `{"error":"`+tc.want+`"}`)
		eq(t, code, 1)
	}
	eq(t, readFile(t, staged), "three")

	fifo := filepath.Join(dir, "pipe")
	must(t, syscall.Mkfifo(fifo, 0o600))
	code := make(chan string, 1)
	go func() {
		var out bytes.Buffer
		Place([]string{"--from", fifo, "--to", filepath.Join(dir, "x")}, &out, io.Discard)
		code <- out.String()
	}()
	select {
	case line := <-code:
		eq(t, line, `{"error":"not_regular"}`+"\n")
	case <-time.After(5 * time.Second):
		t.Fatal("place of a FIFO hangs")
	}

	for _, m := range []string{"644x", "999", "0o644", "1777", "04755", "-1", ""} {
		line, code := call(t, Place, "--from", staged, "--to", target, "--mode", m)
		eq(t, line, `{"error":"bad_args"}`)
		eq(t, code, 2)
	}
	for _, args := range [][]string{
		{"--from", "rel", "--to", target}, {"--from", staged, "--to", "rel"},
		{"--from", staged, "--to", "/"}, {"--to", target}, {"--from", staged, "--to", target, "x"},
	} {
		line, code := call(t, Place, args...)
		eq(t, line, `{"error":"bad_args"}`)
		eq(t, code, 2)
	}
}
