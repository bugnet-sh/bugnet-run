package sandbox

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestManagedBlockSurvivesHandEdits(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "hosts")
	writeFile(t, path, "127.0.0.1 localhost\n")

	must(t, SetBlock(path, "127.77.0.1 a.example\n", 0o644))
	eq(t, readFile(t, path), "127.0.0.1 localhost\n# bugnet begin\n127.77.0.1 a.example\n"+
		"# bugnet end\n")

	writeFile(t, path, "10.0.0.1 mine\n127.0.0.1 localhost\n# bugnet begin\n127.77.0.1 a.example\n"+
		"hand inside\n# bugnet end\n10.0.0.2 after\n")
	must(t, SetBlock(path, "127.77.0.1 b.example\n", 0o644))
	eq(t, readFile(t, path), "10.0.0.1 mine\n127.0.0.1 localhost\n# bugnet begin\n"+
		"127.77.0.1 b.example\n# bugnet end\n10.0.0.2 after\n")
	body, err := Block(path)
	must(t, err)
	eq(t, body, "127.77.0.1 b.example\n")

	must(t, SetBlock(path, "", 0o644))
	eq(t, readFile(t, path), "10.0.0.1 mine\n127.0.0.1 localhost\n10.0.0.2 after\n")
	body, err = Block(path)
	must(t, err)
	eq(t, body, "")
}

func TestManagedBlockCreatesAndKeepsMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "new")
	must(t, SetBlock(path, "x", 0o640))
	eq(t, readFile(t, path), "# bugnet begin\nx\n# bugnet end\n")
	info, err := os.Stat(path)
	must(t, err)
	eq(t, info.Mode().Perm(), os.FileMode(0o640))

	must(t, os.Chmod(path, 0o604))
	must(t, SetBlock(path, "y\n", 0o640))
	info, err = os.Stat(path)
	must(t, err)
	eq(t, info.Mode().Perm(), os.FileMode(0o604))
	eq(t, leftovers(t, dir), []string{"new"})

	missing := filepath.Join(dir, "missing")
	body, err := Block(missing)
	must(t, err)
	eq(t, body, "")
	must(t, SetBlock(missing, "", 0o644))
	eq(t, readFile(t, missing), "")
}

func TestManagedBlockStrayMarkers(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "f")
	writeFile(t, path, "a\n# bugnet begin\nold 1\n# bugnet end\nb\n# bugnet begin\nold 2\n"+
		"# bugnet end\n# bugnet end\nc\n# bugnet begin\nd\n")
	must(t, SetBlock(path, "new\n", 0o644))
	eq(t, readFile(t, path), "a\n# bugnet begin\nnew\n# bugnet end\nb\nc\nd\n")
}

func TestManagedBlockInPlaceOnEBUSY(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EBUSY, syscall.EXDEV} {
		t.Run(errno.Error(), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "hosts")
			writeFile(t, path, "127.0.0.1 localhost\n")
			before := inode(t, path)

			rename = func(oldpath, newpath string) error {
				return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: errno}
			}
			t.Cleanup(func() { rename = os.Rename })

			must(t, SetBlock(path, "127.77.0.1 a.example b.example\n", 0o644))
			eq(t, inode(t, path), before)
			eq(t, readFile(t, path), "127.0.0.1 localhost\n# bugnet begin\n"+
				"127.77.0.1 a.example b.example\n# bugnet end\n")

			must(t, SetBlock(path, "", 0o644))
			eq(t, inode(t, path), before)
			eq(t, readFile(t, path), "127.0.0.1 localhost\n")
			eq(t, leftovers(t, dir), []string{"hosts"})
		})
	}
}

func TestManagedBlockRereadsAFileRenamedWhileItWaited(t *testing.T) {
	for _, body := range []string{"127.77.0.1 a.example\n", "127.77.0.1 b.example\n"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "hosts")
		writeFile(t, path, "127.0.0.1 localhost\n# bugnet begin\n127.77.0.1 a.example\n"+
			"# bugnet end\n")
		renamed := "127.0.0.1 localhost\n10.0.0.9 added\n# bugnet begin\n127.77.0.1 c.example\n" +
			"# bugnet end\n"
		calls := 0
		flock = func(fd, how int) error {
			calls++
			if calls == 1 {
				// Another writer renames its copy over the path while this one waits for the lock
				writeFile(t, filepath.Join(dir, "other"), renamed)
				must(t, os.Rename(filepath.Join(dir, "other"), path))
			}
			return syscall.Flock(fd, how)
		}
		t.Cleanup(func() { flock = syscall.Flock })

		must(t, SetBlock(path, body, 0o644))
		eq(t, readFile(t, path), "127.0.0.1 localhost\n10.0.0.9 added\n# bugnet begin\n"+body+
			"# bugnet end\n")
		eq(t, calls, 2)
		eq(t, leftovers(t, dir), []string{"hosts"})
	}
}

func TestManagedBlockGivesUpOnAFileThatKeepsBeingReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	writeFile(t, path, "127.0.0.1 localhost\n")
	calls := 0
	flock = func(fd, how int) error {
		calls++
		writeFile(t, filepath.Join(dir, "other"), "10.0.0.9 replaced\n")
		must(t, os.Rename(filepath.Join(dir, "other"), path))
		return syscall.Flock(fd, how)
	}
	t.Cleanup(func() { flock = syscall.Flock })
	if err := SetBlock(path, "127.77.0.1 a.example\n", 0o644); err == nil {
		t.Fatal("SetBlock wrote a file that another writer kept replacing")
	}
	eq(t, calls, blockTries)
	eq(t, readFile(t, path), "10.0.0.9 replaced\n")
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	must(t, err)
	return info.Sys().(*syscall.Stat_t).Ino
}

func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	must(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
