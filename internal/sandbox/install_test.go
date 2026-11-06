package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestInstallRunnerCopiesOnce(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	exe := filepath.Join(t.TempDir(), "bugnet-run")
	writeFile(t, exe, "runner v1\n")
	must(t, os.Chmod(exe, 0o700))

	changed, err := InstallRunner(r, exe)
	must(t, err)
	eq(t, changed, true)
	dst := r.Path(RunnerPath)
	eq(t, readFile(t, dst), "runner v1\n")
	info, err := os.Stat(dst)
	must(t, err)
	eq(t, info.Mode().Perm(), os.FileMode(0o755))
	dir, err := os.Stat(filepath.Dir(dst))
	must(t, err)
	eq(t, dir.Mode().Perm(), os.FileMode(0o755))
	eq(t, os.SameFile(info, mustStat(t, exe)), false)

	before := inode(t, dst)
	changed, err = InstallRunner(r, exe)
	must(t, err)
	eq(t, changed, false)
	eq(t, inode(t, dst), before)
	eq(t, leftovers(t, filepath.Dir(dst)), []string{"bugnet-run"})
}

func TestInstallRunnerReplacesAChangedBinaryAtomically(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	exe := filepath.Join(t.TempDir(), "bugnet-run")
	writeFile(t, exe, "runner v1\n")
	_, err := InstallRunner(r, exe)
	must(t, err)
	dst := r.Path(RunnerPath)
	// A running service holds the old file, which a rename leaves whole
	held := filepath.Join(t.TempDir(), "held")
	must(t, os.Link(dst, held))

	writeFile(t, exe, "runner v2, a longer one\n")
	changed, err := InstallRunner(r, exe)
	must(t, err)
	eq(t, changed, true)
	eq(t, readFile(t, dst), "runner v2, a longer one\n")
	eq(t, readFile(t, held), "runner v1\n")
	eq(t, os.SameFile(mustStat(t, dst), mustStat(t, held)), false)
	eq(t, leftovers(t, filepath.Dir(dst)), []string{"bugnet-run"})

	// Same size and other bytes still count as a change
	writeFile(t, exe, "runner v3, a longer one\n")
	changed, err = InstallRunner(r, exe)
	must(t, err)
	eq(t, changed, true)
	eq(t, readFile(t, dst), "runner v3, a longer one\n")
}

func TestInstallRunnerRewritesAWrongModeOrALink(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	exe := filepath.Join(t.TempDir(), "bugnet-run")
	writeFile(t, exe, "runner\n")
	_, err := InstallRunner(r, exe)
	must(t, err)
	dst := r.Path(RunnerPath)
	must(t, os.Chmod(dst, 0o777))
	changed, err := InstallRunner(r, exe)
	must(t, err)
	eq(t, changed, true)
	eq(t, mustStat(t, dst).Mode().Perm(), os.FileMode(0o755))

	victim := filepath.Join(t.TempDir(), "victim")
	writeFile(t, victim, "runner\n")
	must(t, os.Chmod(victim, 0o755))
	must(t, os.Remove(dst))
	must(t, os.Symlink(victim, dst))
	changed, err = InstallRunner(r, exe)
	must(t, err)
	eq(t, changed, true)
	info, err := os.Lstat(dst)
	must(t, err)
	eq(t, info.Mode().IsRegular(), true)
	eq(t, readFile(t, victim), "runner\n")
}

func TestInstallRunnerFromItsOwnPathKeepsIt(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	dst := r.Path(RunnerPath)
	writeFile(t, dst, "baked runner\n")
	before := inode(t, dst)
	changed, err := InstallRunner(r, dst)
	must(t, err)
	eq(t, changed, false)
	eq(t, inode(t, dst), before)
}

func TestInstallRunnerFailedRenameKeepsTheOldCopy(t *testing.T) {
	r := testRoot(t)
	exe := filepath.Join(t.TempDir(), "bugnet-run")
	writeFile(t, exe, "runner v1\n")
	_, err := InstallRunner(r, exe)
	must(t, err)
	writeFile(t, exe, "runner v2\n")
	rename = func(oldpath, newpath string) error {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: syscall.EIO}
	}
	t.Cleanup(func() { rename = os.Rename })

	changed, err := InstallRunner(r, exe)
	eq(t, err != nil && strings.Contains(err.Error(), "input/output error"), true)
	eq(t, changed, false)
	dst := r.Path(RunnerPath)
	eq(t, readFile(t, dst), "runner v1\n")
	eq(t, leftovers(t, filepath.Dir(dst)), []string{"bugnet-run"})

	_, err = InstallRunner(r, filepath.Join(t.TempDir(), "missing"))
	eq(t, err != nil, true)
	_, err = InstallRunner(r, t.TempDir())
	eq(t, err != nil, true)
	eq(t, readFile(t, dst), "runner v1\n")
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	must(t, err)
	return info
}
