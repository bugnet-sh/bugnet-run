package sandbox

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Lines that open and close the managed block of a file
const (
	BlockBegin = "# bugnet begin"
	BlockEnd   = "# bugnet end"
)

// Variables so tests can fail a rename with EBUSY and act while a writer waits for its lock
var (
	rename = os.Rename
	flock  = syscall.Flock
)

// blockTries bounds how often SetBlock starts again after another writer replaced the file
const blockTries = 10

// SetBlock makes body the managed block of path, an empty body removing the block
func SetBlock(path, body string, mode fs.FileMode) error {
	for range blockTries {
		if stale, err := setBlock(path, body, mode); !stale {
			return err
		}
	}
	return fmt.Errorf("%s kept being replaced while waiting for its lock", path)
}

// setBlock reports stale when path names another file once the lock is held, as after a rename
func setBlock(path, body string, mode fs.FileMode) (bool, error) {
	created := !exists(path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, mode)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	if err := flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return false, err
	}
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	now, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) || err == nil && !os.SameFile(info, now) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	old, err := io.ReadAll(f)
	if err != nil {
		return false, err
	}
	next := withBlock(string(old), body)
	if next == string(old) {
		return false, nil
	}
	perm := info.Mode().Perm()
	if created {
		perm = mode.Perm()
	}
	err = replace(path, []byte(next), perm, info)
	if errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EXDEV) {
		err = rewriteInPlace(f, []byte(next))
	}
	return false, err
}

// Block returns the body of the first managed block of path, empty when there is none
func Block(path string) (string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	lines := splitLines(string(b))
	for i, line := range lines {
		if marker(line) != BlockBegin {
			continue
		}
		if end := blockEnd(lines, i+1); end > 0 {
			return joinLines(lines[i+1 : end]), nil
		}
	}
	return "", nil
}

// withBlock puts body where the first complete block was, dropping other blocks and stray markers
func withBlock(old, body string) string {
	lines := splitLines(old)
	var out []string
	at := -1
	for i := 0; i < len(lines); i++ {
		switch marker(lines[i]) {
		case BlockEnd:
			continue
		case BlockBegin:
			if end := blockEnd(lines, i+1); end > 0 {
				if at < 0 {
					at = len(out)
				}
				i = end
			}
			continue
		}
		out = append(out, lines[i])
	}
	if at < 0 {
		at = len(out)
	}
	var block []string
	if body != "" {
		block = append(append([]string{BlockBegin}, splitLines(body)...), BlockEnd)
	}
	out = append(out[:at], append(block, out[at:]...)...)
	return joinLines(out)
}

func blockEnd(lines []string, from int) int {
	for j := from; j < len(lines); j++ {
		switch marker(lines[j]) {
		case BlockEnd:
			return j
		case BlockBegin:
			return -1
		}
	}
	return -1
}

func marker(line string) string {
	return strings.TrimRight(line, " \t\r")
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

func joinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// replace renames a finished copy over path with perm, keeping the original's owner
func replace(path string, data []byte, perm fs.FileMode, info fs.FileInfo) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".bugnet-*")
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 {
		_ = tmp.Chown(int(st.Uid), int(st.Gid))
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := rename(tmp.Name(), path); err != nil {
		return err
	}
	done = true
	return nil
}

// rewriteInPlace writes over the locked file itself, for a bind mount that cannot be renamed over
func rewriteInPlace(f *os.File, data []byte) error {
	if _, err := f.WriteAt(data, 0); err != nil {
		return err
	}
	if err := f.Truncate(int64(len(data))); err != nil {
		return err
	}
	return f.Sync()
}
