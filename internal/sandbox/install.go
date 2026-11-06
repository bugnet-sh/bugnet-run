package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// InstallRunner copies exe to RunnerPath through a renamed temporary file, reporting a change
func InstallRunner(r Root, exe string) (bool, error) {
	src, err := os.Open(exe)
	if err != nil {
		return false, err
	}
	defer func() { _ = src.Close() }()
	info, err := src.Stat()
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", exe)
	}
	dst := r.Path(RunnerPath)
	if same, err := installed(src, info, dst); err != nil || same {
		return false, err
	}
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return false, err
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(dst)+".bugnet-*")
	if err != nil {
		return false, err
	}
	name := tmp.Name()
	_, err = io.Copy(tmp, src)
	if err == nil {
		err = tmp.Chmod(0o755)
	}
	if err == nil && os.Geteuid() == 0 {
		err = tmp.Chown(0, 0)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = rename(name, dst)
	}
	if err != nil {
		_ = os.Remove(name)
		return false, err
	}
	return true, nil
}

// installed reports whether dst is src itself, or a 0755 file root owns holding src's bytes
func installed(src *os.File, info fs.FileInfo, dst string) (bool, error) {
	have, err := os.Lstat(dst)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if os.SameFile(info, have) {
		return true, nil
	}
	if !have.Mode().IsRegular() || have.Mode().Perm() != 0o755 || have.Size() != info.Size() {
		return false, nil
	}
	if st, ok := have.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 &&
		(st.Uid != 0 || st.Gid != 0) {
		return false, nil
	}
	f, err := os.Open(dst)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	return sameBytes(src, f)
}

func sameBytes(a, b io.Reader) (bool, error) {
	bufA, bufB := make([]byte, 64<<10), make([]byte, 64<<10)
	for {
		n, errA := io.ReadFull(a, bufA)
		m, errB := io.ReadFull(b, bufB)
		if n != m || !bytes.Equal(bufA[:n], bufB[:m]) {
			return false, nil
		}
		endA := errors.Is(errA, io.EOF) || errors.Is(errA, io.ErrUnexpectedEOF)
		endB := errors.Is(errB, io.EOF) || errors.Is(errB, io.ErrUnexpectedEOF)
		switch {
		case errA != nil && !endA:
			return false, errA
		case errB != nil && !endB:
			return false, errB
		case endA || endB:
			return endA && endB, nil
		}
	}
}
