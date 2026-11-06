// Package xfer holds stat, stage-out and place, which the router runs with sudo for staged files
package xfer

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// Info is what stat prints, and stage-out and place print for the file they made
type Info struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	// Mode holds the permission bits, 420 for 0644
	Mode             uint32 `json:"mode"`
	ModifiedUnixNano int64  `json:"modified_unix_nano"`
	IsDir            bool   `json:"is_dir"`
	Regular          bool   `json:"regular"`
}

// Values of the error each subcommand prints
const (
	ErrBadArgs     = "bad_args"
	ErrNotFound    = "not_found"
	ErrIsDirectory = "is_directory"
	ErrNotRegular  = "not_regular"
	ErrChanged     = "file_changed"
	ErrStatFailed  = "stat_failed"
	ErrStageFailed = "stage_failed"
	ErrPlaceFailed = "place_failed"
)

const (
	exitFailed  = 1
	exitBadArgs = 2
)

// Variables so tests can change a source once it is open and fail a rename with EXDEV
var (
	afterOpen = func(*os.File) {}
	rename    = os.Rename
)

type failure struct {
	reason string
	err    error
}

func (f *failure) Error() string { return f.reason + ": " + f.err.Error() }

func (f *failure) Unwrap() error { return f.err }

func fail(reason string, err error) error { return &failure{reason: reason, err: err} }

// report prints the info or the error, a bad_args error exiting 2 and any other 1
func report(stdout, stderr io.Writer, name string, res Info, err error) int {
	if err == nil {
		b, _ := json.Marshal(res)
		_, _ = stdout.Write(append(b, '\n'))
		return 0
	}
	reason, status := ErrBadArgs, exitBadArgs
	var f *failure
	if errors.As(err, &f) && f.reason != ErrBadArgs {
		reason, status = f.reason, exitFailed
	}
	b, _ := json.Marshal(map[string]string{"error": reason})
	_, _ = stdout.Write(append(b, '\n'))
	_, _ = fmt.Fprintf(stderr, "bugnet-run %s: %v\n", name, err)
	return status
}

func parse(flags *flag.FlagSet, args []string) error {
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		return fail(ErrBadArgs, err)
	}
	if flags.NArg() > 0 {
		return fail(ErrBadArgs, fmt.Errorf("unexpected argument %q", flags.Arg(0)))
	}
	return nil
}

// cleanAbs cleans an absolute path, so a trailing slash never makes lstat follow a final link
func cleanAbs(name, p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", fail(ErrBadArgs, fmt.Errorf("--%s is not an absolute path", name))
	}
	return filepath.Clean(p), nil
}

// target is cleanAbs for a path that gets a new file, which / never can
func target(name, p string) (string, error) {
	p, err := cleanAbs(name, p)
	if err == nil && p == "/" {
		err = fail(ErrBadArgs, fmt.Errorf("--%s names the root directory", name))
	}
	return p, err
}

func infoOf(path string, fi fs.FileInfo) Info {
	return Info{
		Path: path, Size: fi.Size(), Mode: uint32(fi.Mode().Perm()),
		ModifiedUnixNano: fi.ModTime().UnixNano(), IsDir: fi.IsDir(),
		Regular: fi.Mode().IsRegular(),
	}
}

// missing reports an absent path, a file standing where a directory should be included
func missing(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

/* stat */

// Stat is bugnet-run stat --path P, describing P without following a final symlink
func Stat(args []string, stdout, stderr io.Writer) int {
	res, err := stat(args)
	return report(stdout, stderr, "stat", res, err)
}

func stat(args []string) (Info, error) {
	flags := flag.NewFlagSet("stat", flag.ContinueOnError)
	path := flags.String("path", "", "absolute path to describe")
	if err := parse(flags, args); err != nil {
		return Info{}, err
	}
	p, err := cleanAbs("path", *path)
	if err != nil {
		return Info{}, err
	}
	fi, err := os.Lstat(p)
	switch {
	case missing(err):
		return Info{}, fail(ErrNotFound, err)
	case err != nil:
		return Info{}, fail(ErrStatFailed, err)
	}
	return infoOf(p, fi), nil
}

/* stage-out */

// StageOut is bugnet-run stage-out, a copy of a regular file the owner alone can read
func StageOut(args []string, stdout, stderr io.Writer) int {
	res, err := stageOut(args)
	return report(stdout, stderr, "stage-out", res, err)
}

func stageOut(args []string) (Info, error) {
	flags := flag.NewFlagSet("stage-out", flag.ContinueOnError)
	from := flags.String("from", "", "regular file to copy")
	to := flags.String("to", "", "path of the copy")
	ownerName := flags.String("owner", "", "user who owns the copy and its new directories")
	if err := parse(flags, args); err != nil {
		return Info{}, err
	}
	src, err := cleanAbs("from", *from)
	if err != nil {
		return Info{}, err
	}
	dst, err := target("to", *to)
	if err != nil {
		return Info{}, err
	}
	uid, gid, err := lookupOwner(*ownerName)
	if err != nil {
		return Info{}, fail(ErrBadArgs, err)
	}

	// O_NONBLOCK lets a FIFO open at once, so it is refused instead of waiting for a writer
	f, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	switch {
	case missing(err):
		return Info{}, fail(ErrNotFound, err)
	case errors.Is(err, syscall.ELOOP):
		return Info{}, fail(ErrNotRegular, errors.New("--from is a symlink"))
	case err != nil:
		return Info{}, fail(ErrStageFailed, err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return Info{}, fail(ErrStageFailed, err)
	}
	if err := regular(fi); err != nil {
		return Info{}, err
	}
	afterOpen(f)

	if err := mkdirOwned(filepath.Dir(dst), uid, gid, 0o700); err != nil {
		return Info{}, fail(ErrStageFailed, err)
	}
	// The copy keeps the source's time, so the router compares it with the ETag it pinned
	err = writeBeside(dst, 0o600, fi.ModTime(), func(tmp *os.File) error {
		if err := tmp.Chown(uid, gid); err != nil {
			return err
		}
		_, err := io.CopyN(tmp, f, fi.Size())
		if errors.Is(err, io.EOF) {
			return fail(ErrChanged, errors.New("--from shrank while it was copied"))
		}
		return err
	})
	if err != nil {
		return Info{}, asFailure(ErrStageFailed, err)
	}
	return statPlaced(dst, ErrStageFailed)
}

func regular(fi fs.FileInfo) error {
	switch {
	case fi.IsDir():
		return fail(ErrIsDirectory, errors.New("the source is a directory"))
	case !fi.Mode().IsRegular():
		return fail(ErrNotRegular, errors.New("the source is not a regular file"))
	}
	return nil
}

func lookupOwner(name string) (int, int, error) {
	if name == "" {
		return 0, 0, errors.New("missing --owner")
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, errors.New("--owner names no user")
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

// mkdirOwned creates the missing directories of dir with perm for uid, leaving existing ones
func mkdirOwned(dir string, uid, gid int, perm fs.FileMode) error {
	fi, err := os.Stat(dir)
	if err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := mkdirOwned(filepath.Dir(dir), uid, gid, perm); err != nil {
		return err
	}
	if err := os.Mkdir(dir, perm); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	// Owner and mode go through a descriptor, so a link swapped in meanwhile is never followed
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := d.Chown(uid, gid); err != nil {
		return err
	}
	// Mkdir's mode went through the umask, so it is set again
	return d.Chmod(perm)
}

/* place */

// Place is bugnet-run place, which moves a staged upload over its target
func Place(args []string, stdout, stderr io.Writer) int {
	res, err := place(args)
	return report(stdout, stderr, "place", res, err)
}

func place(args []string) (Info, error) {
	flags := flag.NewFlagSet("place", flag.ContinueOnError)
	from := flags.String("from", "", "staged regular file")
	to := flags.String("to", "", "target path")
	modeText := flags.String("mode", "0644", "permission bits of the placed file, in octal")
	if err := parse(flags, args); err != nil {
		return Info{}, err
	}
	src, err := cleanAbs("from", *from)
	if err != nil {
		return Info{}, err
	}
	dst, err := target("to", *to)
	if err != nil {
		return Info{}, err
	}
	perm, err := parseMode(*modeText)
	if err != nil {
		return Info{}, err
	}

	// Changes go through this descriptor, so a path swapped meanwhile never gets root's chmod
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	switch {
	case missing(err):
		return Info{}, fail(ErrNotFound, err)
	case errors.Is(err, syscall.ELOOP):
		return Info{}, fail(ErrNotRegular, errors.New("--from is a symlink"))
	case err != nil:
		return Info{}, fail(ErrPlaceFailed, err)
	}
	defer func() { _ = in.Close() }()
	si, err := in.Stat()
	if err != nil {
		return Info{}, fail(ErrPlaceFailed, err)
	}
	if err := regular(si); err != nil {
		return Info{}, err
	}
	afterOpen(in)
	// A new file keeps the staged file's owner, as sudo mv would
	uid, gid := ownerOf(si)
	di, err := os.Lstat(dst)
	switch {
	case err == nil && di.IsDir():
		return Info{}, fail(ErrIsDirectory, errors.New("--to is a directory"))
	case err == nil && di.Mode().IsRegular():
		// A replaced file keeps its owner, as cp onto it would
		uid, gid = ownerOf(di)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return Info{}, fail(ErrPlaceFailed, err)
	}

	// New parents get the new file's owner, so that owner can work in them without sudo
	if err := mkdirOwned(filepath.Dir(dst), uid, gid, 0o755); err != nil {
		return Info{}, fail(ErrPlaceFailed, err)
	}
	// The staged file gets its final owner and mode first, so the target never shows the user's
	if err := in.Chown(uid, gid); err != nil {
		return Info{}, fail(ErrPlaceFailed, err)
	}
	if err := in.Chmod(perm); err != nil {
		return Info{}, fail(ErrPlaceFailed, err)
	}
	copied := false
	err = rename(src, dst)
	if errors.Is(err, syscall.EXDEV) {
		copied = true
		err = copyBeside(in, si, dst, uid, gid, perm)
		if err == nil {
			err = os.Remove(src)
		}
	}
	if err != nil {
		return Info{}, fail(ErrPlaceFailed, err)
	}
	placed, err := os.Lstat(dst)
	if err != nil {
		return Info{}, fail(ErrPlaceFailed, err)
	}
	if !copied && !os.SameFile(si, placed) {
		return Info{}, fail(ErrPlaceFailed, errors.New("--from was replaced while it was placed"))
	}
	return infoOf(dst, placed), nil
}

func ownerOf(fi fs.FileInfo) (int, int) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return os.Geteuid(), os.Getegid()
	}
	return int(st.Uid), int(st.Gid)
}

// parseMode accepts permission bits alone, so an upload never sets setuid or setgid
func parseMode(text string) (fs.FileMode, error) {
	m, err := strconv.ParseUint(text, 8, 32)
	if err != nil || m > 0o777 {
		return 0, fail(ErrBadArgs, errors.New("--mode is not octal permission bits"))
	}
	return fs.FileMode(m), nil
}

// copyBeside copies in into a temporary file in dst's directory, then renames it over dst
func copyBeside(in *os.File, fi fs.FileInfo, dst string, uid, gid int, perm fs.FileMode) error {
	return writeBeside(dst, perm, fi.ModTime(), func(tmp *os.File) error {
		if err := tmp.Chown(uid, gid); err != nil {
			return err
		}
		_, err := io.Copy(tmp, in)
		return err
	})
}

// writeBeside fills a temporary file next to dst and renames it over dst, removing it on failure
func writeBeside(dst string, perm fs.FileMode, modified time.Time,
	fill func(*os.File) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".bugnet-*")
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if err := fill(tmp); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chtimes(tmp.Name(), modified, modified); err != nil {
		return err
	}
	if err := rename(tmp.Name(), dst); err != nil {
		return err
	}
	done = true
	return nil
}

// asFailure keeps the reason a step already gave, and gives reason to any other error
func asFailure(reason string, err error) error {
	var f *failure
	if errors.As(err, &f) {
		return err
	}
	return fail(reason, err)
}

func statPlaced(path, reason string) (Info, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return Info{}, fail(reason, err)
	}
	return infoOf(path, fi), nil
}
