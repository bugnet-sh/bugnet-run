// Package sandbox holds the files and processes bugnet-run keeps inside a sandbox
package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// Sandbox paths, each mapped through Root.Path
const (
	EtcDir         = "/etc/bugnet"
	RunDir         = "/run/bugnet"
	GateKeyFile    = "/etc/bugnet/gate.key"
	GateConfig     = "/etc/bugnet/gate.json"
	EnvFile        = "/etc/bugnet/env"
	SecretsEnvFile = "/etc/bugnet/secrets.env"
	EgressConfig   = "/etc/bugnet/egress.json"
	EgressToken    = "/etc/bugnet/egress.token"
	GitCredentials = "/etc/bugnet/git-credentials"
	SSHDir         = "/etc/bugnet/ssh"
	SSHPortFile    = "/etc/bugnet/ssh/port"
	SSHDConfig     = "/etc/bugnet/ssh/sshd_config"
	SSHDPathFile   = "/etc/bugnet/ssh/sshd_path"
	HostKeyFile    = "/etc/bugnet/ssh/host_ed25519_key"
	AuthorizedKeys = "/etc/bugnet/ssh/authorized_keys"
	ShadowFile     = "/etc/shadow"
	ProfileFile    = "/etc/profile.d/bugnet.sh"
	HostsFile      = "/etc/hosts"
	GitConfig      = "/etc/gitconfig"
	CADir          = "/usr/local/share/ca-certificates"
	CABundle       = "/etc/ssl/certs/ca-certificates.crt"
	SystemdDir     = "/run/systemd/system"
	UnitDir        = "/etc/systemd/system"
	SSHDRunDir     = "/run/sshd"
	SampleConfig   = "/etc/bugnet/sample.json"
	RunnerPath     = "/usr/local/lib/bugnet/bugnet-run"
)

// Root maps sandbox paths under a directory, which is / in a real sandbox
type Root struct{ dir string }

// System is the root of a real sandbox
var System = Root{dir: "/"}

// NewRoot returns the root at dir, which must be absolute, an empty dir meaning /
func NewRoot(dir string) (Root, error) {
	if dir == "" {
		return System, nil
	}
	if !filepath.IsAbs(dir) {
		return Root{}, fmt.Errorf("root %q is not an absolute path", dir)
	}
	return Root{dir: filepath.Clean(dir)}, nil
}

// Dir returns the directory the root maps /
func (r Root) Dir() string {
	if r.dir == "" {
		return "/"
	}
	return r.dir
}

// IsSystem reports whether the root is the sandbox's own /
func (r Root) IsSystem() bool { return r.Dir() == "/" }

// Path maps an absolute sandbox path under the root
func (r Root) Path(p string) string {
	if r.IsSystem() {
		return filepath.Clean(p)
	}
	return filepath.Join(r.dir, p)
}

// Args returns the flag that hands this root to another bugnet-run process
func (r Root) Args() []string {
	if r.IsSystem() {
		return nil
	}
	return []string{"--root", r.dir}
}

// Lock waits for the sandbox lock on /etc/bugnet, which setup and respawn share
func Lock(r Root) (func(), error) {
	unlock, ok, err := lock(r, syscall.LOCK_EX)
	if err == nil && !ok {
		err = fmt.Errorf("lock %s: %w", r.Path(EtcDir), fs.ErrNotExist)
	}
	return unlock, err
}

// TryLock takes the sandbox lock unless another process holds it or /etc/bugnet is missing
func TryLock(r Root) (func(), bool, error) {
	return lock(r, syscall.LOCK_EX|syscall.LOCK_NB)
}

func lock(r Root, how int) (func(), bool, error) {
	f, err := os.Open(r.Path(EtcDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return lockFile(f, how)
}

// lockFile locks f until the returned func closes it, and closes it at once when another holds it
func lockFile(f *os.File, how int) (func(), bool, error) {
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return func() { _ = f.Close() }, true, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
