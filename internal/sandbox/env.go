package sandbox

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Var is one NAME=VALUE line of an env file
type Var struct{ Name, Value string }

// ValidName reports whether name matches ^[A-Za-z_][A-Za-z0-9_]*$
func ValidName(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		switch {
		case c == '_', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// ReadEnvFile returns the lines of an env file whose names are valid, none when it is missing
func ReadEnvFile(path string) ([]Var, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var vars []Var
	for line := range strings.Lines(string(b)) {
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		name, value, ok := strings.Cut(line, "=")
		if ok && ValidName(name) && !strings.ContainsRune(value, 0) {
			vars = append(vars, Var{name, value})
		}
	}
	return vars, nil
}

// FormatEnv renders vars as env file lines
func FormatEnv(vars []Var) []byte {
	var b bytes.Buffer
	for _, v := range vars {
		b.WriteString(v.Name + "=" + v.Value + "\n")
	}
	return b.Bytes()
}

const profileHeader = "# Written by bugnet-run from /etc/bugnet/env and /etc/bugnet/secrets.env\n"

// WriteProfile exports both env files to login shells through /etc/profile.d/bugnet.sh
func WriteProfile(r Root) error {
	var b strings.Builder
	b.WriteString(profileHeader)
	for _, file := range []string{EnvFile, SecretsEnvFile} {
		vars, err := ReadEnvFile(r.Path(file))
		if err != nil {
			return err
		}
		for _, v := range vars {
			b.WriteString("export " + v.Name + "=" + shellQuote(v.Value) + "\n")
		}
	}
	_, err := WriteFile(r.Path(ProfileFile), []byte(b.String()), 0o644)
	return err
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// WriteFile puts data at path with mode through a renamed temporary file, reporting a change
func WriteFile(path string, data []byte, mode fs.FileMode) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		if info, err := os.Stat(path); err == nil && info.Mode().Perm() == mode.Perm() {
			return false, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".bugnet-*")
	if err != nil {
		return false, err
	}
	name := tmp.Name()
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(mode.Perm())
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		_ = os.Remove(name)
		return false, err
	}
	return true, nil
}
