package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadEnvFileChecksNames(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "env")
	writeFile(t, path, "A=1\nB=$HOME\n9X=no\n\n# comment\nexport C=1\nD=a=b\r\nE=\nF\n_g9=x y \n"+
		"H-I=1\n=v\nJ='q'")
	vars, err := ReadEnvFile(path)
	must(t, err)
	eq(t, vars, []Var{
		{"A", "1"}, {"B", "$HOME"}, {"D", "a=b"}, {"E", ""}, {"_g9", "x y "}, {"J", "'q'"},
	})

	vars, err = ReadEnvFile(filepath.Join(t.TempDir(), "missing"))
	must(t, err)
	eq(t, len(vars), 0)
}

func TestValidName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"A", "_", "HF_TOKEN", "a1_b2", "__VITE_X"} {
		eq(t, ValidName(name), true)
	}
	for _, name := range []string{"", "9X", "A-B", "A B", "A.B", "é", "A=B"} {
		eq(t, ValidName(name), false)
	}
}

func TestFormatEnv(t *testing.T) {
	t.Parallel()
	eq(t, string(FormatEnv([]Var{{"A", "1"}, {"B", "x=y z"}})), "A=1\nB=x=y z\n")
	eq(t, string(FormatEnv(nil)), "")
}

func TestWriteProfileExportsBothFiles(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	writeFile(t, r.Path(EnvFile), "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\n"+
		"__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS=.preview.example\n")
	must(t, WriteProfile(r))
	eq(t, readFile(t, r.Path(ProfileFile)), profileHeader+
		"export SSL_CERT_FILE='/etc/ssl/certs/ca-certificates.crt'\n"+
		"export __VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS='.preview.example'\n")

	writeFile(t, r.Path(SecretsEnvFile), "HF_TOKEN=bnsec_x\nQ=it's $HOME `x`\n")
	must(t, WriteProfile(r))
	eq(t, readFile(t, r.Path(ProfileFile)), profileHeader+
		"export SSL_CERT_FILE='/etc/ssl/certs/ca-certificates.crt'\n"+
		"export __VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS='.preview.example'\n"+
		"export HF_TOKEN='bnsec_x'\n"+
		"export Q='it'\\''s $HOME `x`'\n")
	info, err := os.Stat(r.Path(ProfileFile))
	must(t, err)
	eq(t, info.Mode().Perm(), os.FileMode(0o644))
}

func TestWriteFileReportsChange(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "key")
	changed, err := WriteFile(path, []byte("k\n"), 0o600)
	must(t, err)
	eq(t, changed, true)
	changed, err = WriteFile(path, []byte("k\n"), 0o600)
	must(t, err)
	eq(t, changed, false)

	must(t, os.Chmod(path, 0o644))
	changed, err = WriteFile(path, []byte("k\n"), 0o600)
	must(t, err)
	eq(t, changed, true)
	info, err := os.Stat(path)
	must(t, err)
	eq(t, info.Mode().Perm(), os.FileMode(0o600))
	eq(t, leftovers(t, filepath.Join(dir, "sub")), []string{"key"})
}
