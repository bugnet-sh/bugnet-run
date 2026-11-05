package sandbox

import (
	"os"
	"testing"
)

func TestSetEnvLineJoinsBothFiles(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	line, err := SetEnvLine(r)
	must(t, err)
	eq(t, line, "")

	writeFile(t, r.Path(EnvFile), "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\nA=1\n")
	writeFile(t, r.Path(SecretsEnvFile), "HF_TOKEN=bnsec_x\nA=2\nODD=has space\nHASH=#x\n"+
		`Q=a"b`+"\n"+`B=a\b`+"\n"+"S=it's\n")
	line, err = SetEnvLine(r)
	must(t, err)
	eq(t, line, `SetEnv SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt A=2 HF_TOKEN=bnsec_x `+
		`"ODD=has space" "HASH=#x"`)
}

func TestRewriteSetEnvKeepsTheRestOfTheConfig(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	changed, err := RewriteSetEnv(r)
	must(t, err)
	eq(t, changed, false)
	if _, err := os.Stat(r.Path(SSHDConfig)); !os.IsNotExist(err) {
		t.Fatalf("a missing sshd_config was created: %v", err)
	}

	writeFile(t, r.Path(EnvFile), "A=1\n")
	writeFile(t, r.Path(SecretsEnvFile), "HF_TOKEN=bnsec_x\n")
	writeFile(t, r.Path(SSHDConfig), "Port 22\nSetEnv OLD=1\nUsePAM no\nsetenv=DUP=2\n"+
		"#SetEnv KEPT=1\nSubsystem sftp internal-sftp\n")
	must(t, os.Chmod(r.Path(SSHDConfig), 0o600))
	changed, err = RewriteSetEnv(r)
	must(t, err)
	eq(t, changed, true)
	eq(t, readFile(t, r.Path(SSHDConfig)), "Port 22\nSetEnv A=1 HF_TOKEN=bnsec_x\nUsePAM no\n"+
		"#SetEnv KEPT=1\nSubsystem sftp internal-sftp\n")
	info, err := os.Stat(r.Path(SSHDConfig))
	must(t, err)
	eq(t, info.Mode().Perm(), os.FileMode(0o600))
	changed, err = RewriteSetEnv(r)
	must(t, err)
	eq(t, changed, false)

	writeFile(t, r.Path(SSHDConfig), "Port 22\nMatch User nobody\n\tX11Forwarding no\n")
	_, err = RewriteSetEnv(r)
	must(t, err)
	eq(t, readFile(t, r.Path(SSHDConfig)),
		"Port 22\nSetEnv A=1 HF_TOKEN=bnsec_x\nMatch User nobody\n\tX11Forwarding no\n")

	must(t, os.Remove(r.Path(EnvFile)))
	writeFile(t, r.Path(SecretsEnvFile), "")
	_, err = RewriteSetEnv(r)
	must(t, err)
	eq(t, readFile(t, r.Path(SSHDConfig)), "Port 22\nMatch User nobody\n\tX11Forwarding no\n")
}
