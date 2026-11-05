package sandbox

import (
	"errors"
	"io/fs"
	"os"
	"strings"
)

// SetEnvLine returns our sshd's SetEnv line for both env files, empty when they hold nothing
func SetEnvLine(r Root) (string, error) {
	var names []string
	values := map[string]string{}
	for _, file := range []string{EnvFile, SecretsEnvFile} {
		vars, err := ReadEnvFile(r.Path(file))
		if err != nil {
			return "", err
		}
		for _, v := range vars {
			if _, ok := values[v.Name]; !ok {
				names = append(names, v.Name)
			}
			values[v.Name] = v.Value
		}
	}
	var args []string
	for _, name := range names {
		arg := name + "=" + values[name]
		// Old and new sshd parse these characters differently, so no quoting is safe for them
		if strings.ContainsAny(arg, `"'\`) {
			continue
		}
		if strings.ContainsAny(arg, " \t#") {
			arg = `"` + arg + `"`
		}
		args = append(args, arg)
	}
	if len(args) == 0 {
		return "", nil
	}
	return "SetEnv " + strings.Join(args, " "), nil
}

// RewriteSetEnv puts the current SetEnv line in our sshd_config when it exists, reporting a change
func RewriteSetEnv(r Root) (bool, error) {
	path := r.Path(SSHDConfig)
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	old, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	line, err := SetEnvLine(r)
	if err != nil {
		return false, err
	}
	// sshd honours only the first SetEnv, and one after Match would apply to that block alone
	placed := line == ""
	var out []string
	for _, l := range splitLines(string(old)) {
		switch keyword(l) {
		case "setenv":
			if !placed {
				out, placed = append(out, line), true
			}
			continue
		case "match":
			if !placed {
				out, placed = append(out, line), true
			}
		}
		out = append(out, l)
	}
	if !placed {
		out = append(out, line)
	}
	return WriteFile(path, []byte(joinLines(out)), info.Mode().Perm())
}

// keyword returns an sshd_config line's keyword in lower case, which may end at a space or =
func keyword(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	k, _, _ := strings.Cut(fields[0], "=")
	return strings.ToLower(k)
}
