package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/bugnet-sh/bugnet-run/internal/harden"
	"github.com/bugnet-sh/bugnet-run/internal/sandbox"
)

// firewallName stands in respawn's started list for a firewall table loaded again
const firewallName = "firewall"

// Variables so tests can take the sudo path and stand in for sudo
var (
	// respawnTimeout bounds the respawn a job start runs, so it never holds the job up for long
	respawnTimeout = 15 * time.Second
	// sudoProgram runs respawn as root for a start that is not root
	sudoProgram = "sudo"
	// privileged reports whether start may bring back the services of root itself
	privileged = func(root sandbox.Root) bool { return os.Geteuid() == 0 || !root.IsSystem() }
)

type respawnResult struct {
	Started []string `json:"started"`
	Error   string   `json:"error,omitempty"`
}

// respawn starts every service whose config exists and whose process is gone
func respawn(args []string, stdout, stderr io.Writer) int {
	var rootDir string
	flags := newFlags("respawn")
	flags.StringVar(&rootDir, "root", "/", "directory standing for the sandbox's /")
	err := parseFlags(flags, args)
	var root sandbox.Root
	if err == nil {
		root, err = sandbox.NewRoot(rootDir)
	}
	if err != nil {
		return badArgs(stdout, stderr, err)
	}
	exe, err := os.Executable()
	res := respawnResult{Started: []string{}}
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), respawnTimeout)
		var started []string
		started, err = respawnServices(ctx, root, exe)
		cancel()
		res.Started = append(res.Started, started...)
	}
	status := exitOK
	if err != nil {
		res.Error, status = "respawn_failed", exitFailed
		_, _ = fmt.Fprintf(stderr, "bugnet-run: %v\n", err)
	}
	if err := json.NewEncoder(stdout).Encode(res); err != nil {
		return failed(stderr, err)
	}
	return status
}

// needed reports whether a service is down or the firewall table is due a check
func needed(root sandbox.Root) bool {
	return len((sandbox.Supervisor{Root: root}).Dead()) > 0 || harden.Due(root, time.Now())
}

// respawnServices starts each dead service, leaving the round to a setup that holds the sandbox
func respawnServices(ctx context.Context, root sandbox.Root, exe string) ([]string, error) {
	sup := sandbox.Supervisor{Root: root}
	if !needed(root) {
		return nil, nil
	}
	unlock, ok, err := sandbox.TryLock(root)
	if err != nil || !ok {
		return nil, err
	}
	defer unlock()
	var started []string
	var errs []error
	if harden.Due(root, time.Now()) {
		reloaded, err := harden.Recheck(ctx, root, time.Now())
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("reload the firewall: %w", err))
		case reloaded:
			started = append(started, firewallName)
		}
	}
	dead := sup.Dead()
	if len(dead) > 0 {
		// A failed copy still lets each service start from the copy already in place
		if _, err := sandbox.InstallRunner(root, exe); err != nil {
			errs = append(errs, fmt.Errorf("install the runner: %w", err))
		}
	}
	for _, svc := range dead {
		if err := sup.Start(ctx, svc); err != nil {
			errs = append(errs, fmt.Errorf("start %s: %w", svc.Name, err))
			continue
		}
		started = append(started, svc.Name)
	}
	return started, errors.Join(errs...)
}

// respawnBeforeJob brings back dead services and the firewall as root, through sudo if need be
func respawnBeforeJob(root sandbox.Root) {
	if !needed(root) {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), respawnTimeout)
	defer cancel()
	if privileged(root) {
		_, _ = respawnServices(ctx, root, exe)
		return
	}
	sandbox.CloseInherited()
	_ = exec.CommandContext(ctx, sudoProgram, sudoArgs(exe, root)...).Run()
}

// sudoArgs runs respawn for root through sudo, which must never stop to ask for a password
func sudoArgs(exe string, root sandbox.Root) []string {
	return append([]string{"-n", exe, "respawn"}, root.Args()...)
}
