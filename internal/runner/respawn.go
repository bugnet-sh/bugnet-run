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

	"github.com/oynozan/bugnet-run/internal/sandbox"
)

// respawnTimeout bounds the respawn a job start runs, so it never holds the job up for long
const respawnTimeout = 15 * time.Second

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

// respawnServices starts each dead service, leaving the round to a setup that holds the sandbox
func respawnServices(ctx context.Context, root sandbox.Root, exe string) ([]string, error) {
	sup := sandbox.Supervisor{Root: root, Exe: exe}
	if len(sup.Dead()) == 0 {
		return nil, nil
	}
	unlock, ok, err := sandbox.TryLock(root)
	if err != nil || !ok {
		return nil, err
	}
	defer unlock()
	var started []string
	var errs []error
	for _, svc := range sup.Dead() {
		if err := sup.Start(ctx, svc); err != nil {
			errs = append(errs, fmt.Errorf("start %s: %w", svc.Name, err))
			continue
		}
		started = append(started, svc.Name)
	}
	return started, errors.Join(errs...)
}

// respawnBeforeJob brings back dead services as root, through sudo when start runs as another user
func respawnBeforeJob(root sandbox.Root) {
	if len((sandbox.Supervisor{Root: root}).Dead()) == 0 {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), respawnTimeout)
	defer cancel()
	if os.Geteuid() == 0 || !root.IsSystem() {
		_, _ = respawnServices(ctx, root, exe)
		return
	}
	sandbox.CloseInherited()
	_ = exec.CommandContext(ctx, "sudo", "-n", exe, "respawn").Run()
}
