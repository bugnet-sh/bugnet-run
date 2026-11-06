package sandbox

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRootMapsPaths(t *testing.T) {
	t.Parallel()
	sys, err := NewRoot("")
	must(t, err)
	eq(t, sys.IsSystem(), true)
	eq(t, sys.Path(GateKeyFile), "/etc/bugnet/gate.key")
	eq(t, sys.Args(), []string(nil))

	r, err := NewRoot("/sandboxes/a/fs/")
	must(t, err)
	eq(t, r.IsSystem(), false)
	eq(t, r.Dir(), "/sandboxes/a/fs")
	eq(t, r.Path(GateKeyFile), "/sandboxes/a/fs/etc/bugnet/gate.key")
	eq(t, r.Path(RunDir), "/sandboxes/a/fs/run/bugnet")
	eq(t, r.Args(), []string{"--root", "/sandboxes/a/fs"})

	_, err = NewRoot("relative/fs")
	eq(t, err != nil, true)
}

func TestLockSerialisesAndTryLockSkips(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	must(t, os.MkdirAll(r.Path(EtcDir), 0o755))
	unlock, err := Lock(r)
	must(t, err)

	other, ok, err := TryLock(r)
	must(t, err)
	eq(t, ok, false)
	eq(t, other == nil, true)

	got := make(chan struct{})
	go func() {
		again, err := Lock(r)
		if err == nil {
			again()
		}
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("a second Lock did not wait for the first")
	case <-time.After(50 * time.Millisecond):
	}
	unlock()
	<-got

	// A child that another test forks holds a copy of the lock until its exec, so retry briefly
	deadline := time.Now().Add(time.Second)
	free, ok, err := TryLock(r)
	for err == nil && !ok && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		free, ok, err = TryLock(r)
	}
	must(t, err)
	eq(t, ok, true)
	free()
}

func TestLockWithoutEtcDir(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	_, ok, err := TryLock(r)
	must(t, err)
	eq(t, ok, false)
	_, err = os.Stat(filepath.Join(r.Dir(), "etc"))
	eq(t, os.IsNotExist(err), true)
}
