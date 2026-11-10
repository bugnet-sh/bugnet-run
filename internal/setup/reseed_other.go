//go:build !linux

package setup

import "errors"

// kernelReseed has no ioctl off Linux, so the plain write stands in
func kernelReseed(string, []byte) error { return errors.New("no random ioctl on this system") }
