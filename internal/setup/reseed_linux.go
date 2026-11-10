package setup

import (
	"os"
	"syscall"
	"unsafe"
)

// Linux's ioctl numbers for the random device, from linux/random.h
const (
	rndAddEntropy = 0x40085203
	rndReseedCRNG = 0x5207
)

// kernelReseed adds arg with RNDADDENTROPY, then forces a reseed with RNDRESEEDCRNG
func kernelReseed(path string, arg []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	fd := f.Fd()
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, rndAddEntropy,
		uintptr(unsafe.Pointer(&arg[0]))); errno != 0 {
		return errno
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, rndReseedCRNG, 0); errno != 0 {
		return errno
	}
	return nil
}
