package setup

import (
	"encoding/base64"
	"encoding/binary"
	"os"
)

// seedLen is the bytes of router randomness a spec carries
const seedLen = 32

// seedBits is the entropy the ioctl credits for a seed of seedLen bytes
const seedBits = seedLen * 8

// urandom is the kernel's random device, a variable so tests write elsewhere
var urandom = "/dev/urandom"

// addEntropy credits arg to the kernel's pool and forces a reseed, a seam for tests
var addEntropy = kernelReseed

// Values of Result.Reseed
const (
	ReseedIoctl  = "ioctl"
	ReseedWrite  = "write"
	ReseedFailed = "failed"
)

// entropyArg builds the rand_pool_info the RNDADDENTROPY ioctl takes
func entropyArg(seed []byte) []byte {
	arg := make([]byte, 8+len(seed))
	binary.NativeEndian.PutUint32(arg[0:4], uint32(len(seed))*8)
	binary.NativeEndian.PutUint32(arg[4:8], uint32(len(seed)))
	copy(arg[8:], seed)
	return arg
}

// reseed mixes the spec's seed into the kernel and says how, empty without a seed
//
// Without the privilege for the ioctl, a plain write still mixes the bytes in, just without a
// reseed. A failure never fails setup.
func reseed(seed string) string {
	b, err := base64.StdEncoding.DecodeString(seed)
	if err != nil || len(b) != seedLen {
		return ""
	}
	if addEntropy(urandom, entropyArg(b)) == nil {
		return ReseedIoctl
	}
	f, err := os.OpenFile(urandom, os.O_WRONLY, 0)
	if err != nil {
		return ReseedFailed
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return ReseedFailed
	}
	return ReseedWrite
}
