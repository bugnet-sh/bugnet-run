package sample

import "syscall"

// Filesystems that live in memory, whose bytes the memory peak already counts
const (
	tmpfsMagic = 0x01021994
	ramfsMagic = 0x858458f6
)

func diskUsage(path string) (dev, used uint64, ok bool) {
	var st syscall.Stat_t
	var fs syscall.Statfs_t
	if syscall.Stat(path, &st) != nil || syscall.Statfs(path, &fs) != nil {
		return 0, 0, false
	}
	if fs.Type == tmpfsMagic || fs.Type == ramfsMagic {
		return 0, 0, false
	}
	block := uint64(fs.Frsize)
	if block == 0 {
		block = uint64(fs.Bsize)
	}
	return st.Dev, (fs.Blocks - fs.Bfree) * block, true
}
