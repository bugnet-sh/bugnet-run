//go:build !linux

package sample

import "syscall"

func diskUsage(path string) (dev, used uint64, ok bool) {
	var st syscall.Stat_t
	var fs syscall.Statfs_t
	if syscall.Stat(path, &st) != nil || syscall.Statfs(path, &fs) != nil {
		return 0, 0, false
	}
	return uint64(st.Dev), (fs.Blocks - fs.Bfree) * uint64(fs.Bsize), true
}
