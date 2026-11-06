package runner

import "syscall"

// cgroup2Magic is CGROUP2_SUPER_MAGIC, the type statfs gives for a cgroup v2 mount
const cgroup2Magic = 0x63677270

func isCgroup2(path string) bool {
	var st syscall.Statfs_t
	return syscall.Statfs(path, &st) == nil && st.Type == cgroup2Magic
}

// intoCgroup has clone3 start the command inside the cgroup, before it can fork anything
func intoCgroup(attr *syscall.SysProcAttr, fd int) bool {
	attr.UseCgroupFD, attr.CgroupFD = true, fd
	return true
}
