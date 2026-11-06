//go:build !linux

package runner

import "syscall"

func isCgroup2(string) bool { return false }

func intoCgroup(*syscall.SysProcAttr, int) bool { return false }
