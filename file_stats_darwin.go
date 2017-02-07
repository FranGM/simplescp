// +build darwin

package main

import "syscall"

func getLastAccess(stat *syscall.Stat_t) syscall.Timespec {
	return stat.Atimespec
}

func getLastModification(stat *syscall.Stat_t) syscall.Timespec {
	return stat.Mtimespec
}
