//go:build linux
// +build linux

package main

import (
	"os"
	"syscall"
)

func makeMountRShared(path string) error {
	var flags uintptr // nolint: gosimple
	flags = syscall.MS_SHARED
	options := ""
	err := syscall.Mount("none", path, "none", flags, options)
	return os.NewSyscallError("mount", err)
}
