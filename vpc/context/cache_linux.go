// +build linux

package context

import (
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

func atomicWriteOnce(path string, data []byte) error {
	dir := filepath.Dir(path)
	file, err := os.OpenFile(dir, unix.O_TMPFILE|os.O_RDWR, 0644) // nolint: gas
	if err != nil {
		return err
	}
	defer shouldClose(file)
	_, err = file.Write(data)
	if err != nil {
		return err
	}
	err = file.Sync()
	if err != nil {
		return err
	}

	oldpath := filepath.Join("/proc", "self", "fd", strconv.Itoa(int(file.Fd())))
	return unix.Linkat(unix.AT_FDCWD, oldpath, unix.AT_FDCWD, path, unix.AT_SYMLINK_FOLLOW)
}
