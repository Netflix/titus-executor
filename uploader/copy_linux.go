// +build linux

package uploader

import (
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

type linuxDestinationFile struct {
	path string
	file *os.File
}

func (df *linuxDestinationFile) File() *os.File {
	return df.file
}

func (df *linuxDestinationFile) Finish() error {
	procPath := filepath.Join("/proc", "self", "fd", strconv.Itoa(int(df.file.Fd())))
	return unix.Linkat(unix.AT_FDCWD, procPath, unix.AT_FDCWD, df.path, unix.AT_SYMLINK_FOLLOW)
}

func newDestinationFile(filename string, mode os.FileMode) (destinationFile, error) {
	dir := filepath.Dir(filename)
	file, err := os.OpenFile(dir, unix.O_TMPFILE|os.O_RDWR, mode)
	if err != nil {
		return nil, err
	}

	return &linuxDestinationFile{
		path: filename,
		file: file,
	}, nil
}
