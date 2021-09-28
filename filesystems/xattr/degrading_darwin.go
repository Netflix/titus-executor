//go:build darwin
// +build darwin

package xattr

import (
	"errors"
	"io"

	"os"
	"runtime"
	"syscall"
)

const (
	blockSize = 4096
	// XATTR_MAXNAMELEN is extracted from MacOS headers and is the maximum allowable xattr
	XATTR_MAXNAMELEN = 127 // nolint: golint
	// ENOATTR is the error code returned when an attribute doesn't exist
	ENOATTR = syscall.ENOATTR // nolint: golint
)

var (
	errFailedToCompleteWrite = errors.New("Failed to complete write")
)

// The Go implementation of degrading utils
func realMakeHole(file *os.File, start, length int64) error {
	var _ *os.File = file
	// Mac OS X doesn't have an actual implementation

	var oldOffset int64
	var err error
	oldOffset, err = file.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	err = _realMakeHole(file, start, length)

	if _, tmpErr := file.Seek(oldOffset, io.SeekStart); tmpErr != nil && err != nil {
		err = tmpErr
	}

	return err
}
func _realMakeHole(file io.WriteSeeker, start, length int64) error {
	zeroBuf := [blockSize]byte{}
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return err
	}
	for ; length > int64(len(zeroBuf)); length = length - int64(len(zeroBuf)) {
		if written, err := file.Write(zeroBuf[:]); err != nil {
			return err
		} else if written != len(zeroBuf) {
			return errFailedToCompleteWrite
		}
	}
	// Complete the write
	if written, err := file.Write(zeroBuf[:length]); err != nil {
		return err
	} else if int64(written) != length {
		return errFailedToCompleteWrite
	}
	return nil
}

func realFSetXattr(file *os.File, key, value []byte) error {
	// From the man page:
	// In the current implementation, only the resource fork extended attribute makes use of this argument.  For all others, position is reserved and
	// should be set to zero.
	const position = 0
	const options = 0

	tmpRet, _, err := syscall.RawSyscall6(syscall.SYS_FSETXATTR, file.Fd(), pointerToByteSlice(key), pointerToByteSlice(value), uintptr(len(value)), position, options)
	ret := int(tmpRet)
	if ret == -1 {
		return err
	}
	return nil
}

func realFDelXattr(file *os.File, key []byte) error {
	const options = 0
	tmpRet, _, err := syscall.RawSyscall(syscall.SYS_FREMOVEXATTR, file.Fd(), pointerToByteSlice(key), options)
	ret := int(tmpRet)
	if ret == -1 {
		return err
	}
	return nil
}

func realFGetXattr(file *os.File, key []byte) ([]byte, error) {
	const position = 0
	const options = 0

	buf := make([]byte, maxValueSize)
	tmpRet, _, err := syscall.RawSyscall6(syscall.SYS_FGETXATTR, file.Fd(), pointerToByteSlice(key), pointerToByteSlice(buf), uintptr(len(buf)), position, options)
	runtime.KeepAlive(buf)
	ret := ssize_t(tmpRet)
	if ret == -1 {
		return nil, err
	}
	return buf[:ret], nil
}

func realSetXattr(path []byte, key, value []byte) error {
	// From the man page:
	// In the current implementation, only the resource fork extended attribute makes use of this argument.  For all others, position is reserved and
	// should be set to zero.
	const position = 0
	const options = 0

	tmpRet, _, err := syscall.RawSyscall6(syscall.SYS_SETXATTR, pointerToByteSlice(path), pointerToByteSlice(key), pointerToByteSlice(value), uintptr(len(value)), position, options)
	ret := int(tmpRet)
	if ret == -1 {
		return err
	}
	return nil
}

func realDelXattr(path []byte, key []byte) error {
	const options = 0
	tmpRet, _, err := syscall.RawSyscall(syscall.SYS_REMOVEXATTR, pointerToByteSlice(path), pointerToByteSlice(key), options)
	ret := int(tmpRet)
	if ret == -1 {
		return err
	}
	return nil
}

func realGetXattr(path []byte, key []byte) ([]byte, error) {
	const position = 0
	const options = 0

	buf := make([]byte, maxValueSize)
	tmpRet, _, err := syscall.RawSyscall6(syscall.SYS_GETXATTR, pointerToByteSlice(path), pointerToByteSlice(key), pointerToByteSlice(buf), uintptr(len(buf)), position, options)
	runtime.KeepAlive(buf)
	ret := ssize_t(tmpRet)
	if ret == -1 {
		return nil, err
	}
	return buf[:ret], nil
}
