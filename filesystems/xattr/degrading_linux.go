//go:build linux
// +build linux

package xattr

import (
	"math"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	defaultBlockSize = 4096
	/*
		So, this is complicated because:
		the maximum size is dictated by: (name_len + size > BTRFS_MAX_XATTR_SIZE(root->fs_info))
		BTRFS_MAX_XATTR_SIZE is BTRFS_MAX_ITEM_SIZE(info) - sizeof(struct btrfs_dir_item)
		struct btrfs_dir_item is 30 bytes
		BTRFS_MAX_ITEM_SIZE is BTRFS_LEAF_DATA_SIZE(info) - sizeof(struct btrfs_item);
		and so on and so forth

		Although we could cgo these macros in via cgo, they would them come with a lot of baggage. :(
	*/

	// XATTR_MAXNAMELEN comes from the maximal allowed key size that can be stored on ext, given the length is specified in u8
	XATTR_MAXNAMELEN = 255 // nolint: golint

	/* Borrowed from /usr/include */

	// ENOATTR is the error code returned when an attribute doesn't exist
	ENOATTR = syscall.ENODATA // nolint: golint
)

func getBlockSize(file *os.File) int64 {
	var statfs unix.Statfs_t
	err := unix.Fstatfs(int(file.Fd()), &statfs)
	if err != nil {
		return defaultBlockSize
	}
	return statfs.Bsize
}
func newStartAndLength(file *os.File, start, length int64) (int64, int64) {
	blockSize := getBlockSize(file)
	newStart := int64(math.Ceil(float64(start)/float64(blockSize)) * float64(blockSize))
	newLength := int64(math.Floor(float64(length)/float64(blockSize)) * float64(blockSize))
	return newStart, newLength
}

func realMakeHole(file *os.File, start, length int64) error {
	newStart, newLength := newStartAndLength(file, start, length)
	return unix.Fallocate(int(file.Fd()), unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, newStart, newLength)
}

func realFSetXattr(file *os.File, key, value []byte) error {
	// From the man page:
	// In the current implementation, only the resource fork extended attribute makes use of this argument.  For all others, position is reserved and
	// should be set to zero.
	const flags = 0

	// int fsetxattr (int filedes, const char *name,
	// const void *value, size_t size, int flags)
	tmpRet, _, err := syscall.RawSyscall6(syscall.SYS_FSETXATTR, file.Fd(), pointerToByteSlice(key), pointerToByteSlice(value), uintptr(len(value)), flags, 0)
	ret := int(tmpRet)
	if ret == -1 {
		return err
	}
	return nil
}

func realFDelXattr(file *os.File, key []byte) error {
	tmpRet, _, err := syscall.RawSyscall(syscall.SYS_FREMOVEXATTR, file.Fd(), pointerToByteSlice(key), unusedArg)
	ret := int(tmpRet)
	if ret == -1 {
		return err
	}
	return nil
}

func realFGetXattr(file *os.File, key []byte) ([]byte, error) {
	buf := make([]byte, maxValueSize)
	tmpRet, _, err := syscall.RawSyscall6(syscall.SYS_FGETXATTR, file.Fd(), pointerToByteSlice(key), pointerToByteSlice(buf), uintptr(len(buf)), unusedArg, unusedArg)
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
	const flags = 0

	tmpRet, _, err := syscall.RawSyscall6(syscall.SYS_SETXATTR, pointerToByteSlice(path), pointerToByteSlice(key), pointerToByteSlice(value), uintptr(len(value)), flags, unusedArg)
	ret := int(tmpRet)
	if ret == -1 {
		return err
	}
	return nil
}

func realDelXattr(path []byte, key []byte) error {
	tmpRet, _, err := syscall.RawSyscall(syscall.SYS_REMOVEXATTR, pointerToByteSlice(path), pointerToByteSlice(key), unusedArg)
	ret := int(tmpRet)
	if ret == -1 {
		return err
	}
	return nil
}

func realGetXattr(path []byte, key []byte) ([]byte, error) {
	buf := make([]byte, maxValueSize)
	tmpRet, _, err := syscall.RawSyscall6(syscall.SYS_GETXATTR, pointerToByteSlice(path), pointerToByteSlice(key), pointerToByteSlice(buf), uintptr(len(buf)), unusedArg, unusedArg)
	runtime.KeepAlive(buf)
	ret := ssize_t(tmpRet)
	if ret == -1 {
		return nil, err
	}
	return buf[:ret], nil
}
