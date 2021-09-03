package mount

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	/* Empty from path permitted */
	MOVE_MOUNT_F_EMPTY_PATH = 0x00000004 // nolint: golint
	/* Empty to path permitted */
	MOVE_MOUNT_T_EMPTY_PATH = 0x00000040 // nolint: golint
	OPEN_TREE_CLONE         = 1          // nolint: golint
)

func Mount(fd int, where string) error {
	dir := filepath.Dir(where)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return fmt.Errorf("Could not mkdir %q: %w", dir, err)
	}

	// Make sure that this somehow didn't exist before.
	dstfd, err := unix.Open(where, unix.O_CLOEXEC|unix.O_CREAT|unix.O_EXCL, 0755)
	if err != nil {
		return fmt.Errorf("Could not create transition mount point: %w", err)
	}
	defer unix.Close(dstfd)

	emptyPath, err := syscall.BytePtrFromString("")
	if err != nil {
		panic(err)
	}

	srctree, _, errno := syscall.Syscall(unix.SYS_OPEN_TREE, uintptr(fd),
		uintptr(unsafe.Pointer(emptyPath)), unix.AT_EMPTY_PATH|OPEN_TREE_CLONE|unix.O_CLOEXEC)
	if errno != 0 {
		return fmt.Errorf("Could not open src tree: %s: %w", unix.ErrnoName(errno), errno)
	}

	_, _, errno = syscall.Syscall6(unix.SYS_MOVE_MOUNT,
		srctree, uintptr(unsafe.Pointer(emptyPath)),
		uintptr(dstfd), uintptr(unsafe.Pointer(emptyPath)),
		MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH, 0)
	if errno != 0 {
		return fmt.Errorf("Could not move mount: %s: %w", unix.ErrnoName(errno), errno)
	}

	return nil
}
