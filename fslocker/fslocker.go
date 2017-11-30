package fslocker

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type lockType int

const (
	shared    lockType = unix.LOCK_SH
	exclusive          = unix.LOCK_EX
)

// FSLocker is a configuration holder struct, use NewFSLocker to instantiate
type FSLocker struct {
	path string
}

// Lock is either a shared lock, or an exclusive lock.
type Lock struct {
	file *os.File
}

// Unlock the lock
func (l *Lock) Unlock() {
	err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	if err != nil {
		panic(err)
	}
	shouldClose(l.file)
}

// SharedLock represents the state of a Shared Lock
type SharedLock struct {
	*Lock
}

// ToExclusiveLock tries to upgrade a SharedLock into an ExclusiveLock.
// If timeout is nil, then this function will be blocking, otherwise it will be non-blocking.
// It will return unix.ETIMEDOUT if timeout occurs
func (sl *SharedLock) ToExclusiveLock(timeout *time.Duration) error {
	return lockHelper(sl.file, int(exclusive), timeout)
}

// ExclusiveLock represents the state of a Exclusive Lock
type ExclusiveLock struct {
	*Lock
}

// ToSharedLock downgrade an ExclusiveLock into a SharedLock. It should always succeed
func (sl *ExclusiveLock) ToSharedLock() *SharedLock {
	err := unix.Flock(int(sl.file.Fd()), unix.LOCK_SH)
	// This should never fail
	if err != nil {
		panic(err)
	}
	return &SharedLock{Lock: sl.Lock}
}

// NewFSLocker instantiates a new FSLocker instance
func NewFSLocker(path string) (*FSLocker, error) {
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}

	return &FSLocker{path: path}, nil
}

// ExclusiveLock tries to get an exclusive Lock on the path
// If timeout is nil, then this function will be blocking, otherwise it will be non-blocking.
// It will return unix.ETIMEDOUT if timeout occurs
func (locker *FSLocker) ExclusiveLock(path string, timeout *time.Duration) (*ExclusiveLock, error) {
	lock, err := locker.doLock(exclusive, path, timeout)
	if err != nil {
		return nil, err
	}
	return &ExclusiveLock{Lock: lock}, nil
}

// SharedLock tries to get an exclusive Lock on the path
// If timeout is nil, then this function will be blocking, otherwise it will be non-blocking.
// It will return unix.ETIMEDOUT if timeout occurs
func (locker *FSLocker) SharedLock(path string, timeout *time.Duration) (*SharedLock, error) {
	lock, err := locker.doLock(shared, path, timeout)
	if err != nil {
		return nil, err
	}
	return &SharedLock{Lock: lock}, nil
}

func (locker *FSLocker) doLock(how lockType, path string, timeout *time.Duration) (*Lock, error) {
	fd, err := locker.mkdirLockDir(path)
	if err != nil {
		return nil, err
	}

	err = lockHelper(fd, int(how), timeout)
	if err != nil {
		shouldClose(fd)
		return nil, err
	}
	return &Lock{file: fd}, nil
}

func lockHelper(fd *os.File, how int, timeout *time.Duration) error {
	if timeout == nil {
		return unix.Flock(int(fd.Fd()), how)
	}

	if *timeout == 0 {
		return unix.Flock(int(fd.Fd()), how|unix.LOCK_NB)
	}

	start := time.Now()
	firstLoop := true
	for time.Since(start) < *timeout || firstLoop {
		firstLoop = false
		err := unix.Flock(int(fd.Fd()), how|unix.LOCK_NB)
		if err == unix.EWOULDBLOCK {
			time.Sleep(100 * time.Millisecond)
		} else if err != nil {
			return err
		} else {
			return nil
		}
	}

	return unix.ETIMEDOUT
}

func (locker *FSLocker) mkdirLockDir(path string) (*os.File, error) {
	dir, file := filepath.Split(path)
	dirSplit := strings.Split(dir, "/")

	pathComponents := []string{locker.path}
	for idx := range dirSplit {
		pathComponents = append(pathComponents, dirSplit[idx]+".dir")
	}
	pathComponents = append(pathComponents, file+".file")
	lockPath := filepath.Join(pathComponents...)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	return os.OpenFile(lockPath, os.O_RDONLY|os.O_CREATE, 0400)
}

func shouldClose(closeable io.Closer) {
	if err := closeable.Close(); err != nil {
		panic(err)
	}
}
