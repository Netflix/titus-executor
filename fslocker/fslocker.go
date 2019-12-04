package fslocker

import (
	"context"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
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
	pendingWorkPath string
	path            string
}

// Lock is either a shared lock, or an exclusive lock.
type Lock struct {
	file *os.File
}

// Read is a method to implement the io.Reader interface
func (l *Lock) Read(p []byte) (int, error) {
	return l.file.Read(p)
}

// Unlock the lock
func (l *Lock) Unlock() {
	if l.file == nil {
		return
	}
	err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	if err != nil {
		panic(err)
	}
	shouldClose(l.file)
	l.file = nil
}

// Bump the mtime on the locked file
func (l *Lock) Bump() {
	// Bump the mtime
	now := unix.NsecToTimeval(time.Now().UnixNano())
	if err := unix.Futimes(int(l.file.Fd()), []unix.Timeval{now, now}); err != nil {
		panic(err)
	}
}

// SharedLock represents the state of a Shared Lock
type SharedLock struct {
	*Lock
}

// ToExclusiveLock tries to upgrade a SharedLock into an ExclusiveLock.
// If timeout is nil, then this function will be blocking, otherwise it will be non-blocking.
// It will return unix.ETIMEDOUT if timeout occurs
// If timeout is 0
func (sl *SharedLock) ToExclusiveLock(ctx context.Context, timeout *time.Duration) (*ExclusiveLock, error) {
	err := lockHelper(ctx, sl.file, int(exclusive), timeout)
	if err != nil {
		return nil, err
	}
	return &ExclusiveLock{Lock: sl.Lock}, nil
}

// ExclusiveLock represents the state of a Exclusive Lock
type ExclusiveLock struct {
	*Lock
}

// Write is a method to implement the io.Writer interface
func (el *ExclusiveLock) Write(p []byte) (int, error) {
	return el.file.Write(p)
}

// ToSharedLock downgrade an ExclusiveLock into a SharedLock. It should always succeed
func (el *ExclusiveLock) ToSharedLock() *SharedLock {
	err := unix.Flock(int(el.file.Fd()), unix.LOCK_SH)
	// This should never fail
	if err != nil {
		panic(err)
	}
	return &SharedLock{Lock: el.Lock}
}

// NewFSLocker instantiates a new FSLocker instance
func NewFSLocker(path string) (*FSLocker, error) {
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	lockPath := filepath.Join(path, "lockDir")
	if err := os.Mkdir(lockPath, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	pendingWorkPath := filepath.Join(path, ".pendingwork")

	return &FSLocker{path: lockPath, pendingWorkPath: pendingWorkPath}, nil
}

// ExclusiveLock tries to get an exclusive Lock on the path
// If timeout is nil, then this function will be blocking until lock acquisition is successful
// if timeout is 0, it will be non-blocking and return unix.EWOULDBLOCK if we cannot acquire the lock
// if timeout is non-zero, and we timeout, it will return unix.ETIMEDOUT
func (locker *FSLocker) ExclusiveLock(ctx context.Context, path string, timeout *time.Duration) (*ExclusiveLock, error) {
	lock, err := locker.doLock(ctx, exclusive, path, timeout)
	if err != nil {
		return nil, err
	}
	return &ExclusiveLock{Lock: lock}, nil
}

// SharedLock tries to get an shared Lock on the path
// If timeout is nil, then this function will be blocking until lock acquisition is successful
// if timeout is 0, it will be non-blocking and return unix.EWOULDBLOCK if we cannot acquire the lock
// if timeout is non-zero, and we timeout, it will return unix.ETIMEDOUT
func (locker *FSLocker) SharedLock(ctx context.Context, path string, timeout *time.Duration) (*SharedLock, error) {
	lock, err := locker.doLock(ctx, shared, path, timeout)
	if err != nil {
		return nil, err
	}
	return &SharedLock{Lock: lock}, nil
}

// RemovePath removes a given path. It requires that there are no subdirectories.
// It does not ensure the file is not in used
func (locker *FSLocker) RemovePath(path string) error {
	pendingWorkFile, err := os.OpenFile(locker.pendingWorkPath, os.O_RDONLY|os.O_CREATE, 0400)
	if err != nil {
		return err
	}
	defer shouldClose(pendingWorkFile)

	err = unix.Flock(int(pendingWorkFile.Fd()), unix.LOCK_EX)
	if err != nil {
		return err
	}
	defer shouldUnlock(pendingWorkFile)

	return os.Remove(filepath.Join(locker.path, path))
}

// Record includes the metadata about the file
type Record struct {
	Name     string
	BumpTime time.Time
}

// ListFiles lists the files for a given path -- only 1 level deep
func (locker *FSLocker) ListFiles(path string) ([]Record, error) {
	files, err := ioutil.ReadDir(filepath.Join(locker.path, path))
	if os.IsNotExist(err) {
		return []Record{}, nil
	} else if err != nil {
		return nil, err
	}

	ret := make([]Record, len(files))
	for idx, file := range files {
		ret[idx] = Record{Name: file.Name(), BumpTime: file.ModTime()}
	}

	return ret, nil
}

func (locker *FSLocker) doLock(ctx context.Context, how lockType, path string, timeout *time.Duration) (*Lock, error) {
	pendingWorkFile, err := os.OpenFile(locker.pendingWorkPath, os.O_RDONLY|os.O_CREATE, 0400)
	if err != nil {
		return nil, err
	}
	defer shouldClose(pendingWorkFile)

	err = unix.Flock(int(pendingWorkFile.Fd()), unix.LOCK_SH)
	if err != nil {
		return nil, err
	}
	defer shouldUnlock(pendingWorkFile)

	fd, err := locker.mkdirLockDir(path)
	if err != nil {
		return nil, err
	}

	err = lockHelper(ctx, fd, int(how), timeout)
	if err != nil {
		if err != ctx.Err() {
			shouldClose(fd)
		}
		return nil, err
	}

	return &Lock{file: fd}, nil
}

func lockHelper(ctx context.Context, fd *os.File, how int, timeout *time.Duration) error {
	if timeout == nil {
		var err error
		locked := make(chan struct{})
		go func() {
			err = unix.Flock(int(fd.Fd()), how)
			locked <- struct{}{}
		}()
		select {
		case <-ctx.Done():
			go func() {
				<-locked
				_ = unix.Flock(int(fd.Fd()), unix.LOCK_UN)
				shouldClose(fd)
			}()
			return ctx.Err()
		case <-locked:
			return err
		}
	}

	if *timeout == 0 {
		return unix.Flock(int(fd.Fd()), how|unix.LOCK_NB)
	}

	start := time.Now()
	firstLoop := true
	for time.Since(start) < *timeout || firstLoop {
		if ctx.Err() != nil {
			return ctx.Err()
		}
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
	var err error
	for i := 0; i < 10; i++ {
		lockPath := filepath.Join(locker.path, path)
		err = os.MkdirAll(lockPath, 0700)
		if err == nil {
			return os.OpenFile(lockPath, os.O_RDONLY, 0400)
		}
		time.Sleep(time.Millisecond * time.Duration(rand.Intn(100)))
	}
	return nil, err
}

func shouldClose(closeable io.Closer) {
	if err := closeable.Close(); err != nil {
		panic(err)
	}
}

func shouldUnlock(file *os.File) {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		panic(err)
	}
}
