package fslocker

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func durationPointer(duration time.Duration) *time.Duration {
	return &duration
}

func TestFSLockerTwice(t *testing.T) {
	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)

	_, err = NewFSLocker(dir)
	assert.NoError(t, err)

	_, err = NewFSLocker(dir)
	assert.NoError(t, err)
}

func TestFSLocker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)

	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)

	l1, err := locker.ExclusiveLock(ctx, "test", durationPointer(time.Second))
	assert.NoError(t, err)
	_, err = locker.ExclusiveLock(ctx, "test", durationPointer(time.Second))
	assert.Error(t, err)
	l1.ToSharedLock()
	l3, err := locker.SharedLock(ctx, "test", durationPointer(time.Second))
	assert.NoError(t, err)
	l1.Unlock()
	l3.Unlock()
}

func TestFSLockerDir(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)
	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)

	l1, err := locker.ExclusiveLock(ctx, "test/test/test", durationPointer(time.Second))
	assert.NoError(t, err)
	l2, err := locker.ExclusiveLock(ctx, "test/test", durationPointer(time.Second))
	assert.NoError(t, err)
	l2.Unlock()
	l1.Unlock()
}

func TestFSLockUpgradeDowngrade(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)
	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)

	l1, err := locker.SharedLock(ctx, "test/test", nil)
	assert.NoError(t, err)
	l2, err := locker.SharedLock(ctx, "test/test", nil)
	assert.NoError(t, err)

	_, err = l1.ToExclusiveLock(ctx, durationPointer(time.Second))
	assert.Error(t, err)
	l2.Unlock()
	_, err = l1.ToExclusiveLock(ctx, durationPointer(time.Second))
	assert.NoError(t, err)
}

func TestFSLockerRemove(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)
	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)
	l1, err := locker.ExclusiveLock(ctx, "test", durationPointer(time.Second))
	assert.NoError(t, err)
	l1.Unlock()

	files, err := locker.ListFiles("")
	assert.NoError(t, err)
	assert.Len(t, files, 1)

	assert.NoError(t, locker.RemovePath("test"))
	files, err = locker.ListFiles("")
	assert.NoError(t, err)
	assert.Len(t, files, 0)
}

func TestFSLockerOptimistic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)

	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)

	l1, err := locker.ExclusiveLock(ctx, "test", durationPointer(0))
	assert.NoError(t, err)
	l2, err := locker.ExclusiveLock(ctx, "test", durationPointer(0))
	assert.Equal(t, unix.EWOULDBLOCK, err)

	l1.Unlock()
	assert.Nil(t, l2)
}

func TestFSLockerPessimisticSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)

	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)

	l1, err := locker.ExclusiveLock(ctx, "test", durationPointer(0))
	assert.NoError(t, err)
	start := time.Now()
	go func() {
		time.Sleep(1 * time.Second)
		l1.Unlock()
	}()

	l2, err := locker.ExclusiveLock(ctx, "test", durationPointer(5*time.Second))
	assert.NoError(t, err)
	assert.NotNil(t, l2)
	defer l2.Unlock()
	assert.True(t, time.Since(start) > 1*time.Second)
}

func TestFSLockerPessimisticFail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)

	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)

	l1, err := locker.ExclusiveLock(ctx, "test", durationPointer(0))
	assert.NoError(t, err)
	start := time.Now()
	go func() {
		time.Sleep(3 * time.Second)
		l1.Unlock()
	}()

	l2, err := locker.ExclusiveLock(ctx, "test", durationPointer(2*time.Second))
	assert.Error(t, err)
	assert.Equal(t, err, unix.ETIMEDOUT)
	assert.Nil(t, l2)
	assert.True(t, time.Since(start) > 2*time.Second)
}

func removeAll(t *testing.T, dir string) {
	assert.NoError(t, os.RemoveAll(dir))
}

func TestDoubleUnlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)

	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)

	l1, err := locker.ExclusiveLock(ctx, "test", durationPointer(time.Second))
	assert.NoError(t, err)
	l1.Bump()
	l1.Unlock()
	l1.Unlock()
}

func TestLockContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)

	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)

	l1, err := locker.ExclusiveLock(ctx, "test", durationPointer(time.Second))
	assert.NoError(t, err)

	ctx2, cancel2 := context.WithTimeout(ctx, time.Second)
	defer cancel2()
	_, err = locker.ExclusiveLock(ctx2, "test", durationPointer(10*time.Second))
	assert.Error(t, err)
	assert.Equal(t, context.DeadlineExceeded, err)
	l1.Unlock()

	// Make sure we can relock the file (check we're not leaking locks)
	l1, err = locker.ExclusiveLock(ctx, "test", durationPointer(time.Second))
	assert.NoError(t, err)
	l1.Unlock()
}

func TestLockContextIndefinite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)

	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)

	l1, err := locker.ExclusiveLock(ctx, "test", nil)
	assert.NoError(t, err)

	ctx2, cancel2 := context.WithTimeout(ctx, time.Second)
	defer cancel2()
	_, err = locker.ExclusiveLock(ctx2, "test", nil)
	assert.Error(t, err)
	assert.Equal(t, context.DeadlineExceeded, err)
	l1.Unlock()

	//	Make sure we can relock the file (check we're not leaking locks)
	l1, err = locker.ExclusiveLock(ctx, "test", nil)
	assert.NoError(t, err)
	l1.Unlock()
}
