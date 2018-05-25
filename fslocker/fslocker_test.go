package fslocker

import (
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
	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)

	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)

	l1, err := locker.ExclusiveLock("test", durationPointer(time.Second))
	assert.NoError(t, err)
	_, err = locker.ExclusiveLock("test", durationPointer(time.Second))
	assert.Error(t, err)
	l1.ToSharedLock()
	l3, err := locker.SharedLock("test", durationPointer(time.Second))
	assert.NoError(t, err)
	l1.Unlock()
	l3.Unlock()
}

func TestFSLockerDir(t *testing.T) {
	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)
	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)

	l1, err := locker.ExclusiveLock("test/test/test", durationPointer(time.Second))
	assert.NoError(t, err)
	l2, err := locker.ExclusiveLock("test/test", durationPointer(time.Second))
	assert.NoError(t, err)
	l2.Unlock()
	l1.Unlock()
}

func TestFSLockUpgradeDowngrade(t *testing.T) {
	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)
	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)

	l1, err := locker.SharedLock("test/test", nil)
	assert.NoError(t, err)
	l2, err := locker.SharedLock("test/test", nil)
	assert.NoError(t, err)

	_, err = l1.ToExclusiveLock(durationPointer(time.Second))
	assert.Error(t, err)
	l2.Unlock()
	_, err = l1.ToExclusiveLock(durationPointer(time.Second))
	assert.NoError(t, err)
}

func TestFSLockerRemove(t *testing.T) {
	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)
	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)
	l1, err := locker.ExclusiveLock("test", durationPointer(time.Second))
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
	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)

	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)

	l1, err := locker.ExclusiveLock("test", durationPointer(0))
	assert.NoError(t, err)
	l2, err := locker.ExclusiveLock("test", durationPointer(0))
	assert.Equal(t, unix.EWOULDBLOCK, err)

	l1.Unlock()
	assert.Nil(t, l2)
}

func TestFSLockerPessimisticSuccess(t *testing.T) {
	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)

	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)

	l1, err := locker.ExclusiveLock("test", durationPointer(0))
	assert.NoError(t, err)
	start := time.Now()
	go func() {
		time.Sleep(1 * time.Second)
		l1.Unlock()
	}()

	l2, err := locker.ExclusiveLock("test", durationPointer(5*time.Second))
	assert.NoError(t, err)
	assert.NotNil(t, l2)
	defer l2.Unlock()
	assert.True(t, time.Since(start) > 1*time.Second)
}

func TestFSLockerPessimisticFail(t *testing.T) {
	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)

	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)

	l1, err := locker.ExclusiveLock("test", durationPointer(0))
	assert.NoError(t, err)
	start := time.Now()
	go func() {
		time.Sleep(3 * time.Second)
		l1.Unlock()
	}()

	l2, err := locker.ExclusiveLock("test", durationPointer(2*time.Second))
	assert.Error(t, err)
	assert.Equal(t, err, unix.ETIMEDOUT)
	assert.Nil(t, l2)
	assert.True(t, time.Since(start) > 2*time.Second)
}

func removeAll(t *testing.T, dir string) {
	assert.NoError(t, os.RemoveAll(dir))
}

func TestDoubleUnlock(t *testing.T) {
	dir, err := ioutil.TempDir("", "fs-locker")
	require.NoError(t, err)
	defer removeAll(t, dir)

	locker, err := NewFSLocker(dir)
	assert.NoError(t, err)

	l1, err := locker.ExclusiveLock("test", durationPointer(time.Second))
	assert.NoError(t, err)
	l1.Bump()
	l1.Unlock()
	l1.Unlock()
}
