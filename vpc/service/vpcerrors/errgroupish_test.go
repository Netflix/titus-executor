package vpcerrors

import (
	"context"
	"errors"
	"testing"
	"time"

	"gotest.tools/assert"
)

func TestErrGroupish(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errFake := errors.New("test error")
	group := NewErrGroupIsh()
	var done bool
	start := time.Now()
	group.Run(func() error {
		time.Sleep(time.Second)
		done = true
		return errFake
	})

	err := group.Wait(ctx)
	assert.Assert(t, done)
	assert.Assert(t, err != nil)
	assert.Assert(t, time.Since(start) >= time.Second)
}

func TestErrGroupishNoErr(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	group := NewErrGroupIsh()
	group.Run(func() error {
		return nil
	})

	err := group.Wait(ctx)
	assert.NilError(t, err)
}

func TestErrGroupishMany(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	group := NewErrGroupIsh()
	var done1, done2, done3 bool
	group.Run(func() error {
		time.Sleep(time.Second)
		done1 = true
		return nil
	})
	group.Run(func() error {
		time.Sleep(2 * time.Second)
		done2 = true
		return nil
	})
	group.Run(func() error {
		time.Sleep(3 * time.Second)
		done3 = true
		return nil
	})

	err := group.Wait(ctx)
	assert.NilError(t, err)
	assert.Assert(t, done1)
	assert.Assert(t, done2)
	assert.Assert(t, done3)

}
