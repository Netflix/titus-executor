package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/Netflix/titus-executor/vpc/service/vpcerrors"

	"github.com/pkg/errors"
	"gotest.tools/assert"
)

func TestPersistentError(t *testing.T) {
	err := errors.New("test error")
	assert.Assert(t, !vpcerrors.IsPersistentError(err))
	err2 := vpcerrors.NewPersistentError(err)
	assert.Assert(t, vpcerrors.IsPersistentError(err2))

}

func TestWrap(t *testing.T) {
	err := fmt.Errorf("This is a test: %s", "Sargun")
	err = vpcerrors.NewRetryable(err)
	assert.Assert(t, vpcerrors.IsRetryable(err))
	err = errors.Wrap(err, "Wrap 1")
	assert.Assert(t, vpcerrors.IsRetryable(err))
}

func TestBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := errors.New("base error")
	assert.Assert(t, !vpcerrors.IsSleep(err))
	assert.Assert(t, !errors.Is(err, &concurrencyError{}))
	err = &concurrencyError{err: err}

	assert.Assert(t, !vpcerrors.IsSleep(err))
	assert.Assert(t, errors.Is(err, &concurrencyError{}))
	err = vpcerrors.NewWithSleep(err)
	assert.Assert(t, vpcerrors.IsSleep(err))
	assert.Assert(t, errors.Is(err, &concurrencyError{}))
	cancel()
	assert.ErrorContains(t, backOff(ctx, err), "expired")
	assert.NilError(t, backOff(ctx, errors.New("")))
}
