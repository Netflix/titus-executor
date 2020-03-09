package ec2wrapper

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestHedgeBasic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls int64
	delays := []time.Duration{time.Duration(0), time.Second}
	resp, err := hedge(ctx, func(ctx context.Context) (interface{}, error) {
		atomic.AddInt64(&calls, 1)
		return "ok", nil
	}, delays)
	assert.NilError(t, err)
	assert.Equal(t, resp, "ok")
	assert.Assert(t, atomic.LoadInt64(&calls) == 1)
}

func TestHedgeAllTimeout(t *testing.T) {
	t.Parallel()
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var calls int64
	delays := []time.Duration{time.Duration(0), time.Second}
	_, err := hedge(ctx, func(ctx context.Context) (interface{}, error) {
		atomic.AddInt64(&calls, 1)
		time := time.NewTimer(time.Minute)
		defer time.Stop()
		select {
		case <-time.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return "ok", nil
	}, delays)
	assert.Assert(t, err != nil)
	if me, ok := err.(*multierror.Error); ok {
		for _, e := range me.Errors {
			assert.Assert(t, is.Equal(e, context.DeadlineExceeded))
		}
	} else {
		assert.Assert(t, is.Equal(err, context.DeadlineExceeded))
	}
	assert.Assert(t, atomic.LoadInt64(&calls) == 2)
	// This should terminate well less than 30 seconds in
	assert.Assert(t, time.Since(start) < 30*time.Second)
}

func TestHedgeAllErrors(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var calls int64
	delays := []time.Duration{time.Duration(0), time.Second}
	_, err := hedge(ctx, func(ctx context.Context) (interface{}, error) {
		atomic.AddInt64(&calls, 1)
		return nil, errors.New("fake error")
	}, delays)
	assert.Assert(t, err != nil)
	me, ok := err.(*multierror.Error)
	assert.Assert(t, ok)
	assert.Assert(t, is.Len(me.Errors, len(delays)))
	for _, e := range me.Errors {
		assert.Error(t, e, "fake error")
	}
	assert.Assert(t, atomic.LoadInt64(&calls) == 2)
}

func TestFirstError(t *testing.T) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var calls int64
	errors := []error{errors.New("Fake error"), nil}
	values := []string{"first", "second"}
	delays := []time.Duration{time.Duration(0), 2 * time.Second}
	value, err := hedge(ctx, func(ctx context.Context) (interface{}, error) {
		v := atomic.AddInt64(&calls, 1) - 1
		return values[v], errors[v]
	}, delays)

	assert.NilError(t, err)
	assert.Equal(t, value, "second")
	assert.Assert(t, time.Since(start) > time.Second)
	assert.Assert(t, atomic.LoadInt64(&calls) == 2)
}
