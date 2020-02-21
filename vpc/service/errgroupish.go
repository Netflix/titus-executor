package service

import (
	"context"

	"github.com/hashicorp/go-multierror"
)

type errGroupish struct {
	dispatched int
	errCh      chan error
}

func (e *errGroupish) run(f func() error) {
	e.dispatched++
	go func() {
		e.errCh <- f()
	}()
}

func (e *errGroupish) wait(ctx context.Context) error {
	var result *multierror.Error
	for e.dispatched > 0 {
		select {
		case err := <-e.errCh:
			result = multierror.Append(result, err)
			e.dispatched--
		case <-ctx.Done():
			result = multierror.Append(result, ctx.Err())
			goto out
		}
	}
out:
	return result.ErrorOrNil()
}

func newErrGroupIsh() *errGroupish {
	return &errGroupish{
		errCh: make(chan error, 10),
	}
}
