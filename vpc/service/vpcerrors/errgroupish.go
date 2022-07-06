package vpcerrors

import (
	"context"

	"github.com/hashicorp/go-multierror"
)

type ErrGroupish struct {
	dispatched int
	errCh      chan error
}

func (e *ErrGroupish) Run(f func() error) {
	e.dispatched++
	go func() {
		e.errCh <- f()
	}()
}

func (e *ErrGroupish) Wait(ctx context.Context) error {
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

func NewErrGroupIsh() *ErrGroupish {
	return &ErrGroupish{
		errCh: make(chan error, 10),
	}
}
