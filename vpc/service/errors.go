package service

import (
	"fmt"

	"github.com/lib/pq"
	"github.com/pkg/errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type concurrencyError struct {
	err error
}

func newConcurrencyError(err error) error {
	if err == nil {
		panic("err is nil")
	}
	return &concurrencyError{err: err}
}

func (c *concurrencyError) Unwrap() error {
	return c.err
}

func (c *concurrencyError) Error() string {
	return c.err.Error()
}

func (c *concurrencyError) Is(target error) bool {
	_, ok := target.(*concurrencyError)
	return ok
}

func (c *concurrencyError) GRPCStatus() *status.Status {
	return status.New(codes.Aborted, c.err.Error())
}

func isConcurrencyError(err error) bool {
	return errors.Is(err, &concurrencyError{})
}

// irrecoverableError indicates that this work item cannot be started
type irrecoverableError struct {
	err error
}

func newIrrecoverableError(err error) error {
	return &irrecoverableError{err: err}
}

func (p *irrecoverableError) Unwrap() error {
	return p.err
}

func (p *irrecoverableError) Error() string {
	return p.err.Error()
}

func (p *irrecoverableError) Is(target error) bool {
	_, ok := target.(*irrecoverableError)
	return ok
}

func newMethodNotPossibleError(method string) error {
	return &methodNotPossible{method: method}
}

type methodNotPossible struct {
	method string
}

func (m *methodNotPossible) Error() string {
	return fmt.Sprintf("Assignment method %s not possible", m.method)
}

func (m *methodNotPossible) GRPCStatus() *status.Status {
	return status.Newf(codes.FailedPrecondition, "Assignment method %s not possible", m.method)
}

func (m *methodNotPossible) Is(target error) bool {
	_, ok := target.(*methodNotPossible)
	return ok
}

func pqError(err error) *pq.Error {
	for err != nil {
		pqErr, ok := err.(*pq.Error)
		if ok {
			return pqErr
		}
		err = errors.Unwrap(err)
	}

	return nil
}

func isSerializationFailure(err error) bool {
	pqErr := pqError(err)
	if pqErr == nil {
		return false
	}
	return pqErr.Code.Name() == "serialization_failure"
}

type notFoundError struct {
	err error
}

func newNotFoundError(err error) error {
	if err == nil {
		panic("err is nil")
	}
	return &notFoundError{err: err}
}

func (e *notFoundError) Unwrap() error {
	return e.err
}

func (e *notFoundError) Error() string {
	return e.err.Error()
}

func (e *notFoundError) Is(target error) bool {
	_, ok := target.(*notFoundError)
	return ok
}

func (e *notFoundError) GRPCStatus() *status.Status {
	return status.New(codes.NotFound, e.err.Error())
}
