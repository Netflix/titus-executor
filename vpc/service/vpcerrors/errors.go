package vpcerrors

import (
	"errors"
	"fmt"

	"github.com/lib/pq"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// persistentError indicates that this work will not be able to be retried, and it has reached a terminal
// state
type persistentError struct {
	err error
}

func NewPersistentError(err error) error {
	if err == nil {
		panic("err is nil")
	}
	return &persistentError{err: err}
}

func (p *persistentError) Unwrap() error {
	return p.err
}

func (p *persistentError) Error() string {
	return p.err.Error()
}

func (p *persistentError) Is(target error) bool {
	_, ok := target.(*persistentError)
	return ok
}

func IsPersistentError(err error) bool {
	return errors.Is(err, &persistentError{})
}

func NewRetryable(err error) error {
	if err == nil {
		panic("err is nil")
	}
	return &retryable{err: err}
}

type retryable struct {
	err error
}

func (r *retryable) Error() string {
	return "Should retry: " + r.err.Error()
}

func (r *retryable) Is(target error) bool {
	_, ok := target.(*retryable)
	return ok
}

func (r *retryable) Unwrap() error {
	return r.err
}

func IsRetryable(err error) bool {
	return errors.Is(err, &retryable{})
}

type withSleep struct {
	err error
}

func NewWithSleep(err error) error {
	if err == nil {
		panic("err is nil")
	}
	return &withSleep{err: err}
}

func (w *withSleep) Error() string {
	return "Should sleep: " + w.err.Error()
}

func (w *withSleep) Is(target error) bool {
	_, ok := target.(*withSleep)
	return ok
}

func (w *withSleep) Unwrap() error {
	return w.err
}

func IsSleep(err error) bool {
	return errors.Is(err, &withSleep{})
}

type ConcurrencyError struct {
	err error
}

func NewConcurrencyError(err error) error {
	if err == nil {
		panic("err is nil")
	}
	return &ConcurrencyError{err: err}
}

func (c *ConcurrencyError) Unwrap() error {
	return c.err
}

func (c *ConcurrencyError) Error() string {
	return c.err.Error()
}

func (c *ConcurrencyError) Is(target error) bool {
	_, ok := target.(*ConcurrencyError)
	return ok
}

func (c *ConcurrencyError) GRPCStatus() *status.Status {
	return status.New(codes.Aborted, c.err.Error())
}

func IsConcurrencyError(err error) bool {
	return errors.Is(err, &ConcurrencyError{})
}

// vpcerrors.IrrecoverableError indicates that this work item cannot be started
type IrrecoverableError struct {
	err error
}

func NewIrrecoverableError(err error) error {
	return &IrrecoverableError{err: err}
}

func (p *IrrecoverableError) Unwrap() error {
	return p.err
}

func (p *IrrecoverableError) Error() string {
	return p.err.Error()
}

func (p *IrrecoverableError) Is(target error) bool {
	_, ok := target.(*IrrecoverableError)
	return ok
}

func NewMethodNotPossibleError(method string) error {
	return &MethodNotPossible{method: method}
}

type MethodNotPossible struct {
	method string
}

func (m *MethodNotPossible) Error() string {
	return fmt.Sprintf("Assignment method %s not possible", m.method)
}

func (m *MethodNotPossible) GRPCStatus() *status.Status {
	return status.Newf(codes.FailedPrecondition, "Assignment method %s not possible", m.method)
}

func (m *MethodNotPossible) Is(target error) bool {
	_, ok := target.(*MethodNotPossible)
	return ok
}

func PqError(err error) *pq.Error {
	for err != nil {
		pqErr, ok := err.(*pq.Error)
		if ok {
			return pqErr
		}
		err = errors.Unwrap(err)
	}

	return nil
}

func IsSerializationFailure(err error) bool {
	pqErr := PqError(err)
	if pqErr == nil {
		return false
	}
	return pqErr.Code.Name() == "serialization_failure"
}

type notFoundError struct {
	err error
}

func NewNotFoundError(err error) error {
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
