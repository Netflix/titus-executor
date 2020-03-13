package vpcerrors

import "errors"

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
