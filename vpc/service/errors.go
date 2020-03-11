package service

type concurrencyError struct {
	err error
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

// persistentError indicates that this work item has moved to a "terminal" state, and is complete
type persistentError struct {
	err error
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

// irrecoverableError indicates that this work item cannot be started
type irrecoverableError struct {
	err error
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
